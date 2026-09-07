import ast
import hashlib
import json
import subprocess
from pathlib import Path

from conftest import CONTRACT, Harness, base_payload


def source_text():
    return CONTRACT.read_text(encoding="utf-8")


def test_source_is_valid_utf8_small_and_pinned():
    raw = CONTRACT.read_bytes()
    assert raw.decode("utf-8")
    assert len(raw) < 52000
    assert source_text().splitlines()[0].startswith('# { "Depends": "py-genlayer:')
    assert "py-genlayer:test" not in source_text()
    assert "py-genlayer:latest" not in source_text()
    assert "unversioned py-genlayer" not in source_text()


def test_source_size_and_hash_are_explicitly_recorded():
    raw = CONTRACT.read_bytes()
    assert len(raw) == 33364
    assert hashlib.sha256(raw).hexdigest() == "9b69510795da1b74c772d86e56798f711ee3877b802d08f7267edd0a9b13c49c"


def test_forbidden_storage_and_frontend_patterns_are_absent():
    source = source_text()
    assert "DynRay" not in source
    assert "DynArray" not in source
    assert "<script" not in source.lower()
    assert "react" not in source.lower()
    assert "source_quorum" not in source
    assert "source_votes" not in source
    assert "hash(" not in source
    assert "gl.vm.run_nondet_unsafe" in source


def test_no_storage_attribute_is_read_inside_any_loop():
    tree = ast.parse(source_text())
    for loop in (node for node in ast.walk(tree) if isinstance(node, (ast.For, ast.While))):
        for child in ast.walk(loop):
            if isinstance(child, ast.Attribute) and isinstance(child.value, ast.Name) and child.value.id == "self":
                raise AssertionError("contract storage access appears inside a loop")


def test_public_abi_shape_is_exact():
    tree = ast.parse(source_text())
    contract = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "NodeVanta")
    public = {}
    for node in contract.body:
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        decorators = {ast.unparse(item) for item in node.decorator_list}
        if "gl.public.write" in decorators:
            public[node.name] = "write"
        elif "gl.public.view" in decorators:
            public[node.name] = "view"
    assert public == {
        "initialize_session": "write", "process_session": "write", "reassess_session": "write",
        "get_session": "view", "get_session_result": "view", "get_layer_data": "view",
        "is_concluded": "view", "get_owner_task_tally": "view", "get_owner_task_id": "view",
    }
    constructor = next(node for node in contract.body if isinstance(node, ast.FunctionDef) and node.name == "__init__")
    assert len(constructor.args.args) == 1


def test_contract_syntax_and_trailing_whitespace():
    tree = ast.parse(source_text())
    assert isinstance(tree, ast.Module)
    assert all(line.rstrip() == line for line in source_text().splitlines())


def test_genvm_lint_check_passes():
    result = subprocess.run(
        ["genvm-lint", "check", str(CONTRACT), "--json"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    report = json.loads(result.stdout)
    assert report["ok"] is True
    assert report["validate"]["methods"] == 9
    assert report["validate"]["view_methods"] == 6
    assert report["validate"]["write_methods"] == 3
    assert report["validate"]["ctor_params"] == 0


def test_schema_and_abi_extraction_passes():
    result = subprocess.run(
        ["genvm-lint", "schema", str(CONTRACT), "--json"],
        capture_output=True, text=True, check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    schema = json.loads(result.stdout)["schema"]
    assert len(schema["methods"]) == 9
    assert sum(not item["readonly"] for item in schema["methods"].values()) == 3
    assert sum(item["readonly"] for item in schema["methods"].values()) == 6
    assert schema["ctor"]["params"] == []


def _max_url(fill, module):
    prefix = "https://authority.example/"
    return prefix + fill * (module.MAX_URL - len(prefix))


def _worst_case_context(module):
    value = {
        "api_ver": "1.0",
        "task_name": '"' * module.MAX_TITLE,
        "target_entity": "\\" * module.MAX_SUBJECT,
        "node_operator": '"' * module.MAX_ACTOR,
        "policy_config": {
            "policy_rules": "\\" * module.MAX_REQUIREMENT,
            "tag": '"' * module.MAX_LABEL,
            "data_endpoint": _max_url("a", module),
        },
        "operation_data": {
            "operation_details": '"' * module.MAX_OPERATION_DATA,
            "tag": "\\" * module.MAX_LABEL,
            "data_endpoint": _max_url("b", module),
        },
    }
    case = module._validate_case(json.dumps(value, ensure_ascii=False, separators=(",", ":")))
    context = module._context(case, "\\" * module.MAX_SOURCE_TEXT, "\\" * module.MAX_SOURCE_TEXT)
    return case, context


def test_worst_case_context_and_prompt_have_positive_safety_margins():
    h = Harness()
    _, context = _worst_case_context(h.module)
    prompt = h.module._prompt(context)
    assert len(context.encode("utf-8")) <= h.module.MAX_CONTEXT
    assert len(prompt.encode("utf-8")) <= h.module.MAX_PROMPT
    assert len(context.encode("utf-8")) < h.module.MAX_CONTEXT
    assert len(prompt.encode("utf-8")) < h.module.MAX_PROMPT


