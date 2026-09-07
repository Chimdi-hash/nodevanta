import copy
import json

import pytest

from conftest import AUTH_URL, OPERATION_DATA_URL, Harness, case_json, expect_error


def _url(fill="a", length=1024):
    prefix = "https://authority.example/"
    return prefix + fill * (length - len(prefix))


def _with_url(payload, role, url):
    value = copy.deepcopy(payload)
    value[role]["data_endpoint"] = url
    return value


def test_valid_minimal_case_and_strict_normalization():
    h = Harness()
    task_id = h.create()
    stored = h.contract.get_session(task_id)
    assert stored["api_ver"] == "1.0"
    assert stored["node_operator"] == "Alice"
    assert stored["policy_config"]["data_endpoint"] == AUTH_URL
    assert stored["operation_data"]["data_endpoint"] == OPERATION_DATA_URL


def test_valid_maximum_bound_case():
    value = {
        "api_ver": "1.0",
        "task_name": "t" * 160,
        "target_entity": "s" * 800,
        "node_operator": "a" * 512,
        "policy_config": {
            "policy_rules": "r" * 2000,
            "tag": "l" * 160,
            "data_endpoint": _url("a"),
        },
        "operation_data": {
            "operation_details": "d" * 2000,
            "tag": "m" * 160,
            "data_endpoint": _url("b"),
        },
    }
    h = Harness()
    assert h.create(value).startswith("auth-")


@pytest.mark.parametrize("change", [
    lambda p: p.pop("node_operator"),
    lambda p: p.update({"unexpected": True}),
    lambda p: p.update({"api_ver": "2.0"}),
    lambda p: p.update({"task_name": 1}),
    lambda p: p.update({"target_entity": None}),
    lambda p: p.update({"node_operator": []}),
    lambda p: p.update({"policy_config": "approval"}),
    lambda p: p.update({"operation_data": []}),
])
def test_top_level_schema_is_exact(change):
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    change(value)
    expect_error(lambda: h.create(value), "INVALID_CASE")


@pytest.mark.parametrize("role,change", [
    ("policy_config", lambda item: item.pop("tag")),
    ("policy_config", lambda item: item.update({"extra": "x"})),
    ("policy_config", lambda item: item.update({"policy_rules": 3})),
    ("policy_config", lambda item: item.update({"data_endpoint": None})),
    ("operation_data", lambda item: item.pop("operation_details")),
    ("operation_data", lambda item: item.update({"extra": "x"})),
    ("operation_data", lambda item: item.update({"operation_details": {}})),
    ("operation_data", lambda item: item.update({"data_endpoint": 3})),
])
def test_nested_schema_is_exact(role, change):
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    change(value[role])
    expect_error(lambda: h.create(value))


@pytest.mark.parametrize("role,field", [
    ("task_name", "task_name"), ("target_entity", "target_entity"), ("node_operator", "node_operator"),
])
def test_empty_and_whitespace_text_is_rejected(role, field):
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    value[role] = "  "
    expect_error(lambda: h.create(value), "INVALID_CASE")


@pytest.mark.parametrize("role,field,limit", [
    (None, "task_name", 160), (None, "target_entity", 800), (None, "node_operator", 512),
    ("policy_config", "policy_rules", 2000), ("operation_data", "operation_details", 2000),
    ("policy_config", "tag", 160), ("operation_data", "tag", 160),
])
def test_text_field_bounds(role, field, limit):
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    target = value if role is None else value[role]
    target[field] = "x" * (limit + 1)
    expect_error(lambda: h.create(value), "INVALID_CASE")


def test_control_character_in_text_is_rejected():
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    value["node_operator"] = "Alice\x00"
    expect_error(lambda: h.create(value), "INVALID_CASE")


def test_url_bound_and_overall_json_bound():
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    value["policy_config"]["data_endpoint"] = _url("a", 1025)
    expect_error(lambda: h.create(value), "INVALID_URL")
    oversized = json.dumps({"payload": "x" * (h.module.MAX_JSON + 1)})
    expect_error(lambda: h.contract.initialize_session(oversized), "INVALID_CASE")


def test_duplicate_json_keys_are_rejected():
    h = Harness()
    raw = '{"api_ver":"1.0","task_name":"x","task_name":"y"}'
    expect_error(lambda: h.contract.initialize_session(raw), "INVALID_CASE")


def test_duplicate_normalized_urls_are_rejected():
    h = Harness()
    value = copy.deepcopy(__import__("conftest").base_payload())
    value["policy_config"]["data_endpoint"] = "https://AUTHORITY.example/a/../auth.json"
    value["operation_data"]["data_endpoint"] = "https://authority.example/auth.json"
    expect_error(lambda: h.create(value), "INVALID_CASE")


@pytest.mark.parametrize("endpoint", [
    "http://authority.example/auth.json",
    "https://user:pass@authority.example/auth.json",
    "https://user@authority.example/auth.json",
    "https://authority.example/auth.json?x=1",
    "https://authority.example/auth.json#fragment",
    "https://authority.example:443/auth.json",
    "https://127.0.0.1/auth.json",
    "https://[::1]/auth.json",
    "https://localhost/auth.json",
    "https://node.local/auth.json",
    "https://node.internal/auth.json",
    "https://node.lan/auth.json",
    "https://node.invalid/auth.json",
    "https://node.test/auth.json",
    "https://-bad.example/auth.json",
    "https://authority.example/auth%2",
    "https://authority.example/a%252e%252e/auth.json",
    "https://authority.example/a%252f/auth.json",
    "https://authority.example/a%255c/auth.json",
    "https://authority.example/a%2e%2e/auth.json",
    "https://authority.example/a%2E%2E/auth.json",
    "https://authority.example/a%2fauth.json",
    "https://authority.example/a%5Cauth.json",
    "https://authority.example/a b.json",
    "https://authority.example/a\\b.json",
    "https://2130706433/auth.json",
    "https://0x7f000001/auth.json",
    "https://xn--bcher-kva.example/auth.json",
])
def test_unsafe_or_ambiguous_urls_are_rejected(url):
    h = Harness()
    value = _with_url(__import__("conftest").base_payload(), "policy_config", url)
    expect_error(lambda: h.create(value), "INVALID_URL")


def test_mixed_case_host_and_dot_segments_normalize():
    h = Harness()
    value = __import__("conftest").base_payload()
    value["policy_config"]["data_endpoint"] = "https://AUTHORITY.example/a/./b/../auth.json"
    value["operation_data"]["data_endpoint"] = "https://events.example/action.json"
    task_id = h.create(value)
    case = h.contract.get_session(task_id)
    assert case["policy_config"]["data_endpoint"] == "https://authority.example/a/auth.json"


def test_url_input_whitespace_and_controls_are_rejected():
    h = Harness()
    for url in (" https://authority.example/auth.json", "https://authority.example/auth.json ", "https://authority.example/auth\n.json"):
        value = _with_url(__import__("conftest").base_payload(), "policy_config", url)
        expect_error(lambda value=value: h.create(value), "INVALID_URL")

