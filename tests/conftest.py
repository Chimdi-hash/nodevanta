import copy
import importlib.util
import json
import sys
import types
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "NodeVanta.py"
BASE_TIME = "2026-01-01T00:00:00Z"
ALICE = "0x" + "1" * 40
BOB = "0x" + "2" * 40
CHARLIE = "0x" + "3" * 40
AUTH_URL = "https://authority.example/auth.json"
OPERATION_DATA_URL = "https://events.example/action.json"
AUTH_BODY = (
    "Authority record: Alice is permitted to transfer 100 USDC to Treasury. "
    "Permission effective 2025-12-01 at 00:00 UTC; no expiry or revocation."
)
OPERATION_DATA_BODY = (
    "Action record: Alice transferred 100 USDC to Treasury on 2025-12-20 at 12:00 UTC."
)


class ContractError(RuntimeError):
    pass


class ConsensusError(RuntimeError):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class BodyFailureResponse:
    status = 200
    headers = {"Content-Type": "text/plain"}

    @property
    def body(self):
        raise RuntimeError("body accessor failed")


class HeaderFailureResponse:
    status = 200

    @property
    def headers(self):
        raise RuntimeError("headers accessor failed")


class FakeWeb:
    def __init__(self, responses=None):
        self.responses = {} if responses is None else responses
        self.calls = []

    def get(self, url, headers=None):
        self.calls.append((url, headers))
        value = self.responses.get(url)
        if isinstance(value, list):
            value = value.pop(0) if len(value) > 1 else value[0]
        if callable(value):
            value = value(url, headers)
        if isinstance(value, BaseException):
            raise value
        if value is None:
            raise RuntimeError("provider did not mock URL")
        return copy.deepcopy(value)


class FakeLLM:
    def __init__(self, response=None):
        self.response = {"outcome": "APPROVED"} if response is None else response
        self.calls = []

    def exec_prompt(self, prompt, response_format=None):
        self.calls.append((prompt, response_format))
        value = self.response
        if isinstance(value, list):
            value = value.pop(0) if len(value) > 1 else value[0]
        if callable(value):
            value = value(prompt, response_format)
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


class FakeVM:
    Return = Return
    UserError = ContractError

    def __init__(self):
        self.captured = []
        self.validations = []

    def run_nondet_unsafe(self, leader_fn, validator_fn):
        proposal = leader_fn()
        self.captured.append((copy.deepcopy(proposal), leader_fn, validator_fn))
        valid = validator_fn(Return(copy.deepcopy(proposal)))
        self.validations.append(valid)
        if not valid:
            raise ConsensusError("proposal mismatch")
        return proposal


def load_contract_module():
    spec = importlib.util.spec_from_file_location("nodevanta_test_module", CONTRACT)
    module = importlib.util.module_from_spec(spec)
    fake_gl = types.SimpleNamespace()
    fake_gl.vm = types.SimpleNamespace(UserError=ContractError, Return=Return)
    fake_gl.Contract = object

    class Public:
        @staticmethod
        def view(fn):
            return fn

        class Write:
            def __call__(self, fn):
                return fn

        write = Write()

    class StorageType:
        @classmethod
        def __class_getitem__(cls, value):
            return cls

    fake_gl.public = Public()
    fake = types.ModuleType("genlayer")
    fake.__all__ = ["gl", "TreeMap", "u256", "Address"]
    fake.gl = fake_gl
    fake.TreeMap = StorageType
    fake.u256 = int
    fake.Address = str
    previous = sys.modules.get("genlayer")
    sys.modules["genlayer"] = fake
    try:
        assert spec.loader is not None
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop("genlayer", None)
        else:
            sys.modules["genlayer"] = previous
    return module


def response(status=200, body=AUTH_BODY, media="text/plain", headers=True):
    if isinstance(body, str):
        body = body.encode("utf-8")
    response_headers = {"Content-Type": media} if headers else {}
    return types.SimpleNamespace(status=status, headers=response_headers, body=body)


def base_payload():
    return {
        "api_ver": "1.0",
        "task_name": "Treasury transfer authorization",
        "target_entity": "Project X treasury",
        "node_operator": "Alice",
        "policy_config": {
            "policy_rules": "Alice must be authorized to transfer 100 USDC to Treasury.",
            "tag": "Treasury approval",
            "data_endpoint": AUTH_URL,
        },
        "operation_data": {
            "operation_details": "Alice transfers 100 USDC to Treasury.",
            "tag": "Transfer record",
            "data_endpoint": OPERATION_DATA_URL,
        },
    }


def case_json(value=None):
    return json.dumps(base_payload() if value is None else value, ensure_ascii=False, separators=(",", ":"))


class Harness:
    def __init__(self, module=None, web=None, llm=None, sender=ALICE, timestamp=BASE_TIME):
        self.module = load_contract_module() if module is None else module
        self.web = FakeWeb(web or {
            AUTH_URL: response(body=AUTH_BODY),
            OPERATION_DATA_URL: response(body=OPERATION_DATA_BODY),
        })
        self.llm = FakeLLM(llm)
        self.vm = FakeVM()
        self.gl = types.SimpleNamespace(
            vm=self.vm,
            nondet=types.SimpleNamespace(web=self.web, exec_prompt=self.llm.exec_prompt),
            message=types.SimpleNamespace(sender_address=sender),
            message_raw={"datetime": timestamp},
        )
        self.module.gl = self.gl
        self.contract = self.module.NodeVanta()
        self.contract.task_storage = {}
        self.contract.result_storage = {}
        self.contract.owner_task_tally = {}
        self.contract.owner_task_id = {}
        self.contract.global_tally = 0

    def create(self, value=None):
        return self.contract.initialize_session(case_json(value))


def set_sender(harness, sender):
    harness.gl.message.sender_address = sender


def set_time(harness, timestamp):
    harness.gl.message_raw["datetime"] = timestamp


def expect_error(fn, text=None):
    try:
        fn()
    except ContractError as exc:
        if text is not None:
            assert text in str(exc)
        return exc
    raise AssertionError("expected ContractError")


