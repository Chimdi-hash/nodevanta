import pytest
import json
from unittest.mock import patch, MagicMock

# Simplified mocks for testing GenVM locally
class MockGLMessage:
    def __init__(self, sender_address):
        self.sender_address = sender_address

class MockGLNondetWeb:
    class Response:
        def __init__(self, status, body):
            self.status = status
            self.body = body

    @staticmethod
    def get(url, headers=None):
        if "bad" in url:
            return MockGLNondetWeb.Response(404, b"Not Found")
        if "exception" in url:
            raise Exception("Network error")
        return MockGLNondetWeb.Response(200, b"All looks good here.")

class MockGLNondet:
    web = MockGLNondetWeb()
    
    @staticmethod
    def exec_prompt(prompt, response_format):
        if "VIOLATION" in prompt:
            return '{"status": "VIOLATION", "reason": "Found violation"}'
        return '{"status": "COMPLIANT", "reason": "Looks fine"}'

class MockGLVM:
    class UserError(Exception):
        pass
        
    class Return:
        def __init__(self, calldata):
            self.calldata = calldata

    @staticmethod
    def run_nondet_unsafe(leader_fn, validator_fn):
        res = leader_fn()
        valid = validator_fn(MockGLVM.Return(res))
        if not valid:
            raise Exception("Consensus failed")
        return res

class MockGLPublic:
    @staticmethod
    def write(func):
        return func
    
    @staticmethod
    def view(func):
        return func

class MockGL:
    message = MockGLMessage("0x1111111111111111111111111111111111111111")
    nondet = MockGLNondet()
    vm = MockGLVM()
    public = MockGLPublic()
    
    class Contract:
        pass

import sys
sys.modules['genlayer'] = MockGL

# Now import NodeVanta
import NodeVanta

# Mock TreeMap
class MockTreeMap(dict):
    pass

NodeVanta.TreeMap = MockTreeMap

def test_register_task_success():
    contract = NodeVanta.NodeVanta()
    contract.tasks = MockTreeMap()
    contract.results = MockTreeMap()
    
    contract.register_task(
        task_id="task-123",
        operator_id="op-1",
        endpoints=["https://telemetry.com/1", "https://telemetry.com/2"],
        policy_rules="Must run correctly"
    )
    
    assert "task-123" in contract.tasks
    task = json.loads(contract.tasks["task-123"])
    assert task["owner"] == "0x1111111111111111111111111111111111111111"
    assert len(task["endpoints"]) == 2

def test_register_task_invalid_endpoints():
    contract = NodeVanta.NodeVanta()
    contract.tasks = MockTreeMap()
    
    with pytest.raises(MockGL.vm.UserError, match="Must provide between 1 and 5"):
        contract.register_task("t1", "op1", [], "rules")
        
    with pytest.raises(MockGL.vm.UserError, match="Must provide between 1 and 5"):
        contract.register_task("t1", "op1", ["https://ok.com"] * 6, "rules")

def test_audit_task_success():
    contract = NodeVanta.NodeVanta()
    contract.tasks = MockTreeMap()
    contract.results = MockTreeMap()
    
    contract.register_task(
        task_id="task-123",
        operator_id="op-1",
        endpoints=["https://telemetry.com/1"],
        policy_rules="Must run correctly"
    )
    
    contract.audit_task("task-123")
    
    assert "task-123" in contract.results
    result = json.loads(contract.results["task-123"])
    assert result["outcome"] in ["COMPLIANT", "VIOLATION", "INCONCLUSIVE"]
    assert "reason" in result
    assert "https://telemetry.com/1" in result["telemetry_log"]

def test_audit_task_unauthorized():
    contract = NodeVanta.NodeVanta()
    contract.tasks = MockTreeMap()
    contract.results = MockTreeMap()
    
    contract.register_task(
        task_id="task-123",
        operator_id="op-1",
        endpoints=["https://telemetry.com/1"],
        policy_rules="rules"
    )
    
    # Change sender
    MockGL.message.sender_address = "0x2222222222222222222222222222222222222222"
    with pytest.raises(MockGL.vm.UserError, match="Unauthorized"):
        contract.audit_task("task-123")

def test_get_views():
    contract = NodeVanta.NodeVanta()
    contract.tasks = MockTreeMap()
    contract.results = MockTreeMap()
    
    MockGL.message.sender_address = "0x1111111111111111111111111111111111111111"
    contract.register_task("t1", "op", ["https://t.com"], "rules")
    
    task_view = contract.get_task("t1")
    assert task_view["operator"] == "op"
    
    res_view = contract.get_audit_result("t1")
    assert res_view["outcome"] == "PENDING"
    
    contract.audit_task("t1")
    res_view_done = contract.get_audit_result("t1")
    assert res_view_done["outcome"] != "PENDING"
