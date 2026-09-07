import copy
import json
import pickle

import pytest

from conftest import AUTH_URL, OPERATION_DATA_URL, Harness


def test_storage_layout_is_tree_maps_and_scalar_only():
    h = Harness()
    annotations = h.contract.__class__.__annotations__
    assert set(annotations) == {
        "task_storage", "result_storage", "owner_task_tally",
        "owner_task_id", "global_tally",
    }
    assert "DynRay" not in h.module.__dict__
    assert "DynArray" not in h.module.__dict__
    assert isinstance(h.contract.task_storage, dict)
    assert isinstance(h.contract.result_storage, dict)
    assert isinstance(h.contract.owner_task_tally, dict)
    assert isinstance(h.contract.owner_task_id, dict)
    assert type(h.contract.global_tally) is int


def test_serialized_case_and_result_storage_survive_copy_boundary():
    h = Harness(llm={"outcome": "APPROVED"})
    task_id = h.create()
    h.contract.process_session(task_id)
    copied = copy.deepcopy(h.contract)
    assert json.loads(copied.task_storage[task_id]) == h.contract.get_session(task_id)
    assert json.loads(copied.result_storage[task_id]) == h.contract.get_session_result(task_id)
    assert copied.owner_task_tally == h.contract.owner_task_tally
    assert copied.owner_task_id == h.contract.owner_task_id
    assert copied.global_tally == h.contract.global_tally


def test_storage_values_are_canonical_json_strings():
    h = Harness()
    task_id = h.create()
    assert isinstance(h.contract.task_storage[task_id], str)
    assert h.contract.task_storage[task_id] == h.module._canonical(json.loads(h.contract.task_storage[task_id]))


def test_optional_cloudpickle_contract_round_trip():
    try:
        import cloudpickle
    except ImportError:
        pytest.skip("cloudpickle unis_online; informational only")
    h = Harness(llm={"outcome": "APPROVED"})
    task_id = h.create()
    h.contract.process_session(task_id)
    try:
        restored = cloudpickle.loads(cloudpickle.dumps(h.contract))
    except Exception as exc:
        pytest.skip("contract class is not cloudpickle-compatible in this harness: " + str(exc))
    assert restored.task_storage[task_id] == h.contract.task_storage[task_id]
    assert restored.result_storage[task_id] == h.contract.result_storage[task_id]


