import copy
import json

import pytest

from conftest import (
    OPERATION_DATA_URL,
    ALICE,
    AUTH_URL,
    BOB,
    Harness,
    base_payload,
    expect_error,
    response,
    set_sender,
    set_time,
)


def test_ready_state_and_public_reads():
    h = Harness()
    task_id = h.create()
    evaluation = h.contract.get_session_result(task_id)
    assert evaluation == {
        "api_ver": "1.0",
        "task_id": task_id,
        "phase": "READY",
        "attempt_count": 0,
        "task_hash": h.contract.get_session(task_id)["task_hash"],
    }
    assert h.contract.is_concluded(task_id) is False
    assert h.contract.get_layer_data(task_id, "POLICY_CONFIG")["data_endpoint"] == AUTH_URL
    assert h.contract.get_layer_data(task_id, "OPERATION_DATA")["data_endpoint"] == OPERATION_DATA_URL
    expect_error(lambda: h.contract.get_layer_data(task_id, "PREREQUISITE"), "INVALID_ROLE")


def test_success_finalizes_authorized_and_evaluation_is_immutable():
    h = Harness(llm={"outcome": "APPROVED"})
    task_id = h.create()
    h.contract.process_session(task_id)
    before = h.contract.get_session_result(task_id)
    assert before["phase"] == "FINALIZED"
    assert before["outcome"] == "APPROVED"
    assert before["attempt_count"] == 0
    assert h.contract.is_concluded(task_id) is True
    expect_error(lambda: h.contract.process_session(task_id), "INVALID_STATE")
    expect_error(lambda: h.contract.reassess_session(task_id), "INVALID_STATE")
    assert h.contract.get_session_result(task_id) == before


def test_unauthorized_and_unresolved_are_final_results():
    for status in ("UNAPPROVED", "INCONCLUSIVE"):
        h = Harness(llm={"outcome": status})
        task_id = h.create()
        h.contract.process_session(task_id)
        evaluation = h.contract.get_session_result(task_id)
        assert evaluation["phase"] == "FINALIZED"
        assert evaluation["outcome"] == status
        assert evaluation["attempt_count"] == 0


def transient_harness():
    return Harness(web={AUTH_URL: response(status=503), OPERATION_DATA_URL: response(status=503)})


def test_retry_lifecycle_has_no_fourth_retry():
    h = transient_harness()
    task_id = h.create()
    assert h.contract.get_session_result(task_id)["phase"] == "READY"
    h.contract.process_session(task_id)
    first = h.contract.get_session_result(task_id)
    assert first["phase"] == "RETRYABLE_FAILURE"
    assert first["attempt_count"] == 0
    set_time(h, "2026-01-02T00:00:00Z")
    h.contract.reassess_session(task_id)
    second = h.contract.get_session_result(task_id)
    assert second["phase"] == "RETRYABLE_FAILURE"
    assert second["attempt_count"] == 1
    set_time(h, "2026-01-03T00:00:00Z")
    h.contract.reassess_session(task_id)
    set_time(h, "2026-01-04T00:00:00Z")
    h.contract.reassess_session(task_id)
    final = h.contract.get_session_result(task_id)
    assert final["phase"] == "FINALIZED"
    assert final["outcome"] == "INCONCLUSIVE"
    assert final["attempt_count"] == 3
    assert h.contract.is_concluded(task_id) is True
    expect_error(lambda: h.contract.reassess_session(task_id), "INVALID_STATE")


def test_terminal_failure_finalizes_without_retry():
    h = Harness(web={AUTH_URL: response(status=404), OPERATION_DATA_URL: response(body="operation_data")})
    task_id = h.create()
    h.contract.process_session(task_id)
    evaluation = h.contract.get_session_result(task_id)
    assert evaluation["phase"] == "FINALIZED"
    assert evaluation["outcome"] == "INCONCLUSIVE"
    assert evaluation["attempt_count"] == 0
    expect_error(lambda: h.contract.reassess_session(task_id), "INVALID_STATE")


def test_retry_ready_case_and_non_owner_writes_are_rejected():
    h = Harness()
    task_id = h.create()
    expect_error(lambda: h.contract.reassess_session(task_id), "READY")
    set_sender(h, BOB)
    expect_error(lambda: h.contract.process_session(task_id), "UNAPPROVED")
    expect_error(lambda: h.contract.reassess_session(task_id), "UNAPPROVED")


def test_owner_indexes_are_bounded_one_by_one_lookups():
    h = Harness()
    first = h.create()
    second = h.create()
    assert h.contract.get_owner_task_tally(ALICE) == 2
    assert h.contract.get_owner_task_id(ALICE, 1) == first
    assert h.contract.get_owner_task_id(ALICE, 2) == second
    assert h.contract.get_owner_task_tally(BOB) == 0
    for index in (0, -1, 3):
        expect_error(lambda index=index: h.contract.get_owner_task_id(ALICE, index), "INVALID_INDEX")
    expect_error(lambda: h.contract.get_owner_task_id(BOB, 1), "INVALID_INDEX")


def test_missing_case_and_invalid_task_ids_are_rejected():
    h = Harness()
    for method in (
        h.contract.get_session, h.contract.get_session_result, h.contract.is_concluded,
    ):
        expect_error(lambda method=method: method("auth-" + "a" * 64), "case not found")
    expect_error(lambda: h.contract.get_session("bad"), "INVALID_CASE_ID")
    expect_error(lambda: h.contract.get_layer_data("bad", "OPERATION_DATA"), "INVALID_CASE_ID")


def test_address_normalization_is_lowercase_and_zero_address_is_rejected():
    h = Harness()
    assert h.contract.get_owner_task_tally(ALICE.upper()) == 0
    expect_error(lambda: h.contract.get_owner_task_tally("0x" + "0" * 40), "zero address")
    expect_error(lambda: h.contract.get_owner_task_tally("not-an-address"), "address format")


def test_canonical_json_is_key_order_independent():
    h = Harness()
    left = {"z": 1, "a": {"y": 2, "x": 3}}
    right = {"a": {"x": 3, "y": 2}, "z": 1}
    assert h.module._canonical(left) == h.module._canonical(right)
    assert h.module._digest("case", left) == h.module._digest("case", right)
    assert h.module._digest("case", left) != h.module._digest("result", left)


@pytest.mark.parametrize("path", [
    ("task_name", "Changed title"),
    ("target_entity", "Changed subject"),
    ("node_operator", "Bob"),
])
def test_consequential_top_level_fields_change_task_hash_and_id(path):
    key, replacement = path
    first = Harness()
    first_id = first.create()
    first_case = first.contract.get_session(first_id)
    value = base_payload()
    value[key] = replacement
    second = Harness()
    second_id = second.create(value)
    second_case = second.contract.get_session(second_id)
    assert second_case["task_hash"] != first_case["task_hash"]
    assert second_id != first_id


@pytest.mark.parametrize("role,field", [
    ("policy_config", "policy_rules"), ("policy_config", "tag"),
    ("policy_config", "data_endpoint"), ("operation_data", "operation_details"),
    ("operation_data", "tag"), ("operation_data", "data_endpoint"),
])
def test_consequential_nested_fields_change_task_hash(role, field):
    first = Harness()
    first_id = first.create()
    original = first.contract.get_session(first_id)["task_hash"]
    value = base_payload()
    if field == "data_endpoint":
        value[role][field] = "https://changed.example/changed.json"
    else:
        value[role][field] += " changed"
    second = Harness()
    second_id = second.create(value)
    assert second.contract.get_session(second_id)["task_hash"] != original


def test_same_case_inputs_have_stable_task_id():
    left = Harness(timestamp="2026-01-01T00:00:00Z")
    right = Harness(timestamp="2026-01-01T00:00:00Z")
    first_left = left.create()
    first_right = right.create()
    assert first_left == first_right
    assert left.create() != first_left


def test_source_observation_and_consensus_hashs_bind_content_status_and_metadata():
    h = Harness(llm={"outcome": "APPROVED"})
    task_id = h.create()
    h.contract.process_session(task_id)
    proposal = h.vm.captured[-1][0]
    case = h.contract.get_session(task_id)
    observations = copy.deepcopy(proposal["telemetry_data"])
    assert proposal["telemetry_hash"] == h.module._digest("source-observations", observations)
    changed_observations = copy.deepcopy(observations)
    changed_observations[0]["payload_hash"] = "b" * 64
    assert h.module._digest("source-observations", changed_observations) != proposal["telemetry_hash"]
    assert h.module._consensus_hash(case, observations, proposal["telemetry_hash"], "APPROVED") != h.module._consensus_hash(case, observations, proposal["telemetry_hash"], "UNAPPROVED")
    assert h.module._eval_hash(case, observations, 0, proposal["telemetry_hash"], "APPROVED", proposal["concluded_ts"]) == proposal["eval_hash"]
    assert h.module._eval_hash(case, observations, 1, proposal["telemetry_hash"], "APPROVED", proposal["concluded_ts"]) != proposal["eval_hash"]
    assert h.module._eval_hash(case, observations, 0, proposal["telemetry_hash"], "APPROVED", proposal["concluded_ts"] + 1) != proposal["eval_hash"]

