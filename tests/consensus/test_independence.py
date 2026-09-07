import copy

import pytest

from conftest import (
    OPERATION_DATA_BODY,
    OPERATION_DATA_URL,
    AUTH_BODY,
    AUTH_URL,
    Harness,
    Return,
    ConsensusError,
    response,
)


def prepared(status="APPROVED"):
    h = Harness(llm={"outcome": status})
    task_id = h.create()
    h.contract.process_session(task_id)
    return h, task_id


def test_leader_and_validator_each_refetch_both_sources_and_semantics():
    h, task_id = prepared()
    proposal, leader, validator = h.vm.captured[-1]
    assert proposal["task_id"] == task_id
    assert len(h.web.calls) == 4
    assert len(h.llm.calls) == 2
    assert leader is not validator
    assert validator(Return(copy.deepcopy(proposal))) is True
    assert len(h.web.calls) == 6
    assert len(h.llm.calls) == 3


@pytest.mark.parametrize("mutate", [
    lambda p: p.update({"task_id": "auth-" + "b" * 64}),
    lambda p: p.update({"task_hash": "b" * 64}),
    lambda p: p.update({"phase": "RETRYABLE_FAILURE"}),
    lambda p: p.update({"attempt_count": 1}),
    lambda p: p.update({"concluded_ts": p["concluded_ts"] + 1}),
    lambda p: p.update({"telemetry_hash": "b" * 64}),
    lambda p: p.update({"eval_hash": "b" * 64}),
    lambda p: p.update({"consensus_hash": "b" * 64}),
    lambda p: p.update({"outcome": "UNAPPROVED"}),
    lambda p: p["telemetry_data"][0].update({"layer": "OPERATION_DATA"}),
    lambda p: p["telemetry_data"][0].update({"payload_hash": "b" * 64}),
    lambda p: p["telemetry_data"][1].update({"is_online": False}),
])
def test_tampered_complete_proposals_are_rejected(mutate):
    h, _ = prepared("APPROVED")
    proposal, _, validator = h.vm.captured[-1]
    tampered = copy.deepcopy(proposal)
    mutate(tampered)
    assert validator(Return(tampered)) is False


def test_missing_extra_reordered_and_malformed_proposals_are_rejected():
    h, _ = prepared()
    proposal, _, validator = h.vm.captured[-1]
    candidates = [
        {key: value for key, value in proposal.items() if key != "outcome"},
        {**proposal, "extra": True},
        {**proposal, "telemetry_data": proposal["telemetry_data"][:1]},
        {**proposal, "telemetry_data": list(reversed(proposal["telemetry_data"]))},
        None,
        [],
    ]
    for candidate in candidates:
        assert validator(Return(candidate)) is False
    assert validator(object()) is False


def test_validator_does_not_accept_leader_status_or_format_without_independent_evidence():
    h, _ = prepared("APPROVED")
    proposal, _, validator = h.vm.captured[-1]
    altered = copy.deepcopy(proposal)
    altered["outcome"] = "UNAPPROVED"
    assert validator(Return(altered)) is False
    h.web.responses[AUTH_URL] = response(status=404)
    assert validator(Return(copy.deepcopy(proposal))) is False


@pytest.mark.parametrize("leader_status,validator_status", [
    ("APPROVED", "UNAPPROVED"),
    ("APPROVED", "INCONCLUSIVE"),
    ("UNAPPROVED", "INCONCLUSIVE"),
    ("INCONCLUSIVE", "APPROVED"),
])
def test_semantic_disagreement_rejects_consensus(leader_status, validator_status):
    h = Harness(
        web={AUTH_URL: [response(body=AUTH_BODY), response(body=AUTH_BODY + " validator snapshot")],
             OPERATION_DATA_URL: [response(body=OPERATION_DATA_BODY), response(body=OPERATION_DATA_BODY + " validator snapshot")]},
        llm=[{"outcome": leader_status}, {"outcome": validator_status}],
    )
    task_id = h.create()
    case = h.contract.get_session(task_id)
    with pytest.raises(ConsensusError):
        h.module._consensus(case, task_id, 0, 0)
    assert h.vm.validations[-1] is False


def test_storage_is_loaded_before_nondeterministic_execution():
    h, task_id = prepared()
    h2 = Harness()
    task_id = h2.create()
    in_nondet = {"value": False}
    original_load = h2.contract._load_case

    def guarded_load(value):
        if in_nondet["value"]:
            raise RuntimeError("storage read inside nondeterministic closure")
        return original_load(value)

    h2.contract._load_case = guarded_load
    original_run = h2.vm.run_nondet_unsafe

    def guarded_run(leader_fn, validator_fn):
        in_nondet["value"] = True
        try:
            return original_run(leader_fn, validator_fn)
        finally:
            in_nondet["value"] = False

    h2.vm.run_nondet_unsafe = guarded_run
    h2.contract.process_session(task_id)
    assert h2.contract.get_session_result(task_id)["phase"] == "FINALIZED"


def test_plain_case_snapshot_is_sufficient_for_both_consensus_paths():
    h, task_id = prepared()
    case = h.contract.get_session(task_id)
    original = h.contract._load_case
    calls = {"count": 0}

    def counted_load(value):
        calls["count"] += 1
        return original(value)

    h.contract._load_case = counted_load
    result = h.module._consensus(case, task_id, 0, 0)
    assert result["task_id"] == task_id
    assert calls["count"] == 0


