# NodeVanta Intelligent Contract

NodeVanta is a policy-driven multi-source network operation auditor built for the GenLayer network. It serves as an evaluation primitive that answers a critical operational question:

> **Did the permitted node operator execute the exact events defined by the policy configuration across all monitored endpoints?**

By leveraging GenLayer's unique Optimistic Democracy and Equivalence Principle, NodeVanta fetches telemetry from up to 5 external data endpoints non-deterministically and evaluates them using a specialized Intelligence Engine (LLM).

## Overview

Unlike legacy evaluation contracts that rely on strict two-source or retry-heavy architectures, `NodeVanta.py` introduces a dynamic, multi-source telemetry model with simplified persistence. It allows an operator to register a `task_id`, up to 5 telemetry endpoints, and a set of policy rules. The contract then evaluates this context strictly to determine if the event complies with the network's rules.

Possible outcomes are strictly bounded to:
- `COMPLIANT`: Definitive proof that the operation matched the active policy across all telemetry sources.
- `VIOLATION`: Definitive proof that the operation violated the policy, was executed by the wrong actor, or contradicted rules.
- `INCONCLUSIVE`: Ambiguous, conflicting, or missing context (e.g., a data endpoint was unreachable).

## Core Workflow

1. **Registration**: A node session is created via `register_task` specifying the `task_id`, `operator_id`, a list of 1 to 5 `endpoints`, and the `policy_rules`.
2. **Auditing**: The session owner invokes `audit_task(task_id)`.
3. **Data Retrieval & Evaluation**: NodeVanta pulls all registered endpoints via nondeterministic HTTP requests and evaluates the combined telemetry log with its intelligence engine. It returns both an outcome and a generated reasoning string.
4. **Consensus**: Results are finalized through GenLayer's consensus mechanism based on the Equivalence Principle, where leader and validator nodes independently verify the operation without complex intermediate observation state-saving.

## API Methods

### Public Write Methods
- `register_task(task_id: str, operator_id: str, endpoints: list, policy_rules: str)`: Registers a new auditing task.
- `audit_task(task_id: str)`: Evaluates a pending task and initiates the consensus validation.

### Public View Methods
- `get_task(task_id: str) -> dict`: Retrieves the raw task details.
- `get_audit_result(task_id: str) -> dict`: Retrieves the final intelligence outcome (`COMPLIANT`, `VIOLATION`, or `INCONCLUSIVE`), the LLM reasoning, and the telemetry snapshots.

## Deployment

**Studio Contract Address**: `0x048001B82018B5341DdE7B2f79F06BA61374E11D`

[View on GenLayer Studio Explorer](https://explorer-studio.genlayer.com/address/0x048001B82018B5341DdE7B2f79F06BA61374E11D)

## Security

NodeVanta enforces strict schema checks, bounded data retrievals, and deterministic consensus on nondeterministic outputs. It bounds all inputs and fetched context to prevent excessive token usage or memory exhaustion.
