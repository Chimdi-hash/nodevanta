# NodeVanta Intelligent Contract

NodeVanta is a policy-driven node operation validator built for the GenLayer network. It serves as an evaluation primitive that answers a critical operational question:

> **Did the permitted node operator execute the exact event defined by the policy configuration at the relevant time?**

By leveraging GenLayer's unique Optimistic Democracy and Equivalence Principle, NodeVanta fetches external data endpoints (policies and operation telemetry) non-deterministically and evaluates them using a specialized Intelligence Engine (LLM).

## Overview

`NodeVanta.py` handles semantic policy validation. It captures an operation telemetry task and fetches necessary context (policy rules and event logs). It evaluates this context strictly to determine if the event complies with the network's rules, ensuring that node operators cannot spoof operational logs or operate outside of their allowed constraints.

Possible outcomes are strictly bounded to:
- `APPROVED`: Definitive proof that the operation matched the active policy.
- `REJECTED`: Definitive proof that the operation violated the policy, was executed by the wrong actor, or occurred outside the valid timeframe.
- `INCONCLUSIVE`: Ambiguous, conflicting, or missing context (e.g., a data endpoint was unreachable).

## Core Workflow

1. **Initialization**: A node session is created via `initialize_session` containing the policy endpoint and operation data endpoint.
2. **Processing**: The session owner invokes `process_session`.
3. **Data Retrieval & Evaluation**: NodeVanta pulls context data via nondeterministic HTTP requests and evaluates it with its intelligence engine.
4. **Consensus**: Results are finalized through GenLayer's consensus mechanism based on the Equivalence Principle, where leader and validator nodes independently verify the operation.

## API Methods

### Public Write Methods
- `initialize_session(task_payload: str) -> str`: Initializes a new node validation task with a JSON payload defining the policy and operation data.
- `process_session(task_id: str)`: Evaluates a pending session and initiates the consensus validation.
- `reassess_session(task_id: str)`: Retries a session that failed due to temporary network issues (up to 3 retries).

### Public View Methods
- `get_session(task_id: str) -> dict`: Retrieves the raw session details.
- `get_session_result(task_id: str) -> dict`: Retrieves the final intelligence outcome (`APPROVED`, `REJECTED`, or `INCONCLUSIVE`) and telemetry hashes.
- `is_concluded(task_id: str) -> bool`: Checks if a session has been successfully evaluated.

## Requirements & Deployment

- Built strictly for the **GenLayer Studio network**.
- Requires the `genlayer` Python SDK.
- Complies with GenVM Linter rules.

## Security

NodeVanta enforces strict schema checks, bounded data retrievals, and deterministic consensus on nondeterministic outputs. It bounds all inputs and fetched context to prevent excessive token usage or memory exhaustion.

## Deployment

**Studio Contract Address**: `0x2Ab9bcCD90b670A5205bD4Feaf77BEB70ac98Cf3`

[View on GenLayer Studio Explorer](https://explorer-studio.genlayer.com/address/0x2Ab9bcCD90b670A5205bD4Feaf77BEB70ac98Cf3)

