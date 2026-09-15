# { "Depends": "py-genlayer:1jb45aa8ynh2a9c9xn3b7qqh8sm5q93hwfp7jqmwsfhh8jpz09h6" }
from genlayer import *
import json
import re

class NodeVanta(gl.Contract):
    """
    NodeVanta: A generalized multi-source network policy auditor.
    This contract allows users to register a policy and up to 5 telemetry endpoints.
    The intelligence engine evaluates the combined data to determine compliance.
    """
    
    tasks: TreeMap[str, str]
    results: TreeMap[str, str]

    def __init__(self):
        pass

    @gl.public.write
    def register_task(self, task_id: str, operator_id: str, endpoints: list, policy_rules: str) -> None:
        if type(task_id) is not str or not re.match(r"^[a-zA-Z0-9_-]{4,64}$", task_id):
            raise gl.vm.UserError("Invalid task_id format")
            
        if self.tasks.get(task_id, "") != "":
            raise gl.vm.UserError("Task ID already registered")
            
        if type(endpoints) is not list or not (1 <= len(endpoints) <= 5):
            raise gl.vm.UserError("Must provide between 1 and 5 endpoints")
            
        for ep in endpoints:
            if type(ep) is not str or not ep.startswith("https://"):
                raise gl.vm.UserError("Endpoints must be valid HTTPS URLs")
                
        if type(policy_rules) is not str or len(policy_rules) > 2000:
            raise gl.vm.UserError("Policy rules exceed maximum length")

        sender = gl.message.sender_address
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()
        elif hasattr(sender, "as_hex"):
            sender = "0x" + sender.as_hex()
        elif not isinstance(sender, str):
            sender = str(sender)

        task_data = {
            "operator": str(operator_id)[:200],
            "endpoints": endpoints,
            "policy": policy_rules,
            "owner": sender.lower()
        }
        self.tasks[task_id] = json.dumps(task_data, separators=(",", ":"))

    @gl.public.write
    def audit_task(self, task_id: str) -> None:
        raw_task = self.tasks.get(task_id, "")
        if raw_task == "":
            raise gl.vm.UserError("Task not found")
        
        task = json.loads(raw_task)
        sender = gl.message.sender_address
        if isinstance(sender, bytes):
            sender = "0x" + sender.hex()
        elif hasattr(sender, "as_hex"):
            sender = "0x" + sender.as_hex()
        elif not isinstance(sender, str):
            sender = str(sender)
            
        if task["owner"] != sender.lower():
            raise gl.vm.UserError("Unauthorized: Only the task owner can audit")
            
        if self.results.get(task_id, "") != "":
            raise gl.vm.UserError("Task has already been audited")

        # Consensus Execution
        def leader_execution():
            return self._execute_audit(task)
            
        def validator_execution(leader_output):
            if not isinstance(leader_output, gl.vm.Return):
                return False
            try:
                expected_output = self._execute_audit(task)
                return leader_output.calldata == expected_output
            except Exception:
                return False
                
        # The result must be deterministic between leader and validator
        final_audit_result = gl.vm.run_nondet_unsafe(leader_execution, validator_execution)
        self.results[task_id] = json.dumps(final_audit_result, separators=(",", ":"))

    def _execute_audit(self, task: dict) -> dict:
        fetched_telemetry = {}
        # Fetch all registered endpoints
        for ep in task["endpoints"]:
            try:
                res = gl.nondet.web.get(ep, headers={"Accept": "text/plain, application/json"})
                if res.status == 200:
                    body = res.body
                    if isinstance(body, bytes):
                        text = body.decode("utf-8", errors="ignore")
                    else:
                        text = str(body)
                    # Limit payload size to avoid blowing up the context window
                    fetched_telemetry[ep] = text[:4000]
                else:
                    fetched_telemetry[ep] = f"HTTP_ERR_{res.status}"
            except Exception as e:
                fetched_telemetry[ep] = "FETCH_EXCEPTION"

        # Build prompt for LLM evaluation
        prompt = f"""
You are NodeVanta, a rigorous network policy and compliance auditor.
Your objective is to evaluate the fetched telemetry data from multiple endpoints against the registered policy rules.

Operator ID: {task['operator']}
Policy Rules: {task['policy']}

Telemetry Data:
{json.dumps(fetched_telemetry)}

Determine if the operator strictly adhered to the policy rules across all endpoints.
- If ANY telemetry data proves a violation of the policy, return "VIOLATION".
- If the telemetry definitively confirms full compliance with the policy, return "COMPLIANT".
- If the data is missing, contradictory, or insufficient to prove either, return "INCONCLUSIVE".

You must respond ONLY with valid JSON in this exact format, with no other text:
{{"status": "VIOLATION" | "COMPLIANT" | "INCONCLUSIVE", "reason": "A 1-sentence explanation"}}
"""
        try:
            llm_response = gl.nondet.exec_prompt(prompt, response_format="json")
            if isinstance(llm_response, str):
                parsed = json.loads(llm_response)
            else:
                parsed = llm_response
                
            status = parsed.get("status", "INCONCLUSIVE")
            if status not in ("VIOLATION", "COMPLIANT", "INCONCLUSIVE"):
                status = "INCONCLUSIVE"
                
            reason = str(parsed.get("reason", ""))[:200]
            
            return {
                "outcome": status, 
                "reason": reason, 
                "telemetry_log": fetched_telemetry
            }
        except Exception:
            return {
                "outcome": "INCONCLUSIVE", 
                "reason": "LLM evaluation failed or produced invalid format", 
                "telemetry_log": fetched_telemetry
            }

    @gl.public.view
    def get_task(self, task_id: str) -> dict:
        raw = self.tasks.get(task_id, "")
        if raw == "":
            raise gl.vm.UserError("Task not found")
        return json.loads(raw)

    @gl.public.view
    def get_audit_result(self, task_id: str) -> dict:
        raw = self.results.get(task_id, "")
        if raw == "":
            return {"outcome": "PENDING"}
        return json.loads(raw)
