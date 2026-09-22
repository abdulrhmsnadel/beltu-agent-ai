Analyze the current BELTU context below.

Return exactly this JSON shape:
{
  "summary": "brief evidence-grounded summary",
  "hypotheses": [
    {
      "statement": "testable hypothesis",
      "basis_observation_ids": [1, 2],
      "confidence": 0.0
    }
  ],
  "actions": [
    {
      "action_kind": "one allowed action kind: surface_inventory|service_enrichment|endpoint_mapping|api_analysis|auth_analysis|access_control_analysis|business_logic_analysis|finding_validation|browser_automation|http_workflow|session_replay|api_manipulation|authorization_testing|business_logic_workflow|race_condition_testing",
      "action_payload": {
        "target": "exact current target",
        "hypothesis": "matching hypothesis statement",
        "observation_ids": [1]
      },
      "rationale": "why this next action reduces uncertainty",
      "confidence": 0.0,
      "risk_level": "low|medium|high",
      "requires_approval": true
    }
  ]
}

Do not include fields outside this contract.

{context}
