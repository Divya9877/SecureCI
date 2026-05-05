from scanner import scan_dependencies
from risk_engine import calculate_risk
from policy_engine import enforce_policy

filepath = "requirements.txt"

results = scan_dependencies(filepath)
risk_score, decision = calculate_risk(results)
policy_status = enforce_policy(decision)

print("=== SecureCI Pipeline Check ===")
print("Risk Score:", risk_score)
print("Decision:", decision)
print("Policy:", policy_status)

if decision == "Block":
    raise SystemExit("Pipeline failed: Security risk too high")