import json
import os
from datetime import datetime

HISTORY_FILE = "reports/scan_history.json"

def save_scan_history(risk_score, decision, policy_status):
    os.makedirs("reports", exist_ok=True)

    history = []

    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as file:
            try:
                history = json.load(file)
            except:
                history = []

    history.append({
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "risk_score": risk_score,
        "decision": decision,
        "policy_status": policy_status
    })

    with open(HISTORY_FILE, "w") as file:
        json.dump(history, file, indent=4)

def load_scan_history():
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as file:
            try:
                return json.load(file)
            except:
                return []
    return []