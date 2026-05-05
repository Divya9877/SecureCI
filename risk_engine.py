def calculate_risk(results):
    score = 0

    for item in results:
        severity = item["severity"]

        if severity == "High":
            score += 30
        elif severity == "Medium":
            score += 20
        elif severity == "Low":
            score += 10

    if score <= 30:
        decision = "Allow"
    elif score <= 60:
        decision = "Warn"
    else:
        decision = "Block"

    return score, decision