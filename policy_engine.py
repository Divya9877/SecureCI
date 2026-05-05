def enforce_policy(decision):
    if decision == "Allow":
        return "Deployment Approved"
    elif decision == "Warn":
        return "Deployment Allowed with Warning"
    else:
        return "Deployment Blocked"