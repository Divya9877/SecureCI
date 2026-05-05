def scan_dependencies(filepath):
    results = []

    risky_packages = {
        "django": ("3.0", "High"),
        "flask": ("1.0", "Medium"),
        "requests": ("2.20", "Medium"),
        "urllib3": ("1.25", "High"),
        "jinja2": ("2.11", "Medium")
    }

    try:
        with open(filepath, "r") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()

            if "==" in line:
                package, version = line.split("==")
                package = package.lower()

                if package in risky_packages:
                    safe_version, severity = risky_packages[package]

                    if version < safe_version:
                        results.append({
                            "package": package,
                            "status": "Vulnerable",
                            "severity": severity
                        })
                    else:
                        results.append({
                            "package": package,
                            "status": "Safe",
                            "severity": "Low"
                        })
                else:
                    results.append({
                        "package": package,
                        "status": "Safe",
                        "severity": "Low"
                    })

    except Exception as e:
        results.append({
            "package": "Error",
            "status": str(e),
            "severity": "High"
        })

    return results