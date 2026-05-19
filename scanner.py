import requests


def get_severity(vulns):

    if not vulns:
        return "Low"

    for vuln in vulns:

        if "severity" in vuln:

            for sev in vuln["severity"]:

                score = sev.get(
                    "score",
                    ""
                )

                if "9." in score or "8." in score:
                    return "High"

                elif (
                    "7." in score
                    or "6." in score
                    or "5." in score
                ):
                    return "Medium"

        summary = vuln.get(
            "summary",
            ""
        ).lower()

        if (
            "malicious" in summary
            or "typosquat" in summary
        ):
            return "High"

    if len(vulns) >= 3:
        return "High"

    elif len(vulns) == 2:
        return "Medium"

    else:
        return "Low"


def scan_dependencies(filepath):

    results = []

    try:

        with open(filepath, "r") as file:

            lines = file.readlines()

        for line in lines:

            line = line.strip()

            if "==" in line:

                package, version = line.split("==")

                payload = {

                    "version": version,

                    "package": {

                        "name": package,

                        "ecosystem": "PyPI"

                    }

                }

                try:

                    response = requests.post(

                        "https://api.osv.dev/v1/query",

                        json=payload,

                        timeout=30

                    )

                    data = response.json()

                    vulns = data.get(
                        "vulns",
                        []
                    )

                    if vulns:

                        severity = get_severity(
                            vulns
                        )

                        cve_id = vulns[0].get(
                            "id",
                            "N/A"
                        )

                        results.append({

                            "package": package,

                            "status": "Vulnerable",

                            "severity": severity,

                            "cve": cve_id

                        })

                    else:

                        results.append({

                            "package": package,

                            "status": "Safe",

                            "severity": "Low",

                            "cve": "N/A"

                        })

                except Exception as e:

                    results.append({

                        "package": package,

                        "status": "API Timeout/Error",

                        "severity": "Medium",

                        "cve": "N/A"

                    })

    except Exception as e:

        results.append({

            "package": "System Error",

            "status": str(e),

            "severity": "High",

            "cve": "N/A"

        })

    return results