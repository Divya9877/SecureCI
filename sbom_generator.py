import json
import os

def generate_sbom(filepath):
    sbom = []

    try:
        # Ensure reports folder exists
        os.makedirs("reports", exist_ok=True)

        with open(filepath, "r") as file:
            lines = file.readlines()

        for line in lines:
            line = line.strip()

            if "==" in line:
                package, version = line.split("==")
                sbom.append({
                    "package": package,
                    "version": version
                })

        with open("reports/sbom.json", "w") as report_file:
            json.dump(sbom, report_file, indent=4)

        return sbom

    except Exception as e:
        return [{
            "package": "Error",
            "version": str(e)
        }]