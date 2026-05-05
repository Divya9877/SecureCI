import json
import os
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

def generate_report(results, risk_score, decision, policy_status, sbom):
    os.makedirs("reports", exist_ok=True)

    report = {
        "scan_results": results,
        "risk_score": risk_score,
        "deployment_decision": decision,
        "policy_enforcement": policy_status,
        "sbom": sbom
    }

    # Save JSON report
    with open("reports/scan_report.json", "w") as file:
        json.dump(report, file, indent=4)

    # Save PDF report
    pdf_path = "reports/scan_report.pdf"
    c = canvas.Canvas(pdf_path, pagesize=letter)

    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, 750, "SecureCI Security Report")

    c.setFont("Helvetica", 12)
    c.drawString(50, 720, f"Risk Score: {risk_score}")
    c.drawString(50, 700, f"Deployment Decision: {decision}")
    c.drawString(50, 680, f"Policy Enforcement: {policy_status}")

    y = 640
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "Scan Results:")
    y -= 25

    c.setFont("Helvetica", 11)
    for item in results:
        c.drawString(60, y, f"{item['package']} | {item['status']} | {item['severity']}")
        y -= 20

    y -= 20
    c.setFont("Helvetica-Bold", 13)
    c.drawString(50, y, "SBOM:")
    y -= 25

    c.setFont("Helvetica", 11)
    for item in sbom:
        c.drawString(60, y, f"{item['package']} | {item['version']}")
        y -= 20

    c.save()