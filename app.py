from flask import Flask, render_template, request, send_file
import os
from scanner import scan_dependencies
from risk_engine import calculate_risk
from sbom_generator import generate_sbom
from policy_engine import enforce_policy
from report_generator import generate_report
from history_manager import save_scan_history, load_scan_history

app = Flask(__name__)

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

@app.route("/")
def home():
    return render_template("index.html", history=load_scan_history())

@app.route("/scan", methods=["POST"])
def scan():
    if "file" not in request.files:
        return "No file uploaded"

    file = request.files["file"]

    if file.filename == "":
        return "No selected file"

    filepath = os.path.join(app.config["UPLOAD_FOLDER"], file.filename)
    file.save(filepath)

    results = scan_dependencies(filepath)
    risk_score, decision = calculate_risk(results)
    policy_status = enforce_policy(decision)
    sbom = generate_sbom(filepath)

    # Generate final security reports
    generate_report(results, risk_score, decision, policy_status, sbom)

    # Save and load scan history
    save_scan_history(risk_score, decision, policy_status)
    history = load_scan_history()

    return render_template(
        "index.html",
        results=results,
        risk_score=risk_score,
        decision=decision,
        policy_status=policy_status,
        sbom=sbom,
        history=history
    )

@app.route("/download-report")
def download_report():
    return send_file("reports/scan_report.json", as_attachment=True)

@app.route("/download-pdf")
def download_pdf():
    return send_file("reports/scan_report.pdf", as_attachment=True)

if __name__ == "__main__":
    app.run(debug=True)