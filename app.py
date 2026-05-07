from flask import Flask, render_template, request, send_file, Response
import os

from scanner import scan_dependencies
from risk_engine import calculate_risk
from sbom_generator import generate_sbom
from policy_engine import enforce_policy
from report_generator import generate_report
from history_manager import save_scan_history, load_scan_history

from prometheus_client import Counter, generate_latest

app = Flask(__name__)

# -------------------------------
# Prometheus Metrics
# -------------------------------

SCAN_COUNTER = Counter(
    'secureci_total_scans',
    'Total dependency scans'
)

BLOCK_COUNTER = Counter(
    'secureci_blocked_builds',
    'Total blocked deployments'
)

# -------------------------------
# Upload Folder
# -------------------------------

UPLOAD_FOLDER = "uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# -------------------------------
# Home Page
# -------------------------------

@app.route("/")
def home():

    history = load_scan_history()

    return render_template(
        "index.html",
        history=history
    )

# -------------------------------
# Scan Route
# -------------------------------

@app.route("/scan", methods=["POST"])
def scan():

    # Check file upload
    if "file" not in request.files:
        return "No file uploaded"

    file = request.files["file"]

    if file.filename == "":
        return "No selected file"

    # Save uploaded file
    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        file.filename
    )

    file.save(filepath)

    # -------------------------------
    # Dependency Scanning
    # -------------------------------

    results = scan_dependencies(filepath)

    # Increase scan metric
    SCAN_COUNTER.inc()

    # -------------------------------
    # Risk Engine
    # -------------------------------

    risk_score, decision = calculate_risk(results)

    # -------------------------------
    # Policy Enforcement
    # -------------------------------

    policy_status = enforce_policy(decision)

    # Increase blocked counter
    if decision == "Block":
        BLOCK_COUNTER.inc()

    # -------------------------------
    # Generate SBOM
    # -------------------------------

    sbom = generate_sbom(filepath)

    # -------------------------------
    # Generate Reports
    # -------------------------------

    generate_report(
        results,
        risk_score,
        decision,
        policy_status,
        sbom
    )

    # -------------------------------
    # Save Scan History
    # -------------------------------

    save_scan_history(
        risk_score,
        decision,
        policy_status
    )

    history = load_scan_history()

    # -------------------------------
    # Render Results
    # -------------------------------

    return render_template(
        "index.html",
        results=results,
        risk_score=risk_score,
        decision=decision,
        policy_status=policy_status,
        sbom=sbom,
        history=history
    )

# -------------------------------
# Download JSON Report
# -------------------------------

@app.route("/download-report")
def download_report():

    return send_file(
        "reports/scan_report.json",
        as_attachment=True
    )

# -------------------------------
# Download PDF Report
# -------------------------------

@app.route("/download-pdf")
def download_pdf():

    return send_file(
        "reports/scan_report.pdf",
        as_attachment=True
    )

# -------------------------------
# Prometheus Metrics Endpoint
# -------------------------------

@app.route("/metrics")
def metrics():

    return Response(
        generate_latest(),
        mimetype="text/plain"
    )

# -------------------------------
# Run Flask App
# -------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )