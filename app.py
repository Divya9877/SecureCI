from flask import (
    Flask,
    render_template,
    request,
    send_file,
    Response,
    jsonify
)

import os

from datetime import datetime

from pymongo import MongoClient

from scanner import scan_dependencies
from risk_engine import calculate_risk
from sbom_generator import generate_sbom
from policy_engine import enforce_policy
from report_generator import generate_report

from prometheus_client import (
    Counter,
    generate_latest
)

# ---------------------------------
# Flask App
# ---------------------------------

app = Flask(__name__)

# ---------------------------------
# MongoDB Connection
# ---------------------------------

client = MongoClient(
    "mongodb://localhost:27017/"
)

db = client["secureci"]

scan_collection = db["scan_history"]

# ---------------------------------
# Prometheus Metrics
# ---------------------------------

SCAN_COUNTER = Counter(
    'secureci_total_scans',
    'Total dependency scans'
)

BLOCK_COUNTER = Counter(
    'secureci_blocked_builds',
    'Total blocked deployments'
)

# ---------------------------------
# Upload Folder
# ---------------------------------

UPLOAD_FOLDER = "uploads"

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

# ---------------------------------
# HOME PAGE
# ---------------------------------

@app.route("/")
def home():

    return render_template(
        "index.html"
    )

# ---------------------------------
# SCAN ROUTE
# ---------------------------------

@app.route("/scan", methods=["POST"])
def scan():

    dependency_text = request.form.get(
        "dependency_text"
    )

    # ---------------------------------
    # MANUAL INPUT
    # ---------------------------------

    if dependency_text and dependency_text.strip():

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            "manual_input.txt"
        )

        with open(filepath, "w") as f:
            f.write(dependency_text)

    # ---------------------------------
    # FILE INPUT
    # ---------------------------------

    else:

        if "file" not in request.files:
            return "No file uploaded"

        file = request.files["file"]

        if file.filename == "":
            return "No selected file"

        filepath = os.path.join(
            app.config["UPLOAD_FOLDER"],
            file.filename
        )

        file.save(filepath)

    # ---------------------------------
    # SCAN DEPENDENCIES
    # ---------------------------------

    results = scan_dependencies(filepath)

    # Increase metrics
    SCAN_COUNTER.inc()

    # ---------------------------------
    # RISK ENGINE
    # ---------------------------------

    risk_score, decision = calculate_risk(
        results
    )

    # ---------------------------------
    # POLICY ENFORCEMENT
    # ---------------------------------

    policy_status = enforce_policy(
        decision
    )

    if decision == "Block":

        BLOCK_COUNTER.inc()

    # ---------------------------------
    # SBOM
    # ---------------------------------

    sbom = generate_sbom(filepath)

    # ---------------------------------
    # GENERATE REPORTS
    # ---------------------------------

    generate_report(
        results,
        risk_score,
        decision,
        policy_status,
        sbom
    )

    # ---------------------------------
    # SAVE HISTORY
    # ---------------------------------

    scan_collection.insert_one({

        "timestamp": datetime.now().strftime(
            "%d-%m-%Y %H:%M:%S"
        ),

        "risk_score": risk_score,

        "decision": decision,

        "policy_status": policy_status

    })

    # ---------------------------------
    # RESULTS PAGE
    # ---------------------------------

    return render_template(

        "results.html",

        results=results,

        risk_score=risk_score,

        decision=decision,

        policy_status=policy_status,

        sbom=sbom

    )

# ---------------------------------
# HISTORY PAGE
# ---------------------------------

@app.route("/history")
def history_page():

    history = list(
        scan_collection.find({}, {"_id": 0})
    )

    return render_template(
        "history.html",
        history=history
    )

# ---------------------------------
# REPORTS PAGE
# ---------------------------------

@app.route("/reports")
def reports_page():

    return render_template(
        "reports.html"
    )

# ---------------------------------
# ABOUT PAGE
# ---------------------------------

@app.route("/about")
def about_page():

    return render_template(
        "about.html"
    )

# ---------------------------------
# API → HISTORY
# ---------------------------------

@app.route("/api/history")
def api_history():

    data = list(
        scan_collection.find({}, {"_id": 0})
    )

    return jsonify(data)

# ---------------------------------
# API → METRICS
# ---------------------------------

@app.route("/api/metrics")
def api_metrics():

    return jsonify({

        "total_scans":
            SCAN_COUNTER._value.get(),

        "blocked_builds":
            BLOCK_COUNTER._value.get()

    })

# ---------------------------------
# API → LATEST SCAN
# ---------------------------------

@app.route("/api/latest-scan")
def latest_scan():

    latest = scan_collection.find_one(
        sort=[("_id", -1)]
    )

    if latest:

        latest["_id"] = str(
            latest["_id"]
        )

        return jsonify(latest)

    return jsonify({

        "message":
            "No scans found"

    })

# ---------------------------------
# API → HEALTH CHECK
# ---------------------------------

@app.route("/api/health")
def health():

    return jsonify({

        "status": "running",

        "service": "SecureCI"

    })

# ---------------------------------
# API → REPORT
# ---------------------------------

@app.route("/api/report")
def api_report():

    return send_file(
        "reports/scan_report.json",
        as_attachment=True
    )

# ---------------------------------
# DOWNLOAD JSON REPORT
# ---------------------------------

@app.route("/download-report")
def download_report():

    return send_file(
        "reports/scan_report.json",
        as_attachment=True
    )

# ---------------------------------
# DOWNLOAD PDF REPORT
# ---------------------------------

@app.route("/download-pdf")
def download_pdf():

    return send_file(
        "reports/scan_report.pdf",
        as_attachment=True
    )

# ---------------------------------
# PROMETHEUS METRICS
# ---------------------------------

@app.route("/metrics")
def metrics():

    return Response(
        generate_latest(),
        mimetype="text/plain"
    )

# ---------------------------------
# RUN APP
# ---------------------------------

if __name__ == "__main__":

    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )