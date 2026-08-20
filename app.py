from flask import Flask, render_template, request, jsonify
from scanner import run_scan
from datetime import datetime

app = Flask(__name__)
scan_history = []

@app.route("/")
def index():
    return render_template("index.html")

@app.route("/api/scan", methods=["POST"])
def scan():
    target = request.json.get("target", "").strip()
    if not target:
        return jsonify({"error": "No target provided"})
    result = run_scan(target)
    if "error" not in result:
        scan_history.insert(0, {
            "target": result["target"],
            "risk_level": result["risk_level"],
            "risk_score": result["risk_score"],
            "timestamp": result["timestamp"]
        })
        if len(scan_history) > 10:
            scan_history.pop()
    return jsonify(result)

@app.route("/api/history")
def history():
    return jsonify(scan_history)

if __name__ == "__main__":
    app.run(debug=True, port=5003)
