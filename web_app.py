"""Browser UI for the Blue Team Log Analyzer."""

import os
import tempfile
from pathlib import Path

from dotenv import load_dotenv
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename

from analyzer.detection import detect_bruteforce, group_by_ip
from analyzer.log_parser import parse_log
from analyzer.threat_intel import check_ip

load_dotenv()
app = Flask(__name__)
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_LOG = BASE_DIR / "sample_logs" / "auth.log"


def analyze_file(filepath, threshold):
    entries = parse_log(filepath)
    failed = [entry for entry in entries if entry.is_failed()]
    grouped = group_by_ip(entries)
    flagged = detect_bruteforce(grouped, threshold)
    api_key = os.environ.get("ABUSEIPDB_KEY")
    enriched = []
    for alert in flagged:
        intel = check_ip(alert["ip"], api_key) if api_key else {"ip": alert["ip"]}
        enriched.append({**alert, **intel})
    attempts_by_ip = sorted(((ip, len(items)) for ip, items in grouped.items()), key=lambda item: item[1], reverse=True)
    return {
        "entries": len(entries),
        "failed": len(failed),
        "accepted": len(entries) - len(failed),
        "unique_ips": len(grouped),
        "flagged": enriched,
        "attempts_by_ip": attempts_by_ip,
        "recent_entries": entries[-8:][::-1],
        "filename": Path(filepath).name,
        "threshold": threshold,
        "has_api_key": bool(api_key),
    }


@app.route("/", methods=["GET", "POST"])
def dashboard():
    try:
        threshold = max(2, min(100, int(request.form.get("threshold", "3"))))
    except ValueError:
        threshold = 3
    uploaded = request.files.get("log_file")
    temp_path = None
    try:
        if uploaded and uploaded.filename:
            name = secure_filename(uploaded.filename) or "uploaded.log"
            with tempfile.NamedTemporaryFile(delete=False, suffix="-" + name) as temp_file:
                uploaded.save(temp_file)
                temp_path = temp_file.name
            result = analyze_file(temp_path, threshold)
            result["filename"] = name
        else:
            result = analyze_file(DEFAULT_LOG, threshold)
    except (OSError, ValueError) as error:
        result = {"error": str(error), "filename": "Unable to read log"}
    finally:
        if temp_path:
            Path(temp_path).unlink(missing_ok=True)
    return render_template("index.html", result=result)


if __name__ == "__main__":
    app.run(debug=True)
