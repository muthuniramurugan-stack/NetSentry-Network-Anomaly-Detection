import os, time, uuid, threading
from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, abort
from netsentry.analyzer import analyze_pcap, demo_analysis

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "netsentry-change-this-secret")
app.config["MAX_CONTENT_LENGTH"] = 25 * 1024 * 1024
AGENT_SECRET = os.environ.get("AGENT_SHARED_SECRET", "")
jobs = {}
jobs_lock = threading.Lock()
latest_job_id = None

def require_agent():
    supplied = request.headers.get("X-Agent-Token", "")
    if not AGENT_SECRET or supplied != AGENT_SECRET:
        abort(401)

@app.route("/")
def index():
    with jobs_lock:
        current = dict(jobs.get(latest_job_id, {})) if latest_job_id else None
    return render_template("index.html", result=None, cloud_job=current)

@app.route("/analyze", methods=["POST"])
def analyze():
    uploaded = request.files.get("pcap_file")
    if not uploaded or not uploaded.filename:
        flash("Select a .pcap or .pcapng capture file.")
        return redirect(url_for("index"))
    if not uploaded.filename.lower().endswith((".pcap", ".pcapng")):
        flash("Only .pcap and .pcapng files are accepted.")
        return redirect(url_for("index"))
    import tempfile
    path = None
    try:
        suffix = ".pcapng" if uploaded.filename.lower().endswith(".pcapng") else ".pcap"
        with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as f:
            path = f.name
            uploaded.save(path)
        result = analyze_pcap(path)
        result["capture_name"] = uploaded.filename
        return render_template("index.html", result=result, cloud_job=None)
    except Exception as exc:
        app.logger.exception("PCAP analysis failed")
        flash(f"Could not analyze capture: {exc}")
        return redirect(url_for("index"))
    finally:
        if path and os.path.exists(path):
            os.remove(path)

@app.route("/scan", methods=["POST"])
def create_scan():
    global latest_job_id
    seconds = request.form.get("duration", "20")
    try:
        seconds = max(5, min(60, int(seconds)))
    except ValueError:
        seconds = 20
    job_id = uuid.uuid4().hex
    job = {"id": job_id, "status": "queued", "duration": seconds, "created": time.time(),
           "message": "Waiting for your local NetSentry Agent to pick up this scan."}
    with jobs_lock:
        jobs[job_id] = job
        latest_job_id = job_id
    return render_template("index.html", result=None, cloud_job=job)

@app.route("/api/agent/next", methods=["GET"])
def agent_next():
    require_agent()
    now = time.time()
    with jobs_lock:
        for job in jobs.values():
            if job["status"] == "queued" and now - job["created"] < 300:
                job["status"] = "running"
                job["message"] = "Local agent is capturing authorized network traffic."
                job["started"] = now
                return jsonify({"job": {"id": job["id"], "duration": job["duration"]}})
    return jsonify({"job": None})

@app.route("/api/agent/result", methods=["POST"])
def agent_result():
    require_agent()
    data = request.get_json(force=True)
    job_id = data.get("id")
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"ok": False, "error": "Unknown or expired scan job"}), 404
        if data.get("error"):
            job.update(status="error", message=str(data["error"])[:500])
        else:
            job.update(status="complete", message="Scan completed by your local agent.", result=data.get("result", {}))
        return jsonify({"ok": True})

@app.route("/api/scan/status/<job_id>")
def scan_status(job_id):
    with jobs_lock:
        job = jobs.get(job_id)
        if not job:
            return jsonify({"error": "Scan job not found"}), 404
        safe = dict(job)
    safe.pop("created", None)
    safe.pop("started", None)
    return jsonify(safe)

@app.route("/health")
def health():
    return {"status": "ok", "application": "NetSentry", "agent_secret_configured": bool(AGENT_SECRET)}

@app.route("/demo")
def demo():
    return render_template("index.html", result=demo_analysis(), cloud_job=None)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
