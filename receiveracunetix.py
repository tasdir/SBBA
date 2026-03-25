#!/usr/bin/env python3
"""
Receiver API + Acunetix Queue Worker + Post-Scan Cleanup + Full JSON Tracking
Runs on your Acunetix VPS (127.0.0.1:3443)

Pipeline:
  1. Recon VPS pushes subdomains  →  POST /submit
  2. Queue worker adds target + triggers scan in Acunetix
  3. Cleanup worker polls completed scans:
       - Critical / High / Medium found  →  KEEP target + scan
       - Only Low / Info / nothing       →  DELETE scan + target
  4. Every state change is written to  pipeline_tracking.json
"""

import os
import json
import time
import logging
import threading
import requests
from queue import Queue
from datetime import datetime, timezone
from flask import Flask, request, jsonify
from functools import wraps
from pathlib import Path

# ──────────────────────────────────────────────
# CONFIG
# ──────────────────────────────────────────────
ACUNETIX_URL    = "https://127.0.0.1:3443"
ACUNETIX_APIKEY = os.environ.get("ACUNETIX_APIKEY", "YOUR_ACUNETIX_API_KEY")
RECEIVER_PORT   = 8888
RECEIVER_SECRET = os.environ.get("RECEIVER_SECRET", "changeme_secret_token")

# Acunetix scan profile UUID — run: GET /api/v1/scan_profiles
SCAN_PROFILE_ID = "11111111-1111-1111-1111-111111111111"

# Severities to KEEP — targets with ONLY severities NOT in this set get deleted
KEEP_SEVERITIES = {"critical", "high", "medium"}

# How often the cleanup worker checks for finished scans (seconds)
CLEANUP_POLL_INTERVAL = 60

# Throttle between Acunetix API calls in the queue worker (seconds)
QUEUE_DELAY = 2

# JSON tracking file path
TRACKING_FILE = Path("pipeline_tracking.json")

# ──────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler("pipeline.log"),
        logging.StreamHandler()
    ]
)
log = logging.getLogger(__name__)

# ──────────────────────────────────────────────
# JSON TRACKING LAYER
# Thread-safe read/write to pipeline_tracking.json
# ──────────────────────────────────────────────
tracking_lock = threading.Lock()

TRACKING_SCHEMA = {
    "meta": {
        "created_at":       None,
        "last_updated":     None,
        "total_queued":     0,
        "total_scanned":    0,
        "total_kept":       0,
        "total_pruned":     0,
        "total_failed":     0,
    },
    # Each entry keyed by URL
    # "https://sub.example.com": { ...see track_*() functions... }
    "targets": {}
}


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_tracking() -> dict:
    """Load tracking file from disk. Returns schema if missing."""
    if TRACKING_FILE.exists():
        try:
            with open(TRACKING_FILE, "r") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            log.warning(f"[TRACK] Could not read tracking file: {e} — resetting.")
    schema = json.loads(json.dumps(TRACKING_SCHEMA))
    schema["meta"]["created_at"] = _now()
    return schema


def _save_tracking(data: dict):
    """Write tracking dict to disk atomically via a temp file."""
    data["meta"]["last_updated"] = _now()
    tmp = TRACKING_FILE.with_suffix(".tmp")
    with open(tmp, "w") as f:
        json.dump(data, f, indent=2)
    tmp.replace(TRACKING_FILE)


def track_queued(url: str, source: str):
    with tracking_lock:
        data = _load_tracking()
        data["targets"][url] = {
            "url":          url,
            "source":       source,
            "status":       "queued",
            "target_id":    None,
            "scan_id":      None,
            "queued_at":    _now(),
            "scan_started_at":   None,
            "scan_finished_at":  None,
            "scan_status":  None,
            "severity_counts": {},
            "decision":     None,   # "kept" | "pruned"
            "decision_at":  None,
            "failure_reason": None,
            "deleted_scan":    False,
            "deleted_target":  False,
        }
        data["meta"]["total_queued"] += 1
        _save_tracking(data)


def track_target_added(url: str, target_id: str):
    with tracking_lock:
        data = _load_tracking()
        if url in data["targets"]:
            data["targets"][url]["target_id"] = target_id
            data["targets"][url]["status"]    = "target_added"
        _save_tracking(data)


def track_scan_started(url: str, scan_id: str):
    with tracking_lock:
        data = _load_tracking()
        if url in data["targets"]:
            data["targets"][url]["scan_id"]          = scan_id
            data["targets"][url]["status"]           = "scanning"
            data["targets"][url]["scan_started_at"]  = _now()
        data["meta"]["total_scanned"] += 1
        _save_tracking(data)


def track_scan_finished(url: str, scan_status: str, severity_counts: dict):
    with tracking_lock:
        data = _load_tracking()
        if url in data["targets"]:
            data["targets"][url]["scan_status"]      = scan_status
            data["targets"][url]["scan_finished_at"] = _now()
            data["targets"][url]["severity_counts"]  = severity_counts
        _save_tracking(data)


def track_decision(url: str, decision: str):
    """decision = 'kept' | 'pruned'"""
    with tracking_lock:
        data = _load_tracking()
        if url in data["targets"]:
            data["targets"][url]["decision"]    = decision
            data["targets"][url]["decision_at"] = _now()
            data["targets"][url]["status"]      = decision
        if decision == "kept":
            data["meta"]["total_kept"] += 1
        else:
            data["meta"]["total_pruned"] += 1
        _save_tracking(data)


def track_deleted(url: str, what: str):
    """what = 'scan' | 'target'"""
    with tracking_lock:
        data = _load_tracking()
        if url in data["targets"]:
            if what == "scan":
                data["targets"][url]["deleted_scan"]   = True
            elif what == "target":
                data["targets"][url]["deleted_target"] = True
        _save_tracking(data)


def track_failed(url: str, reason: str):
    with tracking_lock:
        data = _load_tracking()
        if url in data["targets"]:
            data["targets"][url]["status"]         = "failed"
            data["targets"][url]["failure_reason"] = reason
            data["targets"][url]["decision"]       = "failed"
            data["targets"][url]["decision_at"]    = _now()
        data["meta"]["total_failed"] += 1
        _save_tracking(data)


def get_tracking_summary() -> dict:
    with tracking_lock:
        return _load_tracking()


# ──────────────────────────────────────────────
# GLOBAL STATE
# ──────────────────────────────────────────────
subdomain_queue: Queue = Queue()

# { scan_id: { target_id, url, started_at } }
active_scans: dict = {}
active_scans_lock = threading.Lock()

# ──────────────────────────────────────────────
# FLASK APP
# ──────────────────────────────────────────────
app = Flask(__name__)


def require_token(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if auth != f"Bearer {RECEIVER_SECRET}":
            return jsonify({"error": "Unauthorized"}), 401
        return f(*args, **kwargs)
    return decorated


@app.route("/submit", methods=["POST"])
@require_token
def submit_subdomains():
    """
    POST /submit
    Body: { "source": "recon-vps-01", "subdomains": ["sub.example.com", ...] }
    """
    data = request.get_json(force=True, silent=True)
    if not data or "subdomains" not in data:
        return jsonify({"error": "Missing 'subdomains' list"}), 400

    source     = data.get("source", "unknown")
    subdomains = data.get("subdomains", [])

    if not isinstance(subdomains, list):
        return jsonify({"error": "'subdomains' must be a list"}), 400

    normalized = []
    for s in subdomains:
        s = s.strip()
        if s and not s.startswith(("http://", "https://")):
            s = f"https://{s}"
        if s:
            normalized.append(s)

    for sub in normalized:
        subdomain_queue.put({
            "url":         sub,
            "source":      source,
            "received_at": _now()
        })
        track_queued(sub, source)

    log.info(f"[RECV] {len(normalized)} subdomains queued from '{source}' | depth: {subdomain_queue.qsize()}")
    return jsonify({
        "status":     "queued",
        "queued":     len(normalized),
        "queue_size": subdomain_queue.qsize()
    }), 202


@app.route("/status", methods=["GET"])
@require_token
def status():
    """Live stats — pulled from the tracking JSON."""
    with active_scans_lock:
        in_flight = len(active_scans)
    summary = get_tracking_summary()
    return jsonify({
        "queue_pending":   subdomain_queue.qsize(),
        "scans_in_flight": in_flight,
        "meta":            summary["meta"],
    })


@app.route("/report", methods=["GET"])
@require_token
def report():
    """
    Full target report. Optional query filters:
      ?status=kept|pruned|failed|scanning|queued
      ?source=recon-vps-01
      ?severity=critical   (only targets that have at least 1 of this severity)
    """
    status_filter   = request.args.get("status")
    source_filter   = request.args.get("source")
    severity_filter = request.args.get("severity", "").lower()

    summary = get_tracking_summary()
    targets = list(summary["targets"].values())

    if status_filter:
        targets = [t for t in targets if t.get("status") == status_filter]
    if source_filter:
        targets = [t for t in targets if t.get("source") == source_filter]
    if severity_filter:
        targets = [t for t in targets
                   if t.get("severity_counts", {}).get(severity_filter, 0) > 0]

    return jsonify({
        "meta":    summary["meta"],
        "count":   len(targets),
        "targets": targets
    })


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


# ──────────────────────────────────────────────
# ACUNETIX API HELPERS
# ──────────────────────────────────────────────
def _acu(method: str, path: str, **kwargs):
    try:
        return requests.request(
            method,
            f"{ACUNETIX_URL}{path}",
            headers={"X-Auth": ACUNETIX_APIKEY, "Content-Type": "application/json"},
            verify=False,
            timeout=20,
            **kwargs
        )
    except Exception as e:
        log.error(f"[ACU] {method} {path} — {e}")
        return None


def acu_add_target(url: str) -> "str | None":
    r = _acu("POST", "/api/v1/targets", json={
        "address":     url,
        "description": "Auto-added by recon pipeline",
        "type":        "default",
        "criticality": 10
    })
    if r and r.status_code == 201:
        tid = r.json().get("target_id")
        log.info(f"[ACU] ✚ Target added : {url}  →  {tid}")
        track_target_added(url, tid)
        return tid
    log.warning(f"[ACU] Failed to add target {url}: {getattr(r, 'status_code', 'N/A')}")
    return None


def acu_trigger_scan(target_id: str, url: str) -> "str | None":
    r = _acu("POST", "/api/v1/scans", json={
        "profile_id":    SCAN_PROFILE_ID,
        "schedule":      {"disable": False, "start_date": None, "time_sensitive": False},
        "target_id":     target_id,

    })
    if r and r.status_code == 201:
        scan_id = r.headers.get("Location", "").rstrip("/").split("/")[-1]
        log.info(f"[ACU] ▶ Scan triggered: {url}  →  scan_id={scan_id}")
        track_scan_started(url, scan_id)
        return scan_id
    log.warning(f"[ACU] Failed to trigger scan for {url}: {getattr(r, 'status_code', 'N/A')}")
    return None


def acu_get_scan(scan_id: str) -> "dict | None":
    r = _acu("GET", f"/api/v1/scans/{scan_id}")
    return r.json() if (r and r.status_code == 200) else None


def acu_get_severity_counts(scan_id: str) -> dict:
    scan = acu_get_scan(scan_id)
    if not scan:
        return {}
    raw = scan.get("current_session", {}).get("severity_counts", {})
    result = {}
    for k, v in raw.items():
        key = "informational" if k.lower() in ("info", "informational") else k.lower()
        result[key] = int(v or 0)
    return result


def acu_delete_scan(scan_id: str, url: str) -> bool:
    r = _acu("DELETE", f"/api/v1/scans/{scan_id}")
    ok = r is not None and r.status_code in (200, 204)
    if ok:
        log.info(f"[ACU] 🗑  Scan   deleted: {scan_id}")
        track_deleted(url, "scan")
    else:
        log.warning(f"[ACU] Failed to delete scan {scan_id}: {getattr(r,'status_code','N/A')}")
    return ok


def acu_delete_target(target_id: str, url: str) -> bool:
    r = _acu("DELETE", f"/api/v1/targets/{target_id}")
    ok = r is not None and r.status_code in (200, 204)
    if ok:
        log.info(f"[ACU] 🗑  Target deleted: {target_id}")
        track_deleted(url, "target")
    else:
        log.warning(f"[ACU] Failed to delete target {target_id}: {getattr(r,'status_code','N/A')}")
    return ok


def has_significant_vulns(severity_counts: dict) -> bool:
    return any(severity_counts.get(s, 0) > 0 for s in KEEP_SEVERITIES)


# ──────────────────────────────────────────────
# WORKER 1 — QUEUE WORKER
# ──────────────────────────────────────────────
def queue_worker():
    log.info("[QUEUE] Worker started.")
    while True:
        item = subdomain_queue.get()
        url  = item["url"]
        log.info(f"[QUEUE] ► {url}  (from: {item['source']})")

        target_id = acu_add_target(url)
        if not target_id:
            track_failed(url, "target_add_failed")
            subdomain_queue.task_done()
            time.sleep(QUEUE_DELAY)
            continue

        time.sleep(1)
        scan_id = acu_trigger_scan(target_id, url)

        if scan_id:
            with active_scans_lock:
                active_scans[scan_id] = {
                    "target_id":  target_id,
                    "url":        url,
                    "started_at": _now()
                }
        else:
            # Scan trigger failed → delete orphan target, mark failed
            acu_delete_target(target_id, url)
            track_failed(url, "scan_trigger_failed")

        subdomain_queue.task_done()
        time.sleep(QUEUE_DELAY)


# ──────────────────────────────────────────────
# WORKER 2 — CLEANUP WORKER
# ──────────────────────────────────────────────
TERMINAL_STATUSES = {"completed", "failed", "aborted", "stopped"}


def cleanup_worker():
    log.info("[CLEAN] Cleanup worker started.")
    while True:
        time.sleep(CLEANUP_POLL_INTERVAL)

        with active_scans_lock:
            snapshot = dict(active_scans)

        if not snapshot:
            log.debug("[CLEAN] No in-flight scans.")
            continue

        log.info(f"[CLEAN] Polling {len(snapshot)} in-flight scan(s)...")

        for scan_id, meta in snapshot.items():
            scan_data = acu_get_scan(scan_id)
            if not scan_data:
                continue

            current_session = scan_data.get("current_session", {})
            raw_status = (
                current_session.get("status") or
                scan_data.get("current_session_status") or
                scan_data.get("status") or ""
            ).lower()

            if raw_status not in TERMINAL_STATUSES:
                log.debug(f"[CLEAN] {meta['url']} — running (status={raw_status})")
                continue

            # Scan is done
            with active_scans_lock:
                active_scans.pop(scan_id, None)

            url       = meta["url"]
            target_id = meta["target_id"]

            severity_counts = acu_get_severity_counts(scan_id)
            track_scan_finished(url, raw_status, severity_counts)

            summary = "  ".join(
                f"{k}={v}" for k, v in sorted(severity_counts.items()) if v
            ) or "no findings"

            if has_significant_vulns(severity_counts):
                log.info(f"[CLEAN] ✅ KEEP   {url}\n                  [{summary}]")
                track_decision(url, "kept")

            else:
                log.info(f"[CLEAN] 🗑  PRUNE  {url}\n                  [{summary}] — deleting")
                track_decision(url, "pruned")
                acu_delete_scan(scan_id, url)
                time.sleep(1)
                acu_delete_target(target_id, url)

            time.sleep(1)


# ──────────────────────────────────────────────
# ENTRYPOINT
# ──────────────────────────────────────────────
if __name__ == "__main__":
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Ensure tracking file exists on first run
    if not TRACKING_FILE.exists():
        with tracking_lock:
            d = json.loads(json.dumps(TRACKING_SCHEMA))
            d["meta"]["created_at"] = _now()
            _save_tracking(d)
        log.info(f"[TRACK] Initialized tracking file: {TRACKING_FILE}")

    threading.Thread(target=queue_worker,   daemon=True, name="queue-worker").start()
    threading.Thread(target=cleanup_worker, daemon=True, name="cleanup-worker").start()

    log.info(f"[SERVER] Starting on port {RECEIVER_PORT}  |  keep={KEEP_SEVERITIES}  |  poll={CLEANUP_POLL_INTERVAL}s")
    app.run(host="0.0.0.0", port=RECEIVER_PORT, debug=False)
