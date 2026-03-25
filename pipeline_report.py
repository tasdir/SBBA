#!/usr/bin/env python3
"""
pipeline_report.py — Query pipeline_tracking.json from the CLI

Usage:
  python3 pipeline_report.py                      # full summary
  python3 pipeline_report.py --status failed      # only failed targets
  python3 pipeline_report.py --status kept        # only kept (had vulns)
  python3 pipeline_report.py --status pruned      # only pruned (clean)
  python3 pipeline_report.py --status scanning    # currently scanning
  python3 pipeline_report.py --severity critical  # targets with critical vulns
  python3 pipeline_report.py --source recon-vps-01
  python3 pipeline_report.py --json               # dump raw JSON
  python3 pipeline_report.py --failed-only        # shortcut for failed targets
"""

import json
import argparse
import sys
from pathlib import Path
from datetime import datetime

TRACKING_FILE = Path("pipeline_tracking.json")

# ANSI colours
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

STATUS_COLOUR = {
    "queued":       YELLOW,
    "target_added": CYAN,
    "scanning":     CYAN,
    "kept":         GREEN,
    "pruned":       DIM,
    "failed":       RED,
}


def colour(text: str, code: str) -> str:
    return f"{code}{text}{RESET}"


def load() -> dict:
    if not TRACKING_FILE.exists():
        print(f"{RED}Tracking file not found: {TRACKING_FILE}{RESET}")
        sys.exit(1)
    with open(TRACKING_FILE) as f:
        return json.load(f)


def fmt_time(ts: str) -> str:
    if not ts:
        return "—"
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        return dt.strftime("%Y-%m-%d %H:%M:%S UTC")
    except Exception:
        return ts


def fmt_severity(counts: dict) -> str:
    if not counts:
        return colour("no findings", DIM)
    parts = []
    order = ["critical", "high", "medium", "low", "informational"]
    clr   = {"critical": RED, "high": RED, "medium": YELLOW,
              "low": DIM, "informational": DIM}
    for k in order:
        v = counts.get(k, 0)
        if v:
            parts.append(colour(f"{k[0].upper()}={v}", clr.get(k, RESET)))
    return "  ".join(parts) if parts else colour("no findings", DIM)


def print_summary(meta: dict):
    print(f"\n{BOLD}{'─'*55}{RESET}")
    print(f"{BOLD}  Pipeline Tracking Summary{RESET}")
    print(f"{'─'*55}")
    print(f"  Created      : {fmt_time(meta.get('created_at'))}")
    print(f"  Last updated : {fmt_time(meta.get('last_updated'))}")
    print(f"{'─'*55}")
    print(f"  Total queued  : {BOLD}{meta.get('total_queued',0)}{RESET}")
    print(f"  Total scanned : {BOLD}{meta.get('total_scanned',0)}{RESET}")
    print(f"  {GREEN}Kept          : {meta.get('total_kept',0)}{RESET}   (critical/high/medium found)")
    print(f"  {DIM}Pruned        : {meta.get('total_pruned',0)}{RESET}   (no significant findings)")
    print(f"  {RED}Failed        : {meta.get('total_failed',0)}{RESET}   (target/scan error)")
    print(f"{'─'*55}\n")


def print_targets(targets: list, title: str):
    if not targets:
        print(colour(f"  No targets match filter: {title}", DIM))
        return

    print(f"\n{BOLD}{title}  ({len(targets)} entries){RESET}")
    print("─" * 80)

    for t in targets:
        status = t.get("status", "unknown")
        sc     = STATUS_COLOUR.get(status, RESET)
        url    = t.get("url", "?")
        source = t.get("source", "?")

        print(f"\n  {BOLD}{url}{RESET}")
        print(f"    Status    : {colour(status.upper(), sc)}")
        print(f"    Source    : {source}")
        print(f"    Target ID : {t.get('target_id') or colour('—', DIM)}")
        print(f"    Scan ID   : {t.get('scan_id')   or colour('—', DIM)}")
        print(f"    Queued    : {fmt_time(t.get('queued_at'))}")
        print(f"    Scan start: {fmt_time(t.get('scan_started_at'))}")
        print(f"    Scan end  : {fmt_time(t.get('scan_finished_at'))}")
        print(f"    Scan stat : {t.get('scan_status') or colour('—', DIM)}")
        print(f"    Findings  : {fmt_severity(t.get('severity_counts', {}))}")

        if t.get("decision"):
            d_colour = GREEN if t["decision"] == "kept" else (RED if t["decision"] == "failed" else DIM)
            print(f"    Decision  : {colour(t['decision'].upper(), d_colour)}  @ {fmt_time(t.get('decision_at'))}")

        if t.get("failure_reason"):
            print(f"    Fail reason: {colour(t['failure_reason'], RED)}")

        deleted_parts = []
        if t.get("deleted_scan"):    deleted_parts.append("scan")
        if t.get("deleted_target"):  deleted_parts.append("target")
        if deleted_parts:
            print(f"    Deleted   : {colour(', '.join(deleted_parts), DIM)}")

    print()


def main():
    parser = argparse.ArgumentParser(description="Query pipeline_tracking.json")
    parser.add_argument("--file",        default=str(TRACKING_FILE), help="Path to tracking file")
    parser.add_argument("--status",      help="Filter by status: queued|target_added|scanning|kept|pruned|failed")
    parser.add_argument("--source",      help="Filter by source VPS name")
    parser.add_argument("--severity",    help="Filter: only targets with ≥1 of this severity (critical/high/medium/low)")
    parser.add_argument("--failed-only", action="store_true", help="Shortcut: show only failed targets")
    parser.add_argument("--json",        action="store_true", help="Dump full raw JSON")
    parser.add_argument("--summary",     action="store_true", help="Show summary only, no target list")
    args = parser.parse_args()

    global TRACKING_FILE
    TRACKING_FILE = Path(args.file)

    data = load()
    meta = data.get("meta", {})

    if args.json:
        print(json.dumps(data, indent=2))
        return

    print_summary(meta)

    if args.summary:
        return

    targets = list(data.get("targets", {}).values())

    # Apply filters
    if args.failed_only or args.status == "failed":
        targets = [t for t in targets if t.get("status") == "failed"]
        title = "❌ Failed Targets"
    elif args.status:
        targets = [t for t in targets if t.get("status") == args.status]
        title = f"Filter: status={args.status}"
    else:
        title = "All Targets"

    if args.source:
        targets = [t for t in targets if t.get("source") == args.source]
        title += f"  source={args.source}"

    if args.severity:
        sev = args.severity.lower()
        targets = [t for t in targets if t.get("severity_counts", {}).get(sev, 0) > 0]
        title += f"  severity≥1:{sev}"

    # Sort: failed first, then by status, then by queued time
    STATUS_ORDER = {"failed": 0, "scanning": 1, "queued": 2, "target_added": 3, "kept": 4, "pruned": 5}
    targets.sort(key=lambda t: (STATUS_ORDER.get(t.get("status",""), 99), t.get("queued_at", "")))

    print_targets(targets, title)


if __name__ == "__main__":
    main()
