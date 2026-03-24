#!/usr/bin/env python3
# Tool:   SBBAv2 Simple Bug Bounty Automation 
#
# I built this to stop doing the same recon steps manually every time I start
# a new target. It chains together all the tools I use on a daily basis and
# dumps everything into a clean folder with a ready-to-edit report at the end.
#
# Use it only on targets you have permission to test.

import argparse
import subprocess
import sys
import os
import json
import datetime
import signal
import shutil
import threading
import time
import requests
from pathlib import Path

# ─── ANSI Colors ───────────────────────────────────────────────────────────────
R  = "\033[91m"   # Red
G  = "\033[92m"   # Green
Y  = "\033[93m"   # Yellow
B  = "\033[94m"   # Blue
M  = "\033[95m"   # Magenta
C  = "\033[96m"   # Cyan
W  = "\033[97m"   # White
RST= "\033[0m"
BOLD="\033[1m"

def banner():
    print(f"""{C}{BOLD}

   ░██████   ░████████   ░████████      ░███                ░██████  
 ░██   ░██  ░██    ░██  ░██    ░██    ░██░██              ░██   ░██ 
░██         ░██    ░██  ░██    ░██   ░██  ░██  ░██    ░██       ░██ 
 ░████████  ░████████   ░████████   ░█████████ ░██    ░██   ░█████  
        ░██ ░██     ░██ ░██     ░██ ░██    ░██  ░██  ░██   ░██      
 ░██   ░██  ░██     ░██ ░██     ░██ ░██    ░██   ░██░██   ░██       
  ░██████   ░█████████  ░█████████  ░██    ░██    ░███    ░████████ 
                                                                    
{RST}
{M}{'─'*70}{RST}
{W}   🎯  Simple Bug Bounty Automation {Y}v1.0{RST}
{W}   👤  Author : {G}Tasdir Ahmmed{RST}
{W}   🔧  Phases : {C}Recon → Crawl → Vuln Scan → (Nuclei + XSS + Takeover) → Report{RST}
{M}{'─'*70}{RST}
""")

# ─── Background Mode Detection ────────────────────────────────────────────────
_bg_mode = threading.local()

def _is_background():
    return getattr(_bg_mode, 'active', False)

def _log_prefix():
    if _is_background():
        name = getattr(_bg_mode, 'name', '?')
        return f"{M}[BG:{name}]{RST} "
    return ""

def info(msg):  print(f"{_log_prefix()}{B}[*]{RST} {msg}")
def ok(msg):    print(f"{_log_prefix()}{G}[+]{RST} {msg}")
def warn(msg):  print(f"{_log_prefix()}{Y}[!]{RST} {msg}")
def err(msg):   print(f"{_log_prefix()}{R}[-]{RST} {msg}")
def phase(n, title):
    pfx = _log_prefix()
    print(f"\n{pfx}{C}{BOLD}{'─'*60}{RST}\n{pfx}{M}{BOLD}  Phase {n} — {title}{RST}\n{pfx}{C}{BOLD}{'─'*60}{RST}")

# ─── Task Registry ────────────────────────────────────────────────────────────
_bg_registry = {}
_fg_current = {"name": None, "proc": None, "start": 0}
_bg_lock = threading.Lock()

# ─── Helpers ───────────────────────────────────────────────────────────────────

def tool_exists(name):
    return shutil.which(name) is not None

def _kill_proc(proc):
    """Cross-platform process tree kill: SIGTERM/SIGKILL on Linux, TerminateProcess on Windows."""
    if sys.platform != "win32":
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except (OSError, ProcessLookupError):
            pass
    else:
        try:
            proc.terminate()
        except OSError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if sys.platform != "win32":
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            except (OSError, ProcessLookupError):
                pass
        else:
            try:
                proc.kill()
            except OSError:
                pass

def run(cmd, output_file=None, shell=True, tool_name=None):
    """
    Streams stdout/stderr in real-time via Popen.
    Foreground: Ctrl+C opens interactive kill menu.
    Background: runs silently, proc registered for remote kill.
    """
    is_bg = _is_background()

    info(f"Running: {Y}{cmd}{RST}")
    if tool_name and not is_bg:
        info(f"{C}{tool_name}{RST} | {W}Ctrl+C to manage tasks{RST}")

    popen_kwargs = {
        "shell": shell,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True

    try:
        proc = subprocess.Popen(cmd, **popen_kwargs)
    except Exception as e:
        err(f"Failed to start: {e}")
        return ""

    if is_bg:
        bg_name = getattr(_bg_mode, 'name', '')
        with _bg_lock:
            if bg_name in _bg_registry:
                _bg_registry[bg_name]["proc"] = proc
    else:
        _fg_current["name"] = tool_name
        _fg_current["proc"] = proc
        _fg_current["start"] = time.time()

    stdout_lines = []

    def _read_stream(stream, collector=None, is_stderr=False):
        for line in iter(stream.readline, ""):
            if collector is not None:
                collector.append(line)
            if not is_bg:
                stripped = line.rstrip()
                if stripped:
                    if is_stderr:
                        print(f"  {Y}{stripped}{RST}")
                    else:
                        print(f"  {stripped}")
        stream.close()

    t_out = threading.Thread(target=_read_stream, args=(proc.stdout, stdout_lines, False), daemon=True)
    t_err = threading.Thread(target=_read_stream, args=(proc.stderr, None, True), daemon=True)
    t_out.start()
    t_err.start()

    killed = False
    start = time.time()

    if is_bg:
        proc.wait()
    else:
        while True:
            try:
                proc.wait()
                break
            except KeyboardInterrupt:
                action, target_name = _show_kill_menu()
                if action == "cancel":
                    if proc.poll() is not None:
                        break
                    continue
                elif action == "kill_one" and target_name == tool_name:
                    _kill_proc(proc)
                    killed = True
                    break
                elif action == "kill_one":
                    _kill_bg_task(target_name)
                    if proc.poll() is not None:
                        break
                    continue
                elif action == "kill_all":
                    _kill_proc(proc)
                    _kill_all_bg()
                    killed = True
                    break
                elif action == "abort":
                    _kill_proc(proc)
                    _kill_all_bg()
                    killed = True
                    raise

    if not is_bg:
        _fg_current["name"] = None
        _fg_current["proc"] = None

    t_out.join(timeout=2)
    t_err.join(timeout=2)

    elapsed = time.time() - start
    rc = proc.returncode
    if rc and rc != 0 and not killed:
        warn(f"{tool_name or 'Command'} exited with code {rc}")
    ok(f"Done in {elapsed:.1f}s")

    stdout_text = "".join(stdout_lines).strip()
    if stdout_text and output_file:
        Path(output_file).write_text(stdout_text + "\n")
    return stdout_text

def dedupe_file(path):
    """Sort and remove duplicate lines — saves you from nuclei or subfinder spitting out the same host 10 times."""
    p = Path(path)
    if not p.exists():
        return
    lines = sorted(set(p.read_text().splitlines()))
    p.write_text("\n".join(l for l in lines if l) + "\n")
    return len(lines)

def count_lines(path):
    p = Path(path)
    if not p.exists():
        return 0
    return len([l for l in p.read_text().splitlines() if l])

def send_telegram(token, chat_id, message):
    try:
        url = f"https://api.telegram.org/bot{token}/sendMessage"
        requests.post(url, data={"chat_id": chat_id, "text": message, "parse_mode": "Markdown"}, timeout=10)
    except Exception as e:
        warn(f"Telegram failed: {e}")

# ─── Kill Menu & Background Task Management ──────────────────────────────────

def _show_kill_menu():
    """Interactive menu shown on Ctrl+C — pick which task to kill."""
    tasks = []
    if _fg_current["name"] and _fg_current["proc"] and _fg_current["proc"].poll() is None:
        elapsed = time.time() - _fg_current["start"]
        tasks.append(("FG", _fg_current["name"], elapsed))
    with _bg_lock:
        for name, entry in _bg_registry.items():
            if not entry["done"] and entry["proc"] and entry["proc"].poll() is None:
                elapsed = time.time() - entry["start"]
                tasks.append(("BG", name, elapsed))

    if not tasks:
        print(f"\n{Y}  No running tasks.{RST}")
        return "cancel", None

    print(f"\n{Y}{'─'*50}{RST}")
    print(f"{W}  Running tasks:{RST}")
    for i, (kind, name, elapsed) in enumerate(tasks, 1):
        mins, secs = divmod(int(elapsed), 60)
        print(f"    [{W}{i}{RST}] {C}{name:20s}{RST} ({kind}, {mins}m {secs:02d}s)")
    print(f"    [{W}A{RST}] Kill ALL tasks")
    print(f"    [{W}C{RST}] Cancel — resume waiting")
    print(f"{Y}{'─'*50}{RST}")

    try:
        choice = input(f"  {Y}Kill which? > {RST}").strip().upper()
    except (EOFError, KeyboardInterrupt):
        return "abort", None

    if choice == "C" or choice == "":
        return "cancel", None
    elif choice == "A":
        return "kill_all", None
    elif choice.isdigit():
        idx = int(choice) - 1
        if 0 <= idx < len(tasks):
            return "kill_one", tasks[idx][1]

    return "cancel", None


def _kill_bg_task(name):
    """Kill a specific background task by name."""
    with _bg_lock:
        entry = _bg_registry.get(name)
        if not entry or entry["done"]:
            return
        if entry["proc"] and entry["proc"].poll() is None:
            _kill_proc(entry["proc"])
        entry["done"] = True
        entry["status"] = "killed"
    warn(f"Killed background task: {name}")


def _kill_all_bg():
    """Kill every running background task."""
    with _bg_lock:
        for name, entry in _bg_registry.items():
            if not entry["done"] and entry["proc"] and entry["proc"].poll() is None:
                _kill_proc(entry["proc"])
                entry["done"] = True
                entry["status"] = "killed"
    warn("Killed all background tasks")


def run_background(task_name, phase_func, *args):
    """Launch a phase function in a background thread."""
    def _wrapper():
        _bg_mode.active = True
        _bg_mode.name = task_name
        start_t = time.time()
        with _bg_lock:
            _bg_registry[task_name] = {
                "thread": threading.current_thread(),
                "proc": None,
                "start": start_t,
                "done": False,
                "status": "running",
            }
        try:
            phase_func(*args)
            with _bg_lock:
                if _bg_registry[task_name]["status"] != "killed":
                    _bg_registry[task_name]["status"] = "completed"
        except Exception as e:
            with _bg_lock:
                if _bg_registry[task_name]["status"] != "killed":
                    _bg_registry[task_name]["status"] = "failed"
            err(f"failed: {e}")
        finally:
            elapsed = time.time() - start_t
            mins, secs = divmod(int(elapsed), 60)
            with _bg_lock:
                _bg_registry[task_name]["done"] = True
                status = _bg_registry[task_name]["status"]
            if status == "completed":
                ok(f"[BG] {task_name} complete ({mins}m {secs:02d}s)")

    t = threading.Thread(target=_wrapper, name=task_name, daemon=True)
    t.start()
    return t


def wait_all_bg():
    """Block until all background tasks finish. Ctrl+C opens kill menu."""
    pending = [n for n, e in _bg_registry.items() if not e["done"]]
    if not pending:
        return
    info(f"Waiting for {len(pending)} background task(s): {C}{', '.join(pending)}{RST}")
    for name in list(pending):
        entry = _bg_registry[name]
        while entry["thread"].is_alive():
            try:
                entry["thread"].join(timeout=0.5)
            except KeyboardInterrupt:
                action, target_name = _show_kill_menu()
                if action == "kill_one":
                    _kill_bg_task(target_name)
                elif action == "kill_all":
                    _kill_all_bg()
                    return
                elif action == "abort":
                    _kill_all_bg()
                    raise

    completed = [n for n, e in _bg_registry.items() if e["status"] == "completed"]
    killed_list = [n for n, e in _bg_registry.items() if e["status"] == "killed"]
    failed_list = [n for n, e in _bg_registry.items() if e["status"] == "failed"]
    if completed:
        ok(f"Background completed: {C}{', '.join(completed)}{RST}")
    if killed_list:
        warn(f"Background killed: {', '.join(killed_list)}")
    if failed_list:
        err(f"Background failed: {', '.join(failed_list)}")

# ─── Phases ────────────────────────────────────────────────────────────────────

def phase1_subdomains(target, out_dir):
    phase(1, "Subdomain Enumeration")
    sub_file = out_dir / "subdomains.txt"
    tmp_files = []

    for tool, cmd in [
        ("subfinder",   f"subfinder -d {target} -silent -o {out_dir}/sub_subfinder.txt"),
        ("assetfinder", f"assetfinder --subs-only {target} > {out_dir}/sub_assetfinder.txt"),
        ("amass",       f"amass enum -passive -d {target} -o {out_dir}/sub_amass.txt"),
    ]:
        if tool_exists(tool):
            run(cmd, tool_name=tool)
            tmp_files.append(out_dir / f"sub_{tool}.txt")
        else:
            warn(f"{tool} not found — skipping (install: go install github.com/projectdiscovery/{tool}/v2/cmd/{tool}@latest)")

    # merge all three tool outputs and drop duplicates before saving
    all_subs = set()
    for f in tmp_files:
        p = Path(f)
        if p.exists():
            all_subs.update(l.strip() for l in p.read_text().splitlines() if l.strip())
    sub_file.write_text("\n".join(sorted(all_subs)) + "\n")
    n = count_lines(sub_file)
    ok(f"Found {n} unique subdomains → {sub_file}")
    return sub_file


def phase2_live_hosts(out_dir, sub_file):
    phase(2, "Live Host Detection")
    live_file = out_dir / "live.txt"
    if not tool_exists("httpx"):
        err("httpx not found. Install: go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        return live_file
    run(f"httpx -l {sub_file} -silent -threads 50 -o {live_file}", tool_name="httpx")
    ok(f"{count_lines(live_file)} live hosts → {live_file}")

    if tool_exists("gowitness"):
        info("Taking screenshots with gowitness...")
        sc_dir = out_dir / "screenshots"
        sc_dir.mkdir(exist_ok=True)
        run(f"gowitness file -f {live_file} -P {sc_dir} --no-http", tool_name="gowitness")
        ok(f"Screenshots saved to {sc_dir}")
    else:
        warn("gowitness not found — skipping screenshots")
    return live_file


def phase3_port_scan(out_dir, live_file):
    phase(3, "Port Scanning")
    ports_file = out_dir / "ports.txt"
    if not tool_exists("nmap"):
        err("nmap not found. Install: sudo apt install nmap")
        return
    hosts = [l.strip() for l in Path(live_file).read_text().splitlines() if l.strip()]
    # nmap doesn't want http:// prefixes, strip them out
    clean = [h.replace("https://","").replace("http://","").split("/")[0] for h in hosts]
    # cap at 50 hosts — scanning more than that at once gets messy
    tmp = out_dir / "_nmap_hosts.txt"
    tmp.write_text("\n".join(clean) + "\n")
    run(f"nmap -T4 -p 1-65535 --open -iL {tmp} -oN {ports_file}", tool_name="nmap")
    ok(f"Port scan results → {ports_file}")
    # Flag unusual ports
    unusual = run(f"grep 'open' {ports_file} | grep -vE '(80|443|8080|8443)/tcp'", tool_name="grep")
    if unusual:
        warn(f"Unusual open ports found:\n{unusual}")


def phase4_crawl_urls(target, out_dir, live_file):
    phase(4, "Crawling & URL Collection")
    urls_file  = out_dir / "urls.txt"
    params_file= out_dir / "params.txt"
    all_urls   = set()

    for tool, cmd in [
        ("katana",       f"katana -list {live_file} -silent -jc -d 3 -o {out_dir}/urls_katana.txt"),
        ("gau",          f"gau {target} --o {out_dir}/urls_gau.txt"),
        ("waybackurls",  f"echo {target} | waybackurls > {out_dir}/urls_wayback.txt"),
    ]:
        if tool_exists(tool):
            run(cmd, tool_name=tool)
        else:
            warn(f"{tool} not found — skipping")

    for fname in ["urls_katana.txt","urls_gau.txt","urls_wayback.txt"]:
        fp = out_dir / fname
        if fp.exists():
            all_urls.update(l.strip() for l in fp.read_text().splitlines() if l.strip())

    urls_file.write_text("\n".join(sorted(all_urls)) + "\n")
    ok(f"{len(all_urls)} total URLs → {urls_file}")

    # anything with a "?" is worth keeping for XSS testing
    params = [u for u in all_urls if "?" in u]
    params_file.write_text("\n".join(sorted(params)) + "\n")
    ok(f"{len(params)} parameter URLs → {params_file}")
    return urls_file, params_file


def phase5_google_dorks(target):
    phase(5, "Google Dorking Suggestions")
    dorks = [
        f'site:{target} ext:env OR ext:config OR ext:yml OR ext:yaml',
        f'site:{target} inurl:admin OR inurl:administrator OR inurl:dashboard',
        f'site:{target} inurl:login OR inurl:signin OR inurl:auth',
        f'site:{target} intext:"api_key" OR intext:"access_token" OR intext:"secret"',
        f'site:{target} filetype:sql OR filetype:db OR filetype:bak',
        f'site:{target} inurl:".git" OR inurl:".svn" OR inurl:".DS_Store"',
        f'site:{target} inurl:phpinfo OR inurl:test.php OR inurl:info.php',
        f'site:{target} intitle:"index of" OR intitle:"directory listing"',
        f'site:{target} inurl:wp-content OR inurl:wp-admin',
        f'site:{target} intext:"mysql_connect" OR intext:"mysqli" OR intext:"pg_connect"',
    ]
    print(f"\n{Y}Google Dorks for {target}:{RST}")
    for i, d in enumerate(dorks, 1):
        print(f"  {i:2}. {d}")
    return dorks


def phase6_vuln_scan(out_dir, live_file):
    phase(6, "Vulnerability Scanning (Nuclei)")
    vulns_file = out_dir / "vulns.txt"
    if not tool_exists("nuclei"):
        err("nuclei not found. Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        return
    run(f"nuclei -l {live_file} -severity critical,high,medium,low -rl 50 -o {vulns_file} -silent", tool_name="nuclei")
    n = count_lines(vulns_file)
    if n:
        ok(f"{n} findings → {vulns_file}")
    else:
        info("No nuclei findings.")


def phase7_xss(out_dir, params_file):
    phase(7, "XSS Testing (dalfox)")
    xss_file = out_dir / "xss.txt"
    if not tool_exists("dalfox"):
        err("dalfox not found. Install: go install github.com/hahwul/dalfox/v2@latest")
        return
    if count_lines(params_file) == 0:
        info("No parameter URLs to test for XSS.")
        return
    run(f"dalfox file {params_file} --silence --follow-redirects --timeout 13 --no-spinner -o {xss_file}", tool_name="dalfox")
    n = count_lines(xss_file)
    if n:
        ok(f"{n} XSS findings → {xss_file}")
    else:
        info("No XSS confirmed.")


def phase8_takeover(out_dir, sub_file):
    phase(8, "Subdomain Takeover Check")
    takeover_file = out_dir / "takeovers.txt"
    if not tool_exists("nuclei"):
        err("nuclei not found — skipping takeover check")
        return
    run(f"nuclei -l {sub_file} -t takeovers/ -o {takeover_file} -silent", tool_name="nuclei")
    n = count_lines(takeover_file)
    if n:
        ok(f"{n} potential takeovers → {takeover_file}")
    else:
        info("No takeover candidates found.")


def phase9_report(target, out_dir, date_str):
    phase(9, "Report Generation")
    report_file = out_dir / "report.md"

    def read_safe(path, max_lines=50):
        p = Path(path)
        if not p.exists() or p.stat().st_size == 0:
            return "_No results_"
        lines = [l for l in p.read_text().splitlines() if l.strip()]
        snippet = "\n".join(lines[:max_lines])
        if len(lines) > max_lines:
            snippet += f"\n... ({len(lines) - max_lines} more lines)"
        return snippet

    vulns_raw     = read_safe(out_dir / "vulns.txt")
    xss_raw       = read_safe(out_dir / "xss.txt")
    takeover_raw  = read_safe(out_dir / "takeovers.txt")
    subs_count    = count_lines(out_dir / "subdomains.txt")
    live_count    = count_lines(out_dir / "live.txt")
    url_count     = count_lines(out_dir / "urls.txt")
    param_count   = count_lines(out_dir / "params.txt")

    report = f"""# Bug Bounty Report — {target}
**Date:** {date_str}
**Tester:** Omair Temurian

---

## 📊 Recon Summary

| Metric | Count |
|--------|-------|
| Subdomains discovered | {subs_count} |
| Live hosts | {live_count} |
| URLs collected | {url_count} |
| Parameter URLs | {param_count} |

---

## 🔍 Vulnerability Findings (Nuclei)

```
{vulns_raw}
```

---

## 🕷️ XSS Findings (dalfox)

```
{xss_raw}
```

---

## 🔗 Subdomain Takeover Candidates

```
{takeover_raw}
```

---

## 📁 Output Files

| File | Description |
|------|-------------|
| `subdomains.txt` | All discovered subdomains |
| `live.txt` | Live HTTP/HTTPS hosts |
| `ports.txt` | Nmap port scan results |
| `urls.txt` | All crawled URLs |
| `params.txt` | URLs with parameters |
| `vulns.txt` | Nuclei vulnerability findings |
| `xss.txt` | Confirmed XSS via dalfox |

| `takeovers.txt` | Subdomain takeover candidates |
| `screenshots/` | Visual screenshots of live hosts |

---

## ⚠️ Disclaimer

This report was generated as part of an authorized bug bounty assessment.
All testing was performed with explicit permission on in-scope targets only.

---
*Generated by bugbounty.py on {date_str}*
"""
    report_file.write_text(report)
    ok(f"Report saved → {report_file}")
    print(f"\n{G}{BOLD}{'='*60}\n  ✅ Pipeline complete! All results in: {out_dir}\n{'='*60}{RST}")


# ─── Main ──────────────────────────────────────────────────────────────────────

def main():
    banner()
    parser = argparse.ArgumentParser(
        description="Bug Bounty Automation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 bugbounty.py scan target.com
  python3 bugbounty.py recon target.com
  python3 bugbounty.py vuln target.com
  python3 bugbounty.py report target.com --out-dir results_target.com_2026-03-22
  python3 bugbounty.py scan target.com --telegram --tg-token TOKEN --tg-chat CHATID
        """
    )
    parser.add_argument("mode",   choices=["scan","recon","vuln","report"], help="Pipeline mode")
    parser.add_argument("target", help="Target domain (e.g. example.com)")
    parser.add_argument("--out-dir",  help="Override output directory path")
    parser.add_argument("--telegram", action="store_true", help="Send findings to Telegram")
    parser.add_argument("--tg-token", help="Telegram bot token")
    parser.add_argument("--tg-chat",  help="Telegram chat ID")
    parser.add_argument("--skip-confirm", action="store_true", help="Skip scope confirmation prompt")
    args = parser.parse_args()

    target   = args.target.lower().strip()
    date_str = datetime.date.today().isoformat()

    # ── Scope confirmation ──
    if not args.skip_confirm:
        print(f"\n{Y}{BOLD}⚠️  SCOPE CONFIRMATION{RST}")
        print(f"  Target : {W}{target}{RST}")
        print(f"  Mode   : {W}{args.mode}{RST}")
        print(f"\n{R}You must have explicit written permission to test this target.{RST}")
        ans = input(f"\n{Y}Confirm {target} is in-scope and you have permission? [yes/NO]: {RST}").strip().lower()
        if ans != "yes":
            err("Aborted. Only test targets you are authorized to test.")
            sys.exit(1)

    # ── Output directory ──
    out_dir = Path(args.out_dir) if args.out_dir else Path(f"results_{target.replace('.','_')}_{date_str}")
    out_dir.mkdir(parents=True, exist_ok=True)
    ok(f"Output directory: {out_dir.resolve()}")
    info(f"Tip: Press {W}Ctrl+C{RST} during any tool to open the task manager (skip/kill tasks)")

    sub_file   = out_dir / "subdomains.txt"
    live_file  = out_dir / "live.txt"
    urls_file  = out_dir / "urls.txt"
    params_file= out_dir / "params.txt"

    tg = lambda msg: send_telegram(args.tg_token, args.tg_chat, msg) if args.telegram else None

    # ── Run phases based on mode ──
    # Independent phases fire as background threads; the critical dependency
    # chain (subdomains → live hosts → crawl → XSS) stays in the foreground.
    try:
        if args.mode in ("scan", "recon"):
            sub_file = phase1_subdomains(target, out_dir)

            run_background("dorks", phase5_google_dorks, target)
            live_file = phase2_live_hosts(out_dir, sub_file)

            run_background("port_scan", phase3_port_scan, out_dir, live_file)
            urls_file, params_file = phase4_crawl_urls(target, out_dir, live_file)

            tg(f"🎯 Recon done for `{target}`\nSubdomains: {count_lines(sub_file)} | Live: {count_lines(live_file)}")

        if args.mode in ("scan", "vuln"):
            if not live_file.exists():
                err(f"{live_file} not found. Run recon first.")
                sys.exit(1)
            run_background("nuclei", phase6_vuln_scan, out_dir, live_file)
            run_background("takeover", phase8_takeover, out_dir, sub_file)
            phase7_xss(out_dir, params_file)
            tg(f"🔍 Vuln scan done for `{target}`")

        wait_all_bg()

        if args.mode in ("scan", "report"):
            phase9_report(target, out_dir, date_str)
            tg(f"📄 Report ready for `{target}` at `{out_dir}/report.md`")

    except KeyboardInterrupt:
        _kill_all_bg()
        warn("\nInterrupted by user. Partial results saved.")
        sys.exit(0)


if __name__ == "__main__":
    main()
