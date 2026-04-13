import json
import sys
import argparse
import requests
import logging
import time
from datetime import datetime
from pathlib import Path

# ──────────────────────────────────────────────
# CONFIG (edit these or pass as CLI args)
# ──────────────────────────────────────────────
RECEIVER_URL    = "http://10.0.3.95:8888/submit" #change this to your own acunetix receiver url
RECEIVER_SECRET = "changeme_secret_token"   # Must match server-side secret
BATCH_SIZE      = 50                         # Send in chunks of N subdomains
MAX_RETRIES     = 5
RETRY_BACKOFF   = 2                          # Base seconds for exponential backoff

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def send_batch(subdomains: list, source: str, receiver_url: str, secret: str) -> bool:
    """Send a batch with exponential-backoff retries. Returns True only on 202."""
    payload = {"source": source, "subdomains": subdomains}
    headers = {
        "Authorization": f"Bearer {secret}",
        "Content-Type": "application/json"
    }
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.post(receiver_url, headers=headers, json=payload, timeout=30)
            if r.status_code == 202:
                data = r.json()
                log.info(f"[SEND] Batch accepted — queued={data.get('queued')} | server_queue={data.get('queue_size')}")
                return True
            if r.status_code < 500:
                log.error(f"[SEND] Server rejected batch (non-retryable): {r.status_code} {r.text[:200]}")
                return False
            log.warning(f"[SEND] Server error {r.status_code}, attempt {attempt}/{MAX_RETRIES}")
        except requests.exceptions.ConnectionError as e:
            log.warning(f"[SEND] Connection error (attempt {attempt}/{MAX_RETRIES}): {e}")
        except requests.exceptions.Timeout:
            log.warning(f"[SEND] Timeout (attempt {attempt}/{MAX_RETRIES})")
        except Exception as e:
            log.error(f"[SEND] Unexpected error: {e}")
            return False

        if attempt < MAX_RETRIES:
            delay = RETRY_BACKOFF * (2 ** (attempt - 1))
            log.info(f"[SEND] Retrying in {delay}s ...")
            time.sleep(delay)

    log.error(f"[SEND] Batch FAILED after {MAX_RETRIES} attempts ({len(subdomains)} domains)")
    return False


def chunked(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def save_failed(failed_domains: list, source: str):
    """Persist failed domains to a timestamped file for later retry."""
    if not failed_domains:
        return
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    path = Path(f"failed_subdomains_{source}_{ts}.txt")
    path.write_text("\n".join(failed_domains) + "\n", encoding="utf-8")
    log.error(f"[SEND] {len(failed_domains)} failed domains saved to {path}  — retry with: python senderacunetix.py -f {path}")


def main():
    parser = argparse.ArgumentParser(description="Send subdomains to Acunetix pipeline receiver")
    parser.add_argument("--source",   default="SBBAv2",      help="Identifier for this recon VPS")
    parser.add_argument("--receiver", default=RECEIVER_URL,     help="Receiver URL")
    parser.add_argument("--secret",   default=RECEIVER_SECRET,  help="Bearer token")
    parser.add_argument("--batch",    default=BATCH_SIZE, type=int, help="Batch size")
    parser.add_argument("--retries",  default=MAX_RETRIES, type=int, help="Max retries per batch")

    group = parser.add_mutually_exclusive_group()
    group.add_argument("-f", "--file",    help="File with one subdomain per line")
    group.add_argument("-d", "--domains", nargs="+", help="Inline list of subdomains")

    args = parser.parse_args()

    # Collect subdomains
    if args.file:
        with open(args.file, "r") as f:
            subdomains = [line.strip() for line in f if line.strip()]
    elif args.domains:
        subdomains = args.domains
    elif not sys.stdin.isatty():
        subdomains = [line.strip() for line in sys.stdin if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    global MAX_RETRIES
    MAX_RETRIES = args.retries

    log.info(f"[SENDER] {len(subdomains)} subdomains loaded from source '{args.source}'")

    total_sent = 0
    failed_domains = []

    for batch in chunked(subdomains, args.batch):
        ok = send_batch(batch, args.source, args.receiver, args.secret)
        if ok:
            total_sent += len(batch)
        else:
            failed_domains.extend(batch)

    log.info(f"[SENDER] Done. Sent {total_sent}/{len(subdomains)} subdomains.")

    if failed_domains:
        log.error(f"[SENDER] {len(failed_domains)} domains FAILED to send!")
        save_failed(failed_domains, args.source)
    else:
        log.info("[SENDER] All domains sent successfully.")


if __name__ == "__main__":
    main()
