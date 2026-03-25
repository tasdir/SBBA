import json
import argparse
import requests
import logging

# ──────────────────────────────────────────────
# CONFIG (edit these or pass as CLI args)
# ──────────────────────────────────────────────
RECEIVER_URL    = "http://10.0.3.95:8888/submit"
RECEIVER_SECRET = "changeme_secret_token"   # Must match server-side secret
BATCH_SIZE      = 50                         # Send in chunks of N subdomains

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
log = logging.getLogger(__name__)


def send_batch(subdomains: list, source: str, receiver_url: str, secret: str) -> bool:
    payload = {"source": source, "subdomains": subdomains}
    headers = {
        "Authorization": f"Bearer {secret}",
        "Content-Type": "application/json"
    }
    try:
        r = requests.post(receiver_url, headers=headers, json=payload, timeout=30)
        if r.status_code == 202:
            data = r.json()
            log.info(f"[SEND] Batch accepted — queued={data.get('queued')} | server_queue={data.get('queue_size')}")
            return True
        else:
            log.error(f"[SEND] Server rejected batch: {r.status_code} {r.text[:200]}")
            return False
    except Exception as e:
        log.error(f"[SEND] Connection error: {e}")
        return False


def chunked(lst, n):
    for i in range(0, len(lst), n):
        yield lst[i:i + n]


def main():
    parser = argparse.ArgumentParser(description="Send subdomains to Acunetix pipeline receiver")
    parser.add_argument("--source",   default="SBBAv2",      help="Identifier for this recon VPS")
    parser.add_argument("--receiver", default=RECEIVER_URL,     help="Receiver URL")
    parser.add_argument("--secret",   default=RECEIVER_SECRET,  help="Bearer token")
    parser.add_argument("--batch",    default=BATCH_SIZE, type=int, help="Batch size")

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
        # Pipe / stdin mode
        subdomains = [line.strip() for line in sys.stdin if line.strip()]
    else:
        parser.print_help()
        sys.exit(1)

    log.info(f"[SENDER] {len(subdomains)} subdomains loaded from source '{args.source}'")

    total_sent = 0
    for batch in chunked(subdomains, args.batch):
        ok = send_batch(batch, args.source, args.receiver, args.secret)
        if ok:
            total_sent += len(batch)

    log.info(f"[SENDER] Done. Sent {total_sent}/{len(subdomains)} subdomains.")


if __name__ == "__main__":
    main()
