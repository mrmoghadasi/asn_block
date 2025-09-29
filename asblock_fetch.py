#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, os, sys, json, re, time, random, datetime as dt
import logging
from logging.handlers import RotatingFileHandler
import tempfile

try:
    import yaml, requests
except Exception:
    print("Install deps first: `apt-get install python3-yaml python3-requests` or `pip install pyyaml requests`", file=sys.stderr)
    sys.exit(2)

CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")
DEF_LOG = "/var/log/as-blocklist.log"
DEF_OUT = "/etc/as-blocklist/blocklist"
UA = "asblock-fetch/1.2 (+https://greenplus.cloud)"

def setup_logger(path, verbose=False):
    logger = logging.getLogger("asblock_fetch")
    logger.setLevel(logging.DEBUG)
    for h in list(logger.handlers):
        logger.removeHandler(h)
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(logging.DEBUG if verbose else logging.INFO)
    ch.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    logger.addHandler(ch)
    if path:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fh = RotatingFileHandler(path, maxBytes=5*1024*1024, backupCount=5)
        fh.setLevel(logging.DEBUG)
        fh.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(fh)
    return logger

def ts():
    return dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def atomic_write(text, dst_path, logger, dry=False):
    os.makedirs(os.path.dirname(dst_path), exist_ok=True)
    if dry:
        logger.info(f"[dry-run] would write {len(text.splitlines())} lines -> {dst_path}")
        return
    with tempfile.NamedTemporaryFile("w", delete=False, dir=os.path.dirname(dst_path)) as tmpf:
        tmpf.write(text); tmpname = tmpf.name
    os.replace(tmpname, dst_path)
    logger.info(f"Wrote {dst_path} ({len(text.splitlines())} lines)")

def parse_retry_after(resp) -> float:
    ra = resp.headers.get("Retry-After")
    if not ra: return 0.0
    try: return float(ra)
    except ValueError: return 0.0

def http_get_with_retries(session, url, timeout, logger, max_retries, backoff_initial, backoff_max):
    attempt = 0
    while True:
        attempt += 1
        try:
            resp = session.get(url, timeout=timeout)
            if resp.status_code == 429 or 500 <= resp.status_code < 600:
                wait_hdr = parse_retry_after(resp)
                if attempt <= max_retries:
                    backoff = min(backoff_max, backoff_initial * (2 ** (attempt - 1)))
                    wait = max(wait_hdr, backoff) + (random.random() * 0.5)
                    logger.warning(f"HTTP {resp.status_code} from {url} (attempt {attempt}/{max_retries}); sleeping {wait:.2f}s")
                    time.sleep(wait); continue
                else:
                    resp.raise_for_status()
            resp.raise_for_status()
            return resp
        except requests.RequestException as e:
            if attempt <= max_retries:
                backoff = min(backoff_max, backoff_initial * (2 ** (attempt - 1)))
                wait = backoff + (random.random() * 0.5)
                logger.warning(f"HTTP error {e} (attempt {attempt}/{max_retries}); sleeping {wait:.2f}s")
                time.sleep(wait); continue
            raise

def fetch_as_prefixes(asn, endpoint, timeout, logger, max_retries, backoff_initial, backoff_max, session):
    url = endpoint.format(asn=asn)
    logger.info(f"Fetching prefixes for AS{asn} from {url}")
    resp = http_get_with_retries(session, url, timeout, logger, max_retries, backoff_initial, backoff_max)
    data = resp.json()
    v4 = [p.get("prefix","") for p in data.get("data",{}).get("ipv4_prefixes",[])]
    v4 = [p for p in v4 if CIDR_RE.match(p)]
    logger.info(f"AS{asn}: {len(v4)} IPv4 CIDRs received")
    return v4

def prune_orphan_files_if_enabled(out_dir, valid_asns, enabled, logger, dry=False):
    if not enabled:
        logger.debug("Prune orphan files disabled.")
        return
    if not os.path.isdir(out_dir):
        return
    for name in os.listdir(out_dir):
        if not name.endswith(".cidr"): continue
        asn = name[:-5]  # strip .cidr
        if asn not in valid_asns:
            path = os.path.join(out_dir, name)
            if dry:
                logger.info(f"[dry-run] would remove orphan file: {path}")
            else:
                try:
                    os.remove(path)
                    logger.info(f"Removed orphan file: {path}")
                except Exception as e:
                    logger.warning(f"Failed to remove orphan file {path}: {e}")

def main():
    ap = argparse.ArgumentParser(description="Fetch prefixes for ASNs and store per-AS files (rate-limit aware, prune orphans).")
    ap.add_argument("--config", default="/etc/as-blocklist/as-blocklist.yaml")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--only-as", nargs="*", help="Limit to specific ASNs (e.g., 214940 214943)")
    args = ap.parse_args()

    with open(args.config, "r") as f:
        cfg = yaml.safe_load(f)

    log_file = cfg.get("paths",{}).get("log_file", DEF_LOG)
    logger = setup_logger(log_file, verbose=args.verbose)

    out_dir    = cfg.get("paths",{}).get("out_dir", DEF_OUT)
    timeout    = int(cfg.get("settings",{}).get("fetch_timeout_seconds", 20))
    endpoint   = cfg.get("settings",{}).get("bgpview_endpoint", "https://api.bgpview.io/asn/{asn}/prefixes")
    sleep_between = float(cfg.get("settings",{}).get("sleep_between_requests_seconds", 3))
    max_retries   = int(cfg.get("settings",{}).get("max_retries", 5))
    backoff_init  = float(cfg.get("settings",{}).get("backoff_initial_seconds", 1))
    backoff_max   = float(cfg.get("settings",{}).get("backoff_max_seconds", 30))
    prune_files   = bool(cfg.get("settings",{}).get("prune_orphan_files", True))

    asns_cfg = cfg.get("asns", [])
    if not asns_cfg:
        logger.error("No ASNs in config."); sys.exit(1)
    configured_asns = [a["asn"] for a in asns_cfg]
    if args.only_as:
        target_asns = [a for a in configured_asns if a in args.only_as]
    else:
        target_asns = configured_asns

    logger.info(f"Start fetch (ASNs={target_asns}) dry={args.dry_run}")

    session = requests.Session()
    session.headers.update({"User-Agent": UA})

    for i, asn in enumerate(target_asns):
        if i > 0 and sleep_between > 0:
            logger.debug(f"Sleeping {sleep_between:.2f}s before next request...")
            time.sleep(sleep_between)
        try:
            cidrs = fetch_as_prefixes(asn, endpoint, timeout, logger, max_retries, backoff_init, backoff_max, session)
            cidrs = sorted(set(cidrs))
            content = "# generated at {}\n".format(ts()) + "\n".join(cidrs) + "\n"
            out_path = os.path.join(out_dir, f"{asn}.cidr")
            atomic_write(content, out_path, logger, dry=args.dry_run)
        except Exception as e:
            logger.error(f"AS{asn}: fetch failed: {e}. Keeping previous file (if any).")
            continue

    # Delete orphan files
    prune_orphan_files_if_enabled(out_dir, configured_asns, prune_files, logger, dry=args.dry_run)

    logger.info("Fetch done.")

if __name__ == "__main__":
    main()