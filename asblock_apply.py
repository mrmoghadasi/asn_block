#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, os, sys, re, datetime as dt, subprocess, tempfile, json, logging
from logging.handlers import RotatingFileHandler

try:
    import yaml
except Exception:
    print("Install deps first: `apt-get install python3-yaml` or `pip install pyyaml`", file=sys.stderr)
    sys.exit(2)

CIDR_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}$")

def require_root():
    if os.geteuid() != 0:
        print("Run as root (sudo).", file=sys.stderr); sys.exit(1)

def run(cmd, check=True, capture=True, dry=False, logger=None):
    s = " ".join(cmd)
    if logger: logger.debug(f"RUN: {s} (dry={dry})")
    if dry:
        return subprocess.CompletedProcess(cmd, 0, "", "")
    return subprocess.run(cmd, check=check, capture_output=capture, text=True)

def setup_logger(path, verbose=False):
    logger = logging.getLogger("asblock_apply")
    logger.setLevel(logging.DEBUG)
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

def ts(): return dt.datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")

def backup(backup_dir, logger, dry=False):
    os.makedirs(backup_dir, exist_ok=True)
    ipt = os.path.join(backup_dir, f"iptables-{ts()}.rules")
    ips = os.path.join(backup_dir, f"ipset-{ts()}.save")
    logger.info(f"Backup iptables -> {ipt}")
    if not dry:
        out = run(["iptables-save"], logger=logger)
        open(ipt,"w").write(out.stdout)
    logger.info(f"Backup ipset -> {ips}")
    if not dry:
        out = run(["ipset","save"], logger=logger)
        open(ips,"w").write(out.stdout)

def ensure_ipset(setname, logger, dry=False):
    res = run(["ipset","list", setname], check=False, logger=logger, dry=dry)
    if res.returncode != 0:
        logger.info(f"Create ipset {setname} (hash:net)")
        run(["ipset","create", setname,"hash:net","-exist"], logger=logger, dry=dry)

def read_current_members(setname, logger):
    res = run(["ipset","list", setname], check=False, logger=logger)
    if res.returncode != 0: return set()
    mem = set()
    in_members=False
    for line in res.stdout.splitlines():
        if line.strip().startswith("Members:"): in_members=True; continue
        if in_members:
            val=line.strip()
            if CIDR_RE.match(val): mem.add(val)
    return mem

def update_ipset_atomic(setname, cidrs, logger, dry=False):
    tmp = f"{setname}.tmp.{os.getpid()}"
    run(["ipset","create", tmp, "hash:net","-exist"], logger=logger, dry=dry)
    for c in cidrs:
        run(["ipset","add", tmp, c, "-exist"], logger=logger, dry=dry)
    ensure_ipset(setname, logger, dry=dry)
    cur = set()
    try: cur = read_current_members(setname, logger)
    except: pass
    tgt = set(cidrs)
    add = tgt - cur; rem = cur - tgt
    logger.info(f"[{setname}] current={len(cur)} target={len(tgt)} add={len(add)} remove={len(rem)}")

    if dry:
        run(["ipset","destroy", tmp], check=False, logger=logger, dry=True)
        return

    run(["ipset","swap", tmp, setname], logger=logger)
    run(["ipset","destroy", tmp], check=False, logger=logger)

def ensure_iptables_rules(setname, logger, dry=False):
    def ensure(chain, args):
        rc = run(["iptables","-C", chain] + args, check=False, logger=logger, dry=dry).returncode
        if rc != 0:
            logger.info(f"Insert iptables in {chain}: {' '.join(args)}")
            run(["iptables","-I", chain, "1"] + args, logger=logger, dry=dry)
        else:
            logger.debug(f"iptables rule present in {chain}: {' '.join(args)}")
    ensure("INPUT",   ["-m","set","--match-set", setname,"src","-j","DROP"])
    ensure("FORWARD", ["-m","set","--match-set", setname,"src","-j","DROP"])
    ensure("OUTPUT",  ["-m","set","--match-set", setname,"dst","-j","REJECT"])

def main():
    ap = argparse.ArgumentParser(description="Apply per-AS CIDR files to ipset/iptables.")
    ap.add_argument("--config", default="/etc/as-blocklist/as-blocklist.yaml")
    ap.add_argument("--backup-dir", default="/etc/as-blocklist/iptable_rule_backup")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--only-as", nargs="*", help="Apply limited ASNs")
    args = ap.parse_args()

    require_root()
    with open(args.config,"r") as f: cfg = yaml.safe_load(f)
    log_file = cfg.get("paths",{}).get("log_file","/var/log/as-blocklist.log")
    logger = setup_logger(log_file, verbose=args.verbose)

    out_dir = cfg.get("paths",{}).get("out_dir","/var/lib/as-blocklist")
    asns_cfg = cfg.get("asns", [])
    if not asns_cfg:
        logger.error("No ASNs in config."); sys.exit(1)

    # map ASN->ipset
    as_map = {a["asn"]: a.get("ipset", f"bad_as{a['asn']}") for a in asns_cfg}
    targets = list(as_map.keys())
    if args.only_as:
        targets = [a for a in targets if a in args.only_as]

    logger.info(f"Apply start (ASNs={targets}) dry={args.dry_run}")
    # backup first
    try:
        backup(args.backup_dir, logger, dry=args.dry_run)
    except Exception as e:
        logger.exception(f"Backup failed: {e}"); sys.exit(3)

    for asn in targets:
        setname = as_map[asn]
        cidr_file = os.path.join(out_dir, f"{asn}.cidr")
        if not os.path.isfile(cidr_file):
            logger.warning(f"Missing CIDR file for AS{asn}: {cidr_file} — skip")
            continue
        with open(cidr_file) as f:
            lines = [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        cidrs = [ln for ln in lines if CIDR_RE.match(ln)]

        logger.info(f"AS{asn} -> ipset {setname}: {len(cidrs)} prefixes")
        try:
            update_ipset_atomic(setname, cidrs, logger, dry=args.dry_run)
            ensure_iptables_rules(setname, logger, dry=args.dry_run)
        except subprocess.CalledProcessError as e:
            logger.error(f"Command failed: {e}\nSTDERR: {getattr(e,'stderr','')}")
            continue
        except Exception as e:
            logger.exception(f"Apply failed for AS{asn}: {e}")
            continue

    logger.info("Apply done.")

if __name__ == "__main__":
    main()