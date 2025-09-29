#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse, os, sys, re, datetime as dt, subprocess, logging
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
    if dry: return subprocess.CompletedProcess(cmd, 0, "", "")
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
        out = run(["iptables-save"], logger=logger); open(ipt,"w").write(out.stdout)
    logger.info(f"Backup ipset -> {ips}")
    if not dry:
        out = run(["ipset","save"], logger=logger); open(ips,"w").write(out.stdout)

def ensure_ipset(setname, logger, dry=False):
    rc = run(["ipset","list", setname], check=False, logger=logger, dry=dry).returncode
    if rc != 0:
        logger.info(f"Create ipset {setname} (hash:net)")
        run(["ipset","create", setname,"hash:net","-exist"], logger=logger, dry=dry)

def read_current_members(setname, logger):
    res = run(["ipset","list", setname], check=False, logger=logger)
    if res.returncode != 0: return set()
    mem, in_members = set(), False
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

def remove_iptables_rules_for_set(setname, logger, dry=False):
    """حذف تمام ruleهایی که به این ipset اشاره دارند (ساده و ایمن: با -S grep و سپس -D)."""
    res = run(["iptables","-S"], check=True, logger=logger, dry=False)
    lines = res.stdout.splitlines()
    to_delete = []
    for ln in lines:
        if f"--match-set {setname} " in ln:
            # Example: -A INPUT -m set --match-set bad_as214943 src -j DROP
            to_delete.append(ln)
    # Remove from exact chain: -D must be the same as the rule arguments.
    for rule in to_delete:
        parts = rule.split()
        # rule same: -A CHAIN args...
        if len(parts) >= 3 and parts[0] == "-A":
            chain = parts[1]
            rule_args = parts[2:]
            logger.info(f"Deleting iptables rule from {chain}: {' '.join(rule_args)}")
            if not dry:
                run(["iptables","-D", chain] + rule_args, logger=logger)
        else:
            logger.debug(f"Skip unparsable rule: {rule}")

def destroy_ipset(setname, logger, dry=False):
    logger.info(f"Destroy ipset {setname}")
    run(["ipset","destroy", setname], check=False, logger=logger, dry=dry)

def main():
    ap = argparse.ArgumentParser(description="Apply per-AS CIDR files to ipset/iptables (with prune).")
    ap.add_argument("--config", default="/etc/as-blocklist/as-blocklist.yaml")
    ap.add_argument("--backup-dir", default="/etc/as-blocklist/iptable_rule_backup")
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--only-as", nargs="*", help="Apply limited ASNs")
    ap.add_argument("--prune", action="store_true", help="Remove ipset/iptables entries for ASNs not in config or without CIDR files")
    args = ap.parse_args()

    require_root()
    with open(args.config,"r") as f: cfg = yaml.safe_load(f)
    log_file = cfg.get("paths",{}).get("log_file","/var/log/as-blocklist.log")
    logger = setup_logger(log_file, verbose=args.verbose)

    out_dir = cfg.get("paths",{}).get("out_dir","/var/lib/as-blocklist")
    asns_cfg = cfg.get("asns", [])
    prune_cfg = bool(cfg.get("settings",{}).get("prune_orphan_sets", True))
    do_prune = args.prune or prune_cfg

    if not asns_cfg:
        logger.warning("No ASNs in config. With --prune, orphan sets will be removed.")
    # map ASN->ipset
    as_map = {a["asn"]: a.get("ipset", f"bad_as{a['asn']}") for a in asns_cfg}
    targets = list(as_map.keys())
    if args.only_as:
        targets = [a for a in targets if a in args.only_as]

    logger.info(f"Apply start (ASNs={targets}) dry={args.dry_run} prune={do_prune}")
    # backup first
    try:
        backup(args.backup_dir, logger, dry=args.dry_run)
    except Exception as e:
        logger.exception(f"Backup failed: {e}"); sys.exit(3)

    # 1) Apply for configured ASNs that have CIDR files
    for asn in targets:
        setname = as_map[asn]
        cidr_file = os.path.join(out_dir, f"{asn}.cidr")
        if not os.path.isfile(cidr_file):
            logger.warning(f"Missing CIDR file for AS{asn}: {cidr_file} — skip apply for this AS")
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

    # 2) Prune orphan sets/rules (ASNs not in YAML or without CIDR file)
    if do_prune:
        # ipset candidates from names in YAML + default patterns
        desired_sets = set(as_map.values())
        # list existing sets
        res = run(["ipset","list","-name"], check=False, logger=logger, dry=False)
        existing_sets = set(res.stdout.split()) if res.returncode == 0 else set()

        # any existing set that is not in desired or does not have a .cidr file should be deleted
        for setname in sorted(existing_sets):
            # only target sets whose names match our pattern to avoid deleting unrelated ones
            if not (setname.startswith("bad_as") or setname in desired_sets):
                continue
            # if this setname is not in desired → orphan
            is_orphan_by_yaml = setname not in desired_sets
            # if we want a reverse map: bad_as214943 → 214943
            m = re.match(r"bad_as(\d+)", setname)
            asn_from_name = m.group(1) if m else None
            cidr_path = os.path.join(out_dir, f"{asn_from_name}.cidr") if asn_from_name else None
            file_exists = os.path.isfile(cidr_path) if cidr_path else False
            is_orphan_by_file = not file_exists

            if is_orphan_by_yaml or is_orphan_by_file:
                logger.info(f"Prune orphan set: {setname} (by_yaml={is_orphan_by_yaml} by_file={is_orphan_by_file})")
                # delete related iptables rules
                remove_iptables_rules_for_set(setname, logger, dry=args.dry_run)
                # delete ipset
                destroy_ipset(setname, logger, dry=args.dry_run)

    logger.info("Apply done.")

if __name__ == "__main__":
    main()
