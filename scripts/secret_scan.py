#!/usr/bin/env python3
"""Secret and topology scanner for this repository.

Stages, in order, on every run:
  1. self-test: canary secrets, generated at runtime, must be detected.
     If any canary is missed the scan aborts (exit 2), so a green result
     can never come from a scanner that is silently broken.
  2. working tree: every tracked file (git ls-files).
  3. history: every added line in every commit (git log --all -p).

Checks: detect-secrets default plugins (keys, tokens, private keys,
high-entropy strings) plus two project policies detect-secrets lacks:
  - LAN addresses (RFC 1918). Documentation ranges (192.0.2.0/24) are fine.
  - MAC addresses outside the allowlisted prefixes.

Outputs go to <out>/<UTC timestamp>/: scan.log, report.json, report.md.
Secret values and topology values are never printed; findings are masked.

Exit codes: 0 clean, 1 findings, 2 self-test failed, 3 environment error.
"""
import argparse
import datetime as dt
import importlib.metadata
import json
import logging
import re
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from detect_secrets.core.secrets_collection import SecretsCollection
from detect_secrets.settings import default_settings

EXIT_CLEAN, EXIT_FINDINGS, EXIT_SELFTEST, EXIT_ENV = 0, 1, 2, 3
log = logging.getLogger("secret_scan")

LAN_IP = re.compile(
    r"(?<![\d.])(10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})(?![\d.])"
)
MAC = re.compile(r"(?<![0-9A-Fa-f:-])((?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})(?![0-9A-Fa-f:-])")
ALLOWED_MAC_PREFIXES = ("02:00:00", "00:00:5e", "aa:bb:cc", "00:00:00", "ff:ff:ff")


def mask_ip(ip):
    a = ip.split(".")
    return f"{a[0]}.{a[1]}.x.x"


def mask_mac(mac):
    m = mac.lower().replace("-", ":")
    return f"{m[:8]}:xx:xx:xx"


def policy_hits(text):
    """Yield (kind, masked_value, column) for LAN IPs and non-allowlisted MACs."""
    for m in LAN_IP.finditer(text):
        yield "policy:lan-ip", mask_ip(m.group(1)), m.start()
    for m in MAC.finditer(text):
        mac = m.group(1).lower().replace("-", ":")
        if not mac.startswith(ALLOWED_MAC_PREFIXES):
            yield "policy:mac", mask_mac(mac), m.start()


def detect_secrets_scan(path):
    """Return (type, line, fingerprint) tuples from detect-secrets for one file."""
    sc = SecretsCollection()
    try:
        with default_settings():
            sc.scan_file(str(path))
    except (UnicodeDecodeError, OSError) as exc:
        log.warning("skipped %s: %s", path, type(exc).__name__)
        return []
    out = []
    for _, items in sc.data.items():
        for s in items:
            out.append((s.type, s.line_number, s.secret_hash[:12]))
    return out


def canary_text():
    # Built from pieces so this file never contains a literal secret.
    return "\n".join([
        "aws = " + "AKIA" + "ABCDEFGHIJKLMNOP",
        "key = '-----BEGIN " + "RSA PRIVATE KEY-----'",
        "gh = " + "ghp_" + "a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8",
        "lan = 192.168.77.10",
        "mac = f4:5c:89:12:ab:cd",
    ])


def self_test(workdir):
    """Scanner must flag every canary category, or it is not trusted."""
    path = Path(workdir) / "canary.txt"
    path.write_text(canary_text())
    found = detect_secrets_scan(path)
    types = {t for t, _, _ in found}
    policy = {k for k, _, _ in policy_hits(path.read_text())}
    required = {"AWS Access Key", "Private Key", "GitHub Token"}
    missing = sorted(required - types) + sorted({"policy:lan-ip", "policy:mac"} - policy)
    if missing:
        return False, missing
    return True, []


def history_records(repo):
    """Parse added lines from git history into (commit, path, lineno, content)."""
    raw = subprocess.run(
        ["git", "-C", str(repo), "log", "--all", "-p", "-U0", "--no-color",
         "--format=@@COMMIT %H"],
        capture_output=True, text=True, check=True,
    ).stdout
    recs, commit, path, newline = [], None, "?", 0
    for line in raw.splitlines():
        if line.startswith("@@COMMIT "):
            commit, path = line[9:21], "?"
        elif line.startswith("+++ "):
            path = line[6:] if line.startswith("+++ b/") else "?"
        elif line.startswith("@@ "):
            m = re.search(r"\+(\d+)", line)
            newline = int(m.group(1)) if m else 0
        elif line.startswith("+") and not line.startswith("+++"):
            recs.append((commit, path, newline, line[1:]))
            newline += 1
    return recs


def scan_history(repo, workdir, findings, stats):
    recs = history_records(repo)
    stats["history_added_lines"] = len(recs)
    tmp = Path(workdir) / "history_added.txt"
    tmp.write_text("\n".join(r[3] for r in recs) + "\n")
    for ds_type, line_no, fp in detect_secrets_scan(tmp):
        commit, path, lineno, _ = recs[line_no - 1]
        findings.append({"stage": "history", "rule": ds_type, "commit": commit,
                         "file": path, "line": lineno, "fingerprint": fp})
    for commit, path, lineno, content in recs:
        for kind, value, _ in policy_hits(content):
            findings.append({"stage": "history", "rule": kind, "commit": commit,
                             "file": path, "line": lineno, "value": value})


def scan_working(repo, findings, stats):
    files = subprocess.run(["git", "-C", str(repo), "ls-files", "-z"],
                           capture_output=True, text=True, check=True).stdout.split("\0")
    files = [f for f in files if f]
    stats["working_files"] = len(files)
    for rel in files:
        p = Path(repo) / rel
        if not p.is_file():
            continue
        for ds_type, line_no, fp in detect_secrets_scan(p):
            findings.append({"stage": "working", "rule": ds_type, "file": rel,
                             "line": line_no, "fingerprint": fp})
        try:
            lines = p.read_text().splitlines()
        except (UnicodeDecodeError, OSError):
            continue
        for n, line in enumerate(lines, 1):
            for kind, value, _ in policy_hits(line):
                findings.append({"stage": "working", "rule": kind, "file": rel,
                                 "line": n, "value": value})


def write_reports(outdir, report):
    (outdir / "report.json").write_text(json.dumps(report, indent=2))
    rows = ["| stage | rule | file | line | commit | detail |", "|---|---|---|---|---|---|"]
    for f in report["findings"]:
        detail = f.get("value") or f"fp {f.get('fingerprint', '')}"
        rows.append(f"| {f['stage']} | {f['rule']} | {f['file']} | {f['line']} | "
                    f"{f.get('commit', '')} | {detail} |")
    md = [f"# Secret scan {report['run_id']}", "",
          f"- repo: `{report['repo']}`", f"- mode: {report['mode']}",
          f"- status: **{report['status']}**",
          f"- detect-secrets {report['detect_secrets_version']}",
          f"- findings: {len(report['findings'])}", "",
          "Secret values are never printed. Policy values are masked.", ""]
    md += rows if report["findings"] else ["No findings."]
    (outdir / "report.md").write_text("\n".join(md) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--repo", default=".", help="repository to scan")
    ap.add_argument("--mode", choices=["all", "working", "history"], default="all")
    ap.add_argument("--out", default="reports/secret-scan", help="report root directory")
    args = ap.parse_args(argv)

    repo = Path(args.repo).resolve()
    run_id = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    outdir = Path(args.out).resolve() / run_id
    outdir.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s",
                        handlers=[logging.FileHandler(outdir / "scan.log"),
                                  logging.StreamHandler(sys.stdout)])
    ds_version = importlib.metadata.version("detect-secrets")
    log.info("run %s repo=%s mode=%s detect-secrets=%s", run_id, repo, args.mode, ds_version)

    report = {"run_id": run_id, "repo": str(repo), "mode": args.mode,
              "detect_secrets_version": ds_version, "findings": [], "stats": {}}
    started = time.monotonic()

    with tempfile.TemporaryDirectory() as tmp:
        ok, missing = self_test(tmp)
        if not ok:
            log.error("self-test FAILED, scanner not trusted; missing detections: %s", missing)
            report.update(status="selftest_failed", selftest_missing=missing)
            write_reports(outdir, report)
            return EXIT_SELFTEST
        log.info("self-test passed: all canary categories detected")
        report["selftest"] = "passed"

        try:
            if args.mode in ("working", "all"):
                log.info("scanning working tree")
                scan_working(repo, report["findings"], report["stats"])
            if args.mode in ("history", "all"):
                log.info("scanning git history")
                scan_history(repo, tmp, report["findings"], report["stats"])
        except subprocess.CalledProcessError as exc:
            log.error("git failed (exit %s) while scanning %s; is this a git repository?",
                      exc.returncode, repo)
            report.update(status="environment_error")
            write_reports(outdir, report)
            return EXIT_ENV

    for f in report["findings"]:
        log.warning("finding stage=%s rule=%s file=%s line=%s", f["stage"], f["rule"],
                    f["file"], f["line"])
    report["status"] = "findings" if report["findings"] else "clean"
    report["elapsed_seconds"] = round(time.monotonic() - started, 2)
    write_reports(outdir, report)

    # Verify the artifacts we just wrote, so a silent write failure cannot pass as clean.
    readback = json.loads((outdir / "report.json").read_text())
    assert readback["status"] == report["status"]
    assert len(readback["findings"]) == len(report["findings"])
    assert (outdir / "report.md").stat().st_size > 0 and (outdir / "scan.log").stat().st_size > 0
    log.info("status=%s findings=%d report=%s", report["status"],
             len(report["findings"]), outdir)
    return EXIT_FINDINGS if report["findings"] else EXIT_CLEAN


if __name__ == "__main__":
    sys.exit(main())
