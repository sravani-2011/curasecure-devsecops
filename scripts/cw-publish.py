#!/usr/bin/env python3
"""Publish the results of one CuraSecure pipeline run to Amazon CloudWatch.

  cw-publish.py <result> <duration_ms>      (run from the Jenkins workspace, after secgate.py)

Reads reports/*.summary.json, reports/security-summary.json and reports/tests.tap, then
  * custom metrics  -> namespace CuraSecure/DevSecOps   (dashboard tiles and graphs)
  * one log event per gate + one per build -> log group /curasecure/pipeline (results table)

Uses the AWS CLI with the EC2 instance profile (LabInstanceProfile in AWS Academy labs).
Never fails the build: any AWS error is printed and ignored.
"""
import glob
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request

REPORTS = os.environ.get("REPORTS_DIR", "reports")
NS = "CuraSecure/DevSecOps"
LOG_GROUP = "/curasecure/pipeline"
PIPELINE = os.environ.get("APP", "curasecure")
SEVS = ["critical", "high", "medium", "low", "info"]
STATUS_CODE = {"pass": 0, "warn": 1, "fail": 2}  # skipped gates are not published
GATE_ORDER = ["secrets", "sast", "sca", "iac", "tests", "npm", "image", "dast"]


def aws_bin():
    for c in (shutil.which("aws"), "/usr/local/bin/aws", "/snap/bin/aws"):
        if c and os.path.exists(c):
            return c
    return None


def region():
    if os.environ.get("AWS_REGION") or os.environ.get("AWS_DEFAULT_REGION"):
        return os.environ.get("AWS_REGION") or os.environ["AWS_DEFAULT_REGION"]
    try:  # IMDSv2 (the instance requires tokens)
        tok = urllib.request.urlopen(urllib.request.Request(
            "http://169.254.169.254/latest/api/token", method="PUT",
            headers={"X-aws-ec2-metadata-token-ttl-seconds": "60"}), timeout=2).read().decode()
        return urllib.request.urlopen(urllib.request.Request(
            "http://169.254.169.254/latest/meta-data/placement/region",
            headers={"X-aws-ec2-metadata-token": tok}), timeout=2).read().decode()
    except Exception:
        return "us-east-1"


def aws(*args):
    cmd = [AWS, "--region", REGION, "--output", "json", *args]
    p = subprocess.run(cmd, capture_output=True, text=True)
    if p.returncode != 0 and "AlreadyExists" not in p.stderr:
        print(f"[cw-publish] aws {args[0]} {args[1]} failed: {p.stderr.strip()[:300]}")
    return p.returncode == 0


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def tests_counts():
    try:
        lines = open(os.path.join(REPORTS, "tests.tap"), encoding="utf-8").read().splitlines()
    except OSError:
        return None
    return (sum(1 for l in lines if l.startswith("ok ")), sum(1 for l in lines if l.startswith("not ok ")))


def main():
    result = (sys.argv[1] if len(sys.argv) > 1 else "UNKNOWN").upper()
    duration_s = int(sys.argv[2]) / 1000 if len(sys.argv) > 2 and sys.argv[2].isdigit() else None
    build = os.environ.get("BUILD_NUMBER", "0")
    commit = os.environ.get("GIT_SHORT", "unknown")
    now = int(time.time())

    summary = load(os.path.join(REPORTS, "security-summary.json")) or {}
    gates = {}
    for path in glob.glob(os.path.join(REPORTS, "*.summary.json")):
        g = load(path)
        if g and g.get("key"):
            gates[g["key"]] = g

    pipe = [{"Name": "Pipeline", "Value": PIPELINE}]
    m = []

    def put(name, value, dims=pipe, unit="Count"):
        m.append({"MetricName": name, "Dimensions": dims, "Value": float(value), "Unit": unit,
                  "Timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now))})

    put("PipelineSucceeded", 1 if result == "SUCCESS" else 0)
    put("BuildNumber", int(build) if build.isdigit() else 0, unit="None")
    if duration_s is not None:
        put("PipelineDurationSeconds", duration_s, unit="Seconds")
    put("GatesFailed", sum(1 for g in gates.values() if g.get("status") == "fail"))
    put("GatesRun", len(gates))

    sev_total = {s: 0 for s in SEVS}
    for key, g in gates.items():
        code = STATUS_CODE.get(g.get("status"))
        if code is not None:
            put("GateStatus", code, dims=[{"Name": "Gate", "Value": key}], unit="None")
        counts = g.get("counts") or {}
        put("GateFindings", sum(counts.get(s, 0) for s in SEVS), dims=[{"Name": "Gate", "Value": key}])
        for s in SEVS:
            sev_total[s] += counts.get(s, 0)
    for s in SEVS:
        put("Findings", sev_total[s], dims=[{"Name": "Severity", "Value": s}])
    put("TotalFindings", sum(sev_total.values()))

    tc = tests_counts()
    if tc:
        put("TestsPassed", tc[0])
        put("TestsFailed", tc[1])
    sbom = (summary.get("sbom") or {}).get("components")
    if sbom:
        put("SbomComponents", sbom)

    # put-metric-data accepts up to 1000 datums per call; we send ~30
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(m, f)
        mpath = f.name
    ok = aws("cloudwatch", "put-metric-data", "--namespace", NS, "--metric-data", f"file://{mpath}")

    # ---- log events (one JSON line per gate + one per build) ----
    ts = now * 1000
    events = []
    for key in GATE_ORDER:
        g = gates.get(key)
        if not g:
            continue
        c = g.get("counts") or {}
        top = (g.get("findings") or [{}])[0]
        events.append({"timestamp": ts, "message": json.dumps({
            "type": "gate", "build": int(build) if build.isdigit() else build, "commit": commit,
            "result": result, "gate": key, "name": g.get("name"), "tool": g.get("tool"),
            "status": g.get("status"), "policy": g.get("policy"),
            **{s: c.get(s, 0) for s in SEVS},
            "topFinding": f"{top.get('id', '')} {top.get('title', '')}".strip()[:120]})})
    events.append({"timestamp": ts, "message": json.dumps({
        "type": "build", "build": int(build) if build.isdigit() else build, "commit": commit,
        "result": result, "image": summary.get("image", ""), "gatePassed": summary.get("gatePassed"),
        "durationSec": duration_s, "gatesFailed": sum(1 for g in gates.values() if g.get("status") == "fail"),
        "sbomComponents": sbom or 0, **{s: sev_total[s] for s in SEVS}})})

    stream = f"build-{build}"
    aws("logs", "create-log-group", "--log-group-name", LOG_GROUP)
    aws("logs", "put-retention-policy", "--log-group-name", LOG_GROUP, "--retention-in-days", "30")
    aws("logs", "create-log-stream", "--log-group-name", LOG_GROUP, "--log-stream-name", stream)
    with tempfile.NamedTemporaryFile("w", suffix=".json", delete=False) as f:
        json.dump(events, f)
        epath = f.name
    ok = aws("logs", "put-log-events", "--log-group-name", LOG_GROUP, "--log-stream-name", stream,
             "--log-events", f"file://{epath}") and ok
    os.unlink(mpath)
    os.unlink(epath)
    print(f"[cw-publish] build {build} ({result}): {len(m)} metrics, {len(events)} log events -> "
          f"{'CloudWatch OK' if ok else 'CloudWatch errors above (build not affected)'}")


if __name__ == "__main__":
    AWS = aws_bin()
    if not AWS:
        print("[cw-publish] AWS CLI not installed - run infra/cloudwatch-setup.sh on the EC2 host. Skipping.")
        sys.exit(0)
    REGION = region()
    try:
        main()
    except Exception as e:  # never break the pipeline because of monitoring
        print(f"[cw-publish] skipped: {e}")
    sys.exit(0)
