#!/usr/bin/env python3
"""Security gate evaluator for the CuraSecure DevSecOps pipeline.

  secgate.py check <gate> <report.json>   -> normalise a scanner report, apply the gate
                                             policy, write reports/<gate>.summary.json,
                                             exit 1 if the release must be blocked
  secgate.py publish <out.json> <build> <commit> <image>
                                          -> merge all gate summaries into the report
                                             shown in the portal's Security Center
"""
import glob
import json
import os
import sys
from datetime import datetime, timezone

REPORTS = os.environ.get("REPORTS_DIR", "reports")
SEVS = ["critical", "high", "medium", "low", "info"]

# name, tool, policy text, ordering
GATES = {
    "secrets": ("Secret scanning", "Gitleaks", "Block on any secret"),
    "sast":    ("Static code analysis (SAST)", "Semgrep", "Block on ERROR (high) findings"),
    "tests":   ("Unit & security tests", "node:test", "Block on any failing test"),
    "npm":     ("Dependency audit", "npm audit", "Block on critical"),
    "sca":     ("Dependency scan (SCA)", "Trivy fs", "Block on fixable HIGH/CRITICAL"),
    "iac":     ("Infrastructure-as-Code scan", "Trivy config", "Block on HIGH/CRITICAL misconfig"),
    "image":   ("Container image scan", "Trivy image", "Block on fixable CRITICAL"),
    "dast":    ("Dynamic scan (DAST)", "OWASP ZAP", "Block + rollback on High risk alert"),
}


def load(path):
    try:
        with open(path, encoding="utf-8") as f:
            txt = f.read().strip()
        return json.loads(txt) if txt else None
    except (OSError, ValueError):
        return None


def norm(sev):
    s = str(sev or "").lower()
    return {"error": "high", "warning": "medium", "moderate": "medium", "unknown": "info", "note": "low",
            "informational": "info"}.get(s, s if s in SEVS else "info")


def finding(id_, sev, title, loc):
    return {"id": str(id_)[:80], "severity": norm(sev), "title": str(title)[:160], "location": str(loc)[:120]}


# ---------------- parsers: return (findings, blocking_bool) ----------------
def p_secrets(r):
    items = r or []
    f = [finding(i.get("RuleID"), "critical", i.get("Description", "Secret"), f"{i.get('File')}:{i.get('StartLine')}") for i in items]
    return f, len(f) > 0


def p_sast(r):
    res = (r or {}).get("results", [])
    f = [finding(x.get("check_id", "").split(".")[-1], x.get("extra", {}).get("severity"),
                 x.get("extra", {}).get("message", "").split("\n")[0], f"{x.get('path')}:{x.get('start', {}).get('line')}") for x in res]
    # Fail closed if Semgrep itself could not load its rules (otherwise "0 findings" would be a lie)
    for e in (r or {}).get("errors", []):
        if e.get("level") == "error" and "Syntax" not in str(e.get("type")) and "Partial" not in str(e.get("type")):
            f.append(finding("semgrep-error", "high", str(e.get("message", "Semgrep error")).split("\n")[0], "semgrep"))
    return f, any(x["severity"] == "high" for x in f)


def p_tests(r):
    r = r or {}
    f = [finding("test", "high", t, "app/test") for t in r.get("failed", [])]
    return f, r.get("fail", 1) > 0


def p_npm(r):
    vulns = (r or {}).get("vulnerabilities", {})
    f = [finding(name, v.get("severity"), f"Vulnerable dependency {name} {v.get('range', '')}", "app/package-lock.json") for name, v in vulns.items()]
    return f, any(x["severity"] == "critical" for x in f)


def trivy_vulns(r, target_label):
    out, block_sevs = [], []
    for res in (r or {}).get("Results", []) or []:
        for v in res.get("Vulnerabilities", []) or []:
            fx = v.get("FixedVersion")
            out.append((finding(v.get("VulnerabilityID"), v.get("Severity"),
                                f"{v.get('PkgName')} {v.get('InstalledVersion')}{' -> fix ' + fx if fx else ' (no fix yet)'}",
                                res.get("Target", target_label)), bool(fx)))
    return out


def p_sca(r):
    v = trivy_vulns(r, "app")
    return [x for x, _ in v], any(x["severity"] in ("critical", "high") and fixable for x, fixable in v)


def p_iac(r):
    f = []
    for res in (r or {}).get("Results", []) or []:
        for m in res.get("Misconfigurations", []) or []:
            if m.get("Status", "FAIL") == "FAIL":
                f.append(finding(m.get("ID") or m.get("AVDID"), m.get("Severity"), m.get("Title"), res.get("Target")))
    return f, any(x["severity"] in ("critical", "high") for x in f)


def p_image(r):
    v = trivy_vulns(r, "image")
    return [x for x, _ in v], any(x["severity"] == "critical" and fixable for x, fixable in v)


def p_dast(r):
    risk = {"3": "high", "2": "medium", "1": "low", "0": "info"}
    f = []
    for site in (r or {}).get("site", []) or []:
        for a in site.get("alerts", []) or []:
            inst = (a.get("instances") or [{}])[0]
            f.append(finding(f"ZAP-{a.get('pluginid')}", risk.get(str(a.get("riskcode")), "info"), a.get("name"), inst.get("uri", site.get("@name"))))
    return f, any(x["severity"] == "high" for x in f)


PARSERS = {"secrets": p_secrets, "sast": p_sast, "tests": p_tests, "npm": p_npm, "sca": p_sca,
           "iac": p_iac, "image": p_image, "dast": p_dast}


def load_tap(path):
    try:
        lines = open(path, encoding="utf-8").read().splitlines()
    except OSError:
        return None
    failed = [l.split(" - ", 1)[-1] for l in lines if l.startswith("not ok ")]
    passed = sum(1 for l in lines if l.startswith("ok "))
    return {"pass": passed, "fail": len(failed), "failed": failed} if (passed or failed) else None


def check(gate, path):
    report = load_tap(path) if gate == "tests" else load(path)
    name, tool, policy = GATES[gate]
    if report is None and gate != "secrets":
        status, findings, blocking = "fail", [finding("report", "high", f"{tool} produced no readable report", path)], True
    else:
        findings, blocking = PARSERS[gate](report)
        status = "fail" if blocking else ("warn" if any(f["severity"] in ("critical", "high", "medium") for f in findings) else "pass")
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVS}
    findings.sort(key=lambda f: SEVS.index(f["severity"]))
    summary = {"key": gate, "name": name, "tool": tool, "policy": policy, "status": status, "counts": counts, "findings": findings[:15]}
    os.makedirs(REPORTS, exist_ok=True)
    with open(os.path.join(REPORTS, f"{gate}.summary.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)

    print(f"\n=== {name} ({tool}) — policy: {policy}")
    print("    " + "  ".join(f"{s.upper()}={counts[s]}" for s in SEVS))
    for f in findings[:10]:
        print(f"    [{f['severity'].upper():8}] {f['id']}: {f['title']}  ({f['location']})")
    print(f"    RESULT: {status.upper()}{'  -> RELEASE BLOCKED' if blocking else ''}\n")
    return 1 if blocking else 0


def publish(out, build, commit, image):
    gates = []
    for key in GATES:
        s = load(os.path.join(REPORTS, f"{key}.summary.json"))
        if s:
            gates.append(s)
        else:
            n, t, p = GATES[key]
            gates.append({"key": key, "name": n, "tool": t, "policy": p, "status": "skipped", "counts": {}, "findings": []})
    sbom = load(os.path.join(REPORTS, "sbom.cdx.json")) or {}
    doc = {
        "available": True, "build": build, "commit": commit, "image": image,
        "generatedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "gatePassed": all(g["status"] != "fail" for g in gates),
        "gates": gates,
        "sbom": {"format": "CycloneDX " + str(sbom.get("specVersion", "")), "components": len(sbom.get("components", []))},
    }
    with open(out, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2)
    print(f"Security summary written to {out}: gatePassed={doc['gatePassed']}")
    for g in gates:
        print(f"  {g['status'].upper():8} {g['name']}")
    return 0


if __name__ == "__main__":
    if len(sys.argv) >= 4 and sys.argv[1] == "check":
        sys.exit(check(sys.argv[2], sys.argv[3]))
    if len(sys.argv) == 6 and sys.argv[1] == "publish":
        sys.exit(publish(*sys.argv[2:]))
    print(__doc__)
    sys.exit(2)
