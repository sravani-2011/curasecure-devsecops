#!/bin/bash
# Run in AWS CloudShell. Installs CloudWatch monitoring on the CuraSecure EC2 host through
# Systems Manager (no SSH), then waits for the first pipeline results and prints a summary.
#   bash finish-monitoring.sh [instance-id]
set -uo pipefail
REGION=${AWS_REGION:-us-east-1}
REF=${REF:-main}
IID=${1:-$(aws ec2 describe-instances --region "$REGION" --filters Name=instance-state-name,Values=running \
      --query 'Reservations[0].Instances[0].InstanceId' --output text)}
echo "== Host $IID ($REGION)"

echo "== Waiting for Systems Manager agent (up to 15 min after attaching LabInstanceProfile)..."
for i in $(seq 1 90); do
  P=$(aws ssm describe-instance-information --region "$REGION" --filters Key=InstanceIds,Values="$IID" \
      --query 'InstanceInformationList[0].PingStatus' --output text 2>/dev/null)
  [ "$P" = "Online" ] && break
  if [ "$i" = 6 ]; then
    echo "   not online yet - rebooting the SSM agent on its next check-in usually needs the instance to pick up the new role;"
    echo "   if this times out, run on the host: sudo snap restart amazon-ssm-agent"
  fi
  sleep 10
done
if [ "$P" != "Online" ]; then
  echo "!! SSM agent not online. SSH to the host and run:"
  echo "   curl -sL https://raw.githubusercontent.com/sravani-2011/curasecure-devsecops/$REF/infra/cloudwatch-setup.sh | sudo bash"
  exit 1
fi
echo "   SSM online."

echo "== Installing CloudWatch agent + health probe on the host..."
CID=$(aws ssm send-command --region "$REGION" --instance-ids "$IID" --document-name AWS-RunShellScript \
  --timeout-seconds 900 --comment "CuraSecure CloudWatch setup" \
  --parameters "commands=[\"curl -sL https://raw.githubusercontent.com/sravani-2011/curasecure-devsecops/$REF/infra/cloudwatch-setup.sh | bash\"]" \
  --query Command.CommandId --output text)
for i in $(seq 1 90); do
  S=$(aws ssm get-command-invocation --region "$REGION" --command-id "$CID" --instance-id "$IID" --query Status --output text 2>/dev/null)
  case "$S" in Success|Failed|Cancelled|TimedOut) break;; esac
  sleep 10
done
echo "   setup: $S"
aws ssm get-command-invocation --region "$REGION" --command-id "$CID" --instance-id "$IID" \
  --query StandardOutputContent --output text | tail -3
[ "$S" = "Success" ] || { aws ssm get-command-invocation --region "$REGION" --command-id "$CID" --instance-id "$IID" --query StandardErrorContent --output text | tail -8; }

echo "== Waiting for live probe + first pipeline build in CloudWatch (Jenkins polls GitHub every 2 min; up to 40 min)..."
for i in $(seq 1 240); do
  N=$(aws logs describe-log-streams --region "$REGION" --log-group-name /curasecure/pipeline \
      --query 'length(logStreams)' --output text 2>/dev/null)
  [ "${N:-0}" != "0" ] && break
  sleep 10
done

python3 - "$REGION" <<'PY'
import json, subprocess, sys
R = sys.argv[1]
def aws(*a):
    return json.loads(subprocess.run(["aws", "--region", R, "--output", "json", *a], capture_output=True, text=True).stdout or "null")
s = aws("logs", "describe-log-streams", "--log-group-name", "/curasecure/pipeline", "--order-by", "LastEventTime", "--descending", "--max-items", "1")
streams = (s or {}).get("logStreams", [])
if not streams:
    print("!! No pipeline build published yet. Click 'Build Now' in Jenkins, then re-run this script.")
else:
    ev = aws("logs", "get-log-events", "--log-group-name", "/curasecure/pipeline", "--log-stream-name", streams[0]["logStreamName"])
    rows = [json.loads(e["message"]) for e in ev.get("events", [])]
    b = next((r for r in rows if r.get("type") == "build"), {})
    print(f"\n#BUILD {b.get('build')} commit={b.get('commit')} result={b.get('result')} gatesFailed={b.get('gatesFailed')} "
          f"dur={b.get('durationSec')}s sbom={b.get('sbomComponents')} C={b.get('critical')} H={b.get('high')} M={b.get('medium')} L={b.get('low')}")
    for r in rows:
        if r.get("type") == "gate":
            print(f"#GATE {r['gate']:8} {r['status']:5} C={r['critical']} H={r['high']} M={r['medium']} L={r['low']} | {r.get('topFinding','')[:60]}")
import datetime as d
now = d.datetime.utcnow(); st = (now - d.timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ"); en = now.strftime("%Y-%m-%dT%H:%M:%SZ")
for m, stat in (("PortalUp", "Minimum"), ("PortalLatencyMs", "Average"), ("ReadyPods", "Minimum")):
    r = aws("cloudwatch", "get-metric-statistics", "--namespace", "CuraSecure/DevSecOps", "--metric-name", m,
            "--dimensions", "Name=Pipeline,Value=curasecure", "--start-time", st, "--end-time", en, "--period", "60", "--statistics", stat)
    pts = sorted((r or {}).get("Datapoints", []), key=lambda p: p["Timestamp"])
    print(f"#LIVE {m}={pts[-1][stat] if pts else 'n/a'}")
for m in ("mem_used_percent", "disk_used_percent"):
    r = aws("cloudwatch", "list-metrics", "--namespace", "CWAgent", "--metric-name", m)
    print(f"#AGENT {m} series={len((r or {}).get('Metrics', []))}")
PY
echo
echo "Dashboard: https://$REGION.console.aws.amazon.com/cloudwatch/home?region=$REGION#dashboards/dashboard/CuraSecure-DevSecOps"
