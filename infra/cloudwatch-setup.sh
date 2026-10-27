#!/bin/bash
# One-time CloudWatch setup ON THE EC2 HOST (run with sudo after ec2-bootstrap.sh has finished).
#   sudo bash infra/cloudwatch-setup.sh
# Requires the instance to have an IAM instance profile allowing CloudWatch + CloudWatch Logs
# (in AWS Academy Learner Lab: LabInstanceProfile).
#
# Installs: AWS CLI v2, Amazon CloudWatch agent (memory, disk, swap, Jenkins/bootstrap logs),
# and a 1-minute health probe that publishes PortalUp / PortalLatencyMs / ReadyPods.
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive

TOKEN=$(curl -fsS -X PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 300')
md() { curl -fsS -H "X-aws-ec2-metadata-token: $TOKEN" "http://169.254.169.254/latest/meta-data/$1"; }
REGION=$(md placement/region)
INSTANCE_ID=$(md instance-id)
if ! md iam/security-credentials/ >/dev/null 2>&1; then
  echo "ERROR: no IAM instance profile attached. Attach LabInstanceProfile (EC2 > Actions > Security > Modify IAM role) and re-run."
  exit 1
fi

# ---- AWS CLI v2 ----
apt-get update -y && apt-get install -y unzip curl
if ! command -v aws >/dev/null; then
  ARCH=$(uname -m)
  curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-${ARCH}.zip" -o /tmp/awscliv2.zip
  unzip -qo /tmp/awscliv2.zip -d /tmp && /tmp/aws/install --update && rm -rf /tmp/aws /tmp/awscliv2.zip
fi

# Region for the jenkins user and root
echo "AWS_DEFAULT_REGION=$REGION" > /etc/default/curasecure-aws
grep -q AWS_DEFAULT_REGION /etc/environment || echo "AWS_DEFAULT_REGION=$REGION" >> /etc/environment

# ---- CloudWatch agent ----
DEB_ARCH=$(dpkg --print-architecture)
curl -fsSL "https://amazoncloudwatch-agent.s3.amazonaws.com/ubuntu/${DEB_ARCH}/latest/amazon-cloudwatch-agent.deb" -o /tmp/cwagent.deb
dpkg -i -E /tmp/cwagent.deb && rm -f /tmp/cwagent.deb

mkdir -p /opt/aws/amazon-cloudwatch-agent/etc
cat > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json <<'JSON'
{
  "agent": { "metrics_collection_interval": 60, "run_as_user": "root" },
  "metrics": {
    "namespace": "CWAgent",
    "append_dimensions": { "InstanceId": "${aws:InstanceId}" },
    "metrics_collected": {
      "mem":  { "measurement": ["mem_used_percent"] },
      "swap": { "measurement": ["swap_used_percent"] },
      "disk": { "measurement": ["disk_used_percent"], "resources": ["/"], "drop_device": true,
                "ignore_file_system_types": ["tmpfs", "overlay", "squashfs", "devtmpfs"] }
    }
  },
  "logs": {
    "logs_collected": { "files": { "collect_list": [
      { "file_path": "/var/log/bootstrap.log", "log_group_name": "/curasecure/ec2", "log_stream_name": "{instance_id}/bootstrap", "retention_in_days": 30 },
      { "file_path": "/var/log/curasecure-health.log", "log_group_name": "/curasecure/ec2", "log_stream_name": "{instance_id}/health", "retention_in_days": 30 }
    ] } }
  }
}
JSON
/opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 \
  -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

# ---- 1-minute portal / Kubernetes health probe ----
cat > /usr/local/bin/curasecure-health.sh <<'SH'
#!/bin/bash
# Publishes PortalUp (1/0), PortalLatencyMs and ReadyPods to CuraSecure/DevSecOps
. /etc/default/curasecure-aws
export AWS_DEFAULT_REGION
OUT=$(curl -s -o /dev/null -w '%{http_code} %{time_total}' --max-time 5 http://localhost:30081/healthz)
CODE=${OUT%% *}; SECS=${OUT##* }
UP=0; [ "$CODE" = "200" ] && UP=1
MS=$(awk -v s="$SECS" 'BEGIN{printf "%.0f", s*1000}')
READY=$(KUBECONFIG=/etc/rancher/k3s/k3s.yaml kubectl -n curasecure get deploy curasecure -o jsonpath='{.status.readyReplicas}' 2>/dev/null)
READY=${READY:-0}
D="Name=Pipeline,Value=curasecure"
/usr/local/bin/aws cloudwatch put-metric-data --namespace CuraSecure/DevSecOps --metric-data \
  "MetricName=PortalUp,Dimensions=[{$D}],Value=$UP,Unit=Count" \
  "MetricName=PortalLatencyMs,Dimensions=[{$D}],Value=$MS,Unit=Milliseconds" \
  "MetricName=ReadyPods,Dimensions=[{$D}],Value=$READY,Unit=Count" >/dev/null 2>&1
echo "$(date -u +%FT%TZ) http=$CODE up=$UP latency_ms=$MS ready_pods=$READY" >> /var/log/curasecure-health.log
SH
chmod 755 /usr/local/bin/curasecure-health.sh
touch /var/log/curasecure-health.log
echo '* * * * * root /usr/local/bin/curasecure-health.sh' > /etc/cron.d/curasecure-health
chmod 644 /etc/cron.d/curasecure-health

# No Jenkins restart needed: scripts/cw-publish.py reads the region from IMDSv2.
/usr/local/bin/curasecure-health.sh || true
echo "CloudWatch monitoring ready for $INSTANCE_ID in $REGION."
echo "Next: create the dashboard (run infra/create-dashboard.sh in AWS CloudShell)."
