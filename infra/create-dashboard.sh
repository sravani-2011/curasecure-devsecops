#!/bin/bash
# Creates the "CuraSecure-DevSecOps" CloudWatch dashboard.
# Run in AWS CloudShell (or anywhere with AWS CLI + credentials for the lab account):
#     bash create-dashboard.sh                      # dashboard + log groups
#     bash create-dashboard.sh --attach-profile     # also attach LabInstanceProfile to the EC2 host if it has none
set -euo pipefail
REGION=${AWS_REGION:-${AWS_DEFAULT_REGION:-us-east-1}}
NAME=CuraSecure-DevSecOps
echo "Region: $REGION"

# Find the CuraSecure EC2 host (the running instance; prefer one whose Name contains curasecure/jenkins/devsecops)
read -r IID IP PROFILE < <(aws ec2 describe-instances --region "$REGION" \
  --filters Name=instance-state-name,Values=running \
  --query 'Reservations[].Instances[].[InstanceId, PublicIpAddress || `none`, IamInstanceProfile.Arn || `none`, (Tags[?Key==`Name`].Value)[0] || `-`]' \
  --output text | awk 'BEGIN{IGNORECASE=1} {line[NR]=$1" "$2" "$3; if ($4 ~ /curasecure|jenkins|devsecops/) pick=NR} END{if(!pick)pick=1; print line[pick]}') || true
IID=${IID:-none}; IP=${IP:-none}; PROFILE=${PROFILE:-none}
echo "EC2 host: $IID  public IP: $IP  instance profile: $PROFILE"

if [ "$IID" != "none" ] && [ "$PROFILE" = "none" ]; then
  if [ "${1:-}" = "--attach-profile" ]; then
    aws ec2 associate-iam-instance-profile --region "$REGION" --instance-id "$IID" \
      --iam-instance-profile Name=LabInstanceProfile >/dev/null && echo "Attached LabInstanceProfile to $IID"
  else
    echo "NOTE: $IID has no IAM instance profile, so it cannot send metrics yet."
    echo "      Re-run with --attach-profile, or EC2 > Actions > Security > Modify IAM role > LabInstanceProfile."
  fi
fi

# Log groups the dashboard queries (created empty so the log widgets don't error before the first build)
for LG in /curasecure/pipeline /curasecure/ec2; do
  aws logs create-log-group --region "$REGION" --log-group-name "$LG" 2>/dev/null || true
  aws logs put-retention-policy --region "$REGION" --log-group-name "$LG" --retention-in-days 30
done

BODY=$(mktemp)
cat > "$BODY" <<'DASHBOARD'
{
 "start": "-P7D",
 "periodOverride": "inherit",
 "widgets": [
  {
   "type": "text",
   "x": 0,
   "y": 0,
   "width": 24,
   "height": 3,
   "properties": {
    "markdown": "# CuraSecure \u2014 DevSecOps Healthcare Pipeline\nGitHub \u2192 **Jenkins (12 stages, 8 security gates)** \u2192 Docker Hub \u2192 **k3s (hardened)** \u2192 OWASP ZAP \u00b7 single EC2 host \u00b7 synthetic patient data only. Gate status: **0 = pass \u00b7 1 = warn \u00b7 2 = BLOCKED**. [Jenkins](http://EC2_PUBLIC_IP:8080) \u00b7 [Portal](http://EC2_PUBLIC_IP:30080) \u00b7 [Security Center](http://EC2_PUBLIC_IP:30080/security.html)"
   }
  },
  {
   "type": "metric",
   "x": 0,
   "y": 3,
   "width": 12,
   "height": 4,
   "properties": {
    "title": "Latest release",
    "view": "singleValue",
    "region": "${REGION}",
    "stat": "Maximum",
    "period": 60,
    "setPeriodToTimeRange": false,
    "sparkline": true,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "BuildNumber",
      "Pipeline",
      "curasecure",
      {
       "label": "Build #"
      }
     ],
     [
      ".",
      "PipelineSucceeded",
      ".",
      ".",
      {
       "label": "Succeeded (1/0)"
      }
     ],
     [
      ".",
      "GatesFailed",
      ".",
      ".",
      {
       "label": "Gates blocked"
      }
     ],
     [
      ".",
      "TotalFindings",
      ".",
      ".",
      {
       "label": "Findings"
      }
     ],
     [
      ".",
      "PipelineDurationSeconds",
      ".",
      ".",
      {
       "label": "Duration (s)"
      }
     ]
    ]
   }
  },
  {
   "type": "metric",
   "x": 12,
   "y": 3,
   "width": 12,
   "height": 4,
   "properties": {
    "title": "Live portal & cluster (1-min probe)",
    "view": "singleValue",
    "region": "${REGION}",
    "stat": "Average",
    "period": 60,
    "sparkline": true,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "PortalUp",
      "Pipeline",
      "curasecure",
      {
       "label": "Portal up (1/0)",
       "stat": "Minimum"
      }
     ],
     [
      ".",
      "PortalLatencyMs",
      ".",
      ".",
      {
       "label": "/healthz latency (ms)"
      }
     ],
     [
      ".",
      "ReadyPods",
      ".",
      ".",
      {
       "label": "Ready pods",
       "stat": "Minimum"
      }
     ],
     [
      ".",
      "TestsPassed",
      ".",
      ".",
      {
       "label": "Tests passed",
       "stat": "Maximum"
      }
     ],
     [
      ".",
      "SbomComponents",
      ".",
      ".",
      {
       "label": "SBOM components",
       "stat": "Maximum"
      }
     ]
    ]
   }
  },
  {
   "type": "metric",
   "x": 0,
   "y": 7,
   "width": 24,
   "height": 4,
   "properties": {
    "title": "Security gates \u2014 latest build (0 pass \u00b7 1 warn \u00b7 2 blocked)",
    "view": "singleValue",
    "region": "${REGION}",
    "stat": "Maximum",
    "period": 60,
    "setPeriodToTimeRange": false,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "secrets",
      {
       "label": "Secrets \u00b7 Gitleaks"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "sast",
      {
       "label": "SAST \u00b7 Semgrep"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "sca",
      {
       "label": "SCA \u00b7 Trivy fs"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "iac",
      {
       "label": "IaC \u00b7 Trivy config"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "tests",
      {
       "label": "Tests \u00b7 node:test"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "npm",
      {
       "label": "npm audit"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "image",
      {
       "label": "Image \u00b7 Trivy"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateStatus",
      "Gate",
      "dast",
      {
       "label": "DAST \u00b7 ZAP"
      }
     ]
    ]
   }
  },
  {
   "type": "metric",
   "x": 0,
   "y": 11,
   "width": 12,
   "height": 6,
   "properties": {
    "title": "Findings by severity per build",
    "view": "timeSeries",
    "stacked": true,
    "region": "${REGION}",
    "stat": "Maximum",
    "period": 300,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "Findings",
      "Severity",
      "critical",
      {
       "label": "Critical",
       "color": "#7b1fa2"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "Findings",
      "Severity",
      "high",
      {
       "label": "High",
       "color": "#d62728"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "Findings",
      "Severity",
      "medium",
      {
       "label": "Medium",
       "color": "#ff7f0e"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "Findings",
      "Severity",
      "low",
      {
       "label": "Low",
       "color": "#2ca02c"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "Findings",
      "Severity",
      "info",
      {
       "label": "Info",
       "color": "#7f7f7f"
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "label": "findings",
      "showUnits": false
     }
    }
   }
  },
  {
   "type": "metric",
   "x": 12,
   "y": 11,
   "width": 12,
   "height": 6,
   "properties": {
    "title": "Findings by gate (selected time range)",
    "view": "bar",
    "region": "${REGION}",
    "stat": "Maximum",
    "period": 300,
    "setPeriodToTimeRange": true,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "secrets",
      {
       "label": "Secrets \u00b7 Gitleaks"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "sast",
      {
       "label": "SAST \u00b7 Semgrep"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "sca",
      {
       "label": "SCA \u00b7 Trivy fs"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "iac",
      {
       "label": "IaC \u00b7 Trivy config"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "tests",
      {
       "label": "Tests \u00b7 node:test"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "npm",
      {
       "label": "npm audit"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "image",
      {
       "label": "Image \u00b7 Trivy"
      }
     ],
     [
      "CuraSecure/DevSecOps",
      "GateFindings",
      "Gate",
      "dast",
      {
       "label": "DAST \u00b7 ZAP"
      }
     ]
    ]
   }
  },
  {
   "type": "metric",
   "x": 0,
   "y": 17,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "Pipeline outcome (1 = released, 0 = blocked)",
    "view": "timeSeries",
    "region": "${REGION}",
    "stat": "Maximum",
    "period": 300,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "PipelineSucceeded",
      "Pipeline",
      "curasecure",
      {
       "label": "Succeeded",
       "color": "#2ca02c"
      }
     ],
     [
      ".",
      "GatesFailed",
      ".",
      ".",
      {
       "label": "Gates blocked",
       "color": "#d62728",
       "yAxis": "right"
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "max": 1,
      "showUnits": false
     },
     "right": {
      "min": 0,
      "showUnits": false
     }
    }
   }
  },
  {
   "type": "metric",
   "x": 8,
   "y": 17,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "Pipeline duration",
    "view": "timeSeries",
    "region": "${REGION}",
    "stat": "Maximum",
    "period": 300,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "PipelineDurationSeconds",
      "Pipeline",
      "curasecure",
      {
       "label": "seconds"
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "showUnits": false
     }
    }
   }
  },
  {
   "type": "metric",
   "x": 16,
   "y": 17,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "Portal availability & latency",
    "view": "timeSeries",
    "region": "${REGION}",
    "period": 60,
    "metrics": [
     [
      "CuraSecure/DevSecOps",
      "PortalUp",
      "Pipeline",
      "curasecure",
      {
       "label": "Up (min)",
       "stat": "Minimum",
       "color": "#2ca02c"
      }
     ],
     [
      ".",
      "PortalLatencyMs",
      ".",
      ".",
      {
       "label": "Latency ms",
       "stat": "Average",
       "yAxis": "right"
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "max": 1,
      "showUnits": false
     },
     "right": {
      "min": 0,
      "showUnits": false
     }
    }
   }
  },
  {
   "type": "text",
   "x": 0,
   "y": 23,
   "width": 24,
   "height": 1,
   "properties": {
    "markdown": "### EC2 host \u2014 Jenkins + k3s + scanners (t3.large, encrypted EBS, IMDSv2)"
   }
  },
  {
   "type": "metric",
   "x": 0,
   "y": 24,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "CPU utilization",
    "view": "timeSeries",
    "region": "${REGION}",
    "stat": "Average",
    "period": 300,
    "metrics": [
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUUtilization\"', 'Average', 300)",
       "id": "cpu",
       "label": ""
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "max": 100
     }
    }
   }
  },
  {
   "type": "metric",
   "x": 8,
   "y": 24,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "Memory / swap / disk used % (CloudWatch agent)",
    "view": "timeSeries",
    "region": "${REGION}",
    "period": 300,
    "metrics": [
     [
      {
       "expression": "SEARCH('Namespace=\"CWAgent\" MetricName=\"mem_used_percent\"', 'Average', 300)",
       "id": "mem",
       "label": "Memory"
      }
     ],
     [
      {
       "expression": "SEARCH('Namespace=\"CWAgent\" MetricName=\"swap_used_percent\"', 'Average', 300)",
       "id": "swap",
       "label": "Swap"
      }
     ],
     [
      {
       "expression": "SEARCH('Namespace=\"CWAgent\" MetricName=\"disk_used_percent\"', 'Average', 300)",
       "id": "disk",
       "label": "Disk /"
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "max": 100
     }
    }
   }
  },
  {
   "type": "metric",
   "x": 16,
   "y": 24,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "Network (image pulls / pushes)",
    "view": "timeSeries",
    "region": "${REGION}",
    "period": 300,
    "metrics": [
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"NetworkIn\"', 'Sum', 300)",
       "id": "nin",
       "label": "In"
      }
     ],
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"NetworkOut\"', 'Sum', 300)",
       "id": "nout",
       "label": "Out"
      }
     ]
    ]
   }
  },
  {
   "type": "metric",
   "x": 0,
   "y": 30,
   "width": 8,
   "height": 4,
   "properties": {
    "title": "Status checks failed",
    "view": "timeSeries",
    "region": "${REGION}",
    "period": 300,
    "metrics": [
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"StatusCheckFailed\"', 'Maximum', 300)",
       "id": "sc",
       "label": ""
      }
     ]
    ],
    "yAxis": {
     "left": {
      "min": 0,
      "max": 1
     }
    }
   }
  },
  {
   "type": "metric",
   "x": 8,
   "y": 30,
   "width": 8,
   "height": 4,
   "properties": {
    "title": "EBS throughput",
    "view": "timeSeries",
    "region": "${REGION}",
    "period": 300,
    "metrics": [
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"EBSWriteBytes\"', 'Sum', 300)",
       "id": "ebw",
       "label": "Write"
      }
     ],
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"EBSReadBytes\"', 'Sum', 300)",
       "id": "ebr",
       "label": "Read"
      }
     ]
    ]
   }
  },
  {
   "type": "metric",
   "x": 16,
   "y": 30,
   "width": 8,
   "height": 4,
   "properties": {
    "title": "CPU credit balance (burstable t3)",
    "view": "timeSeries",
    "region": "${REGION}",
    "period": 300,
    "metrics": [
     [
      {
       "expression": "SEARCH('{AWS/EC2,InstanceId} MetricName=\"CPUCreditBalance\"', 'Average', 300)",
       "id": "cc",
       "label": ""
      }
     ]
    ]
   }
  },
  {
   "type": "log",
   "x": 0,
   "y": 34,
   "width": 24,
   "height": 7,
   "properties": {
    "title": "Gate results per build (log group /curasecure/pipeline)",
    "region": "${REGION}",
    "view": "table",
    "query": "SOURCE '/curasecure/pipeline' | fields @timestamp, build, commit, gate, tool, status, critical, high, medium, low, topFinding | filter type = 'gate' | sort @timestamp desc, gate asc | limit 80"
   }
  },
  {
   "type": "log",
   "x": 0,
   "y": 41,
   "width": 16,
   "height": 6,
   "properties": {
    "title": "Build history",
    "region": "${REGION}",
    "view": "table",
    "query": "SOURCE '/curasecure/pipeline' | fields @timestamp, build, commit, result, gatesFailed, critical, high, medium, durationSec, sbomComponents, image | filter type = 'build' | sort @timestamp desc | limit 30"
   }
  },
  {
   "type": "log",
   "x": 16,
   "y": 41,
   "width": 8,
   "height": 6,
   "properties": {
    "title": "Portal health probe (last events)",
    "region": "${REGION}",
    "view": "table",
    "query": "SOURCE '/curasecure/ec2' | fields @timestamp, @message | filter @logStream like /health/ | sort @timestamp desc | limit 20"
   }
  }
 ]
}
DASHBOARD
sed -i -e "s|\${REGION}|$REGION|g" -e "s|EC2_PUBLIC_IP|$IP|g" "$BODY"
aws cloudwatch put-dashboard --region "$REGION" --dashboard-name "$NAME" --dashboard-body "file://$BODY"
rm -f "$BODY"
echo
echo "Dashboard ready: https://$REGION.console.aws.amazon.com/cloudwatch/home?region=$REGION#dashboards/dashboard/$NAME"
