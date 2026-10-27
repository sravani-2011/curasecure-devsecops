#!/bin/bash
# EC2 user-data bootstrap for Ubuntu 24.04 (t3.medium or larger, 20+ GB disk)
# DevSecOps Healthcare project (CuraSecure). Installs: Docker, Jenkins LTS (Java 21), k3s,
# kubectl access for Jenkins, and pre-pulls the security scanner images.
# Log: /var/log/bootstrap.log   Done marker: /var/log/bootstrap.done
set -euxo pipefail
exec > >(tee -a /var/log/bootstrap.log) 2>&1
export DEBIAN_FRONTEND=noninteractive

# ---- Swap (Jenkins + k3s + builds on 4 GB RAM) ----
if [ ! -f /swapfile ]; then
  fallocate -l 2G /swapfile && chmod 600 /swapfile && mkswap /swapfile && swapon /swapfile
  echo '/swapfile none swap sw 0 0' >> /etc/fstab
fi

apt-get update -y
apt-get install -y ca-certificates curl gnupg git fontconfig python3 openssl openjdk-21-jre

# ---- Docker ----
install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" \
  > /etc/apt/sources.list.d/docker.list

# ---- Jenkins LTS ----
curl -fsSL https://pkg.jenkins.io/debian-stable/jenkins.io-2026.key -o /etc/apt/keyrings/jenkins-keyring.asc
echo "deb [signed-by=/etc/apt/keyrings/jenkins-keyring.asc] https://pkg.jenkins.io/debian-stable binary/" \
  > /etc/apt/sources.list.d/jenkins.list

apt-get update -y
apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin jenkins
systemctl enable --now docker
usermod -aG docker jenkins
usermod -aG docker ubuntu || true

# ---- k3s (single-node Kubernetes, includes kubectl) ----
curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--write-kubeconfig-mode 644 --disable traefik --kubelet-arg=sync-frequency=10s" sh -
until kubectl get nodes 2>/dev/null | grep -q ' Ready'; do sleep 5; done

# Give Jenkins and the ubuntu user a kubeconfig
for H in /var/lib/jenkins /home/ubuntu; do
  mkdir -p "$H/.kube"
  cp /etc/rancher/k3s/k3s.yaml "$H/.kube/config"
done
chown -R jenkins:jenkins /var/lib/jenkins/.kube
chown -R ubuntu:ubuntu /home/ubuntu/.kube
chmod 600 /var/lib/jenkins/.kube/config /home/ubuntu/.kube/config

systemctl enable jenkins
systemctl restart jenkins

# Pre-pull pinned security scanner images so the first pipeline run is fast
for IMG in aquasec/trivy:0.75.0 zricethezav/gitleaks:v8.30.0 semgrep/semgrep:1.180.0 ghcr.io/zaproxy/zaproxy:stable node:20-alpine; do
  docker pull "$IMG" || echo "WARN: could not pull $IMG"
done

date > /var/log/bootstrap.done
echo "Bootstrap complete. Jenkins: http://<public-ip>:8080  Portal: http://<public-ip>:30081"
