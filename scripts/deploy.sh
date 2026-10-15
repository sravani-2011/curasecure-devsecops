#!/usr/bin/env bash
# Apply the hardened manifests and roll out the scanned image.
set -euo pipefail
IMAGE=$1 TAG=$2 BUILD=$3 COMMIT=$4   # IMAGE = repository without tag
kubectl apply -f k8s/namespace.yaml
kubectl apply -f k8s/serviceaccount.yaml -f k8s/networkpolicy.yaml -f k8s/pdb.yaml -f k8s/service.yaml
./scripts/ensure-secrets.sh
sed -e "s|IMAGE_PLACEHOLDER|$IMAGE|g" -e "s|VERSION_PLACEHOLDER|$TAG|g" \
    -e "s|BUILD_PLACEHOLDER|$BUILD|g" -e "s|COMMIT_PLACEHOLDER|$COMMIT|g" k8s/deployment.yaml \
  | kubectl apply -f -
if ! kubectl -n curasecure rollout status deployment/curasecure --timeout=180s; then
  echo "Rollout failed - rolling back"
  kubectl -n curasecure rollout undo deployment/curasecure || true
  exit 1
fi
kubectl -n curasecure get pods -o wide
