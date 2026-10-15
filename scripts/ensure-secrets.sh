#!/usr/bin/env bash
# Create the application secrets ONCE per cluster with cryptographically random values.
# Values are never printed to the Jenkins log. Existing secrets are left untouched
# (rotating DATA_KEY would make previously encrypted data unreadable).
set -euo pipefail
NS=curasecure
if kubectl -n "$NS" get secret curasecure-secrets >/dev/null 2>&1; then
  echo "Secret curasecure-secrets already exists - keeping it"
  exit 0
fi
umask 077
kubectl -n "$NS" create secret generic curasecure-secrets \
  --from-literal=JWT_SECRET="$(openssl rand -hex 48)" \
  --from-literal=DATA_KEY="$(openssl rand -hex 32)" \
  --from-literal=DEMO_PASSWORD="Cura-$(openssl rand -hex 6)!" \
  >/dev/null
echo "Created secret curasecure-secrets (JWT_SECRET, DATA_KEY, DEMO_PASSWORD)"
