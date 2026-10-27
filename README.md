# CuraSecure — Secure DevOps (DevSecOps) Implementation in a Healthcare System

A **fictional** patient portal (synthetic data only) with security built into the application, the
infrastructure **and** every stage of the Jenkins CI/CD pipeline.

## Pipeline — security gates (Jenkinsfile)
| # | Stage | Tool (pinned) | Gate policy |
|---|---|---|---|
| 1 | Checkout | git | – |
| 2 | Secret Scan | Gitleaks v8.30.0 | block on any secret in code or git history |
| 3 | SAST | Semgrep 1.180.0 (OWASP Top 10, JavaScript, JWT + custom healthcare rules) | block on ERROR |
| 4 | Dependency Scan (SCA) | Trivy 0.75.0 `fs` | block on fixable HIGH/CRITICAL |
| 5 | IaC Scan | Trivy `config` (Dockerfile + Kubernetes YAML) | block on HIGH/CRITICAL misconfiguration |
| 6 | Unit & Security Tests + npm audit | node:test (15 tests) | block on any failure / critical dependency |
| 7 | Build Image | Docker (multi-stage, non-root, no npm in runtime) | – |
| 8 | Image Scan + SBOM | Trivy `image` + CycloneDX SBOM | block on fixable CRITICAL |
| 9 | Push Image | Docker Hub (Jenkins credential) | – |
| 10 | Deploy (hardened) | kubectl → k3s | auto-rollback if rollout fails |
| 11 | DAST | OWASP ZAP baseline | block + **rollback** on High risk |
| 12 | Publish Security Report | `scripts/secgate.py` → ConfigMap | shown in the portal's **Security Center** |

All raw reports (`reports/*.json`, `zap.html`, `sbom.cdx.json`) are archived as Jenkins build artifacts.

## Application security controls
- **Authentication**: bcrypt hashes, JWT (HS256, issuer + algorithm pinned, 30 min) in HttpOnly SameSite=Strict cookie, login rate limiting, account lockout after 5 failures, constant-time user lookup
- **RBAC / minimum necessary**: doctor (full), nurse (masked identifiers, no physician notes), admin (no clinical data, audit only)
- **Encryption at rest**: AES-256-GCM per field (national ID, phone, address, diagnosis, notes); key from Kubernetes Secret
- **Audit trail**: every PHI access, denial and login, SHA-256 hash-chained (tamper-evident), no PHI in logs
- **Web hardening**: strict CSP (no inline JS/CSS, no third-party), frame-ancestors none, nosniff, no-referrer, Permissions-Policy, CSRF origin check, JSON-only writes, 10 KB body limit, allow-list validation, generic errors
- **Fail closed**: the app refuses to start in production without its secrets

## Platform hardening (k8s/)
Pod Security Admission `restricted` · non-root UID 10001 · read-only root FS · drop ALL capabilities ·
no privilege escalation · seccomp RuntimeDefault · no service-account token · default-deny NetworkPolicy
(ingress only on 3000, **no egress**) · resource limits · PodDisruptionBudget · secrets generated per cluster.
EC2: encrypted EBS volume, IMDSv2 required.

## Setup
1. EC2 (Ubuntu 24.04, t3.large, 30 GB encrypted) with `infra/ec2-bootstrap.sh` as user data; SG ports 22, 8080, 30081.
2. Push this folder's **contents** to a GitHub repo (top level must show `Jenkinsfile`, `app/`, `k8s/` …).
3. Jenkins: unlock, install suggested plugins, add credential `dockerhub-creds` (Docker Hub user + access token).
4. Pipeline job from SCM → `Jenkinsfile` → **Build Now**.
5. Demo password: `kubectl -n curasecure get secret curasecure-secrets -o jsonpath='{.data.DEMO_PASSWORD}' | base64 -d; echo`
6. Portal: `http://<EC2_IP>:30081` → sign in as `dr.mehta`, `nurse.priya` or `admin.rao`.

## Demo: watch a gate block a release
Add `const key = Math.random(); eval(req.query.x);` to `app/src/app.js` and push. The **SAST** gate fails
(eval-usage) and Jenkins stops before building the image. Revert the change and the pipeline goes green.
