// DevSecOps pipeline for the CuraSecure healthcare portal
// GitHub -> Jenkins (security gates) -> Docker Hub -> Kubernetes (k3s, hardened) -> DAST
//
// Every scanner runs in a pinned Docker image, writes a JSON report to reports/, and
// scripts/secgate.py applies the gate policy. A failing gate stops the release.
//
// Jenkins prerequisites: credential "dockerhub-creds" (Docker Hub username + access token).

pipeline {
    agent any

    options {
        timestamps()
        disableConcurrentBuilds()
        buildDiscarder(logRotator(numToKeepStr: '20', artifactNumToKeepStr: '10'))
        timeout(time: 45, unit: 'MINUTES')
    }

    triggers { pollSCM('H/2 * * * *') }

    environment {
        APP        = 'curasecure'
        NS         = 'curasecure'
        PORT       = '30080'
        KUBECONFIG = '/var/lib/jenkins/.kube/config'
        DOCKER_HUB = credentials('dockerhub-creds')
        // Pinned scanner versions (reproducible, auditable tooling)
        TRIVY      = 'aquasec/trivy:0.75.0'
        GITLEAKS   = 'zricethezav/gitleaks:v8.30.0'
        SEMGREP    = 'semgrep/semgrep:1.180.0'
        ZAP        = 'ghcr.io/zaproxy/zaproxy:stable'
        NODE_IMG   = 'node:20-alpine'
        GATE       = 'python3 scripts/secgate.py'
    }

    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    env.GIT_SHORT = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    env.IMAGE     = "${env.DOCKER_HUB_USR}/${env.APP}"
                    env.TAG       = "${env.BUILD_NUMBER}-${env.GIT_SHORT}"
                    env.UIDGID    = sh(script: 'echo "$(id -u):$(id -g)"', returnStdout: true).trim()
                }
                sh '''
                    chmod +x scripts/*.sh scripts/*.py
                    rm -rf reports && mkdir -p reports && chmod 777 reports
                    mkdir -p "$HOME/.trivy-cache"
                '''
            }
        }

        stage('Secret Scan') {
            steps {
                sh '''
                    docker run --rm -u "$UIDGID" -v "$WORKSPACE":/repo -w /repo "$GITLEAKS" \
                      git --redact --no-banner --exit-code 0 \
                      --report-format json --report-path /repo/reports/gitleaks.json /repo
                    $GATE check secrets reports/gitleaks.json
                '''
            }
        }

        stage('SAST') {
            steps {
                sh '''
                    docker run --rm -u "$UIDGID" -e HOME=/tmp -v "$WORKSPACE":/src -w /src "$SEMGREP" \
                      semgrep scan --metrics=off --quiet \
                        --config p/owasp-top-ten --config p/javascript --config p/jwt \
                        --config security/semgrep-healthcare.yml \
                        --json --output reports/semgrep.json app/src app/server.js app/public/js || true
                    $GATE check sast reports/semgrep.json
                '''
            }
        }

        stage('Dependency Scan (SCA)') {
            steps {
                sh '''
                    docker run --rm -u "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$HOME/.trivy-cache":/cache \
                      -v "$WORKSPACE":/src -w /src "$TRIVY" \
                      fs --scanners vuln --format json --output reports/trivy-fs.json --quiet app
                    $GATE check sca reports/trivy-fs.json
                '''
            }
        }

        stage('IaC Scan') {
            steps {
                sh '''
                    docker run --rm -u "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$HOME/.trivy-cache":/cache \
                      -v "$WORKSPACE":/src -w /src "$TRIVY" \
                      config --format json --output reports/trivy-iac.json --quiet .
                    $GATE check iac reports/trivy-iac.json
                '''
            }
        }

        stage('Unit & Security Tests') {
            steps {
                sh '''
                    docker run --rm -u "$UIDGID" -e HOME=/tmp -v "$WORKSPACE":/w -w /w/app "$NODE_IMG" sh -c "
                      npm ci --no-audit --no-fund ;
                      node --test --test-reporter=tap test/*.test.js > /w/reports/tests.tap ;
                      npm audit --omit=dev --json > /w/reports/npm-audit.json ; true"
                    cat reports/tests.tap | grep -E '^(ok|not ok) ' || true
                    $GATE check tests reports/tests.tap
                    $GATE check npm reports/npm-audit.json
                '''
            }
        }

        stage('Build Image') {
            steps {
                sh 'docker build --pull --build-arg APP_VERSION="$TAG" -t "$IMAGE:$TAG" .'
            }
        }

        stage('Image Scan + SBOM') {
            steps {
                sh '''
                    docker save "$IMAGE:$TAG" -o reports/image.tar
                    docker run --rm -u "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$HOME/.trivy-cache":/cache \
                      -v "$WORKSPACE":/src -w /src "$TRIVY" \
                      image --input reports/image.tar --scanners vuln --format json --output reports/trivy-image.json --quiet
                    docker run --rm -u "$UIDGID" -e TRIVY_CACHE_DIR=/cache -v "$HOME/.trivy-cache":/cache \
                      -v "$WORKSPACE":/src -w /src "$TRIVY" \
                      image --input reports/image.tar --format cyclonedx --output reports/sbom.cdx.json --quiet
                    rm -f reports/image.tar
                    $GATE check image reports/trivy-image.json
                '''
            }
        }

        stage('Push Image') {
            steps {
                sh '''
                    echo "$DOCKER_HUB_PSW" | docker login -u "$DOCKER_HUB_USR" --password-stdin
                    docker push "$IMAGE:$TAG"
                '''
            }
        }

        stage('Deploy (hardened)') {
            steps {
                sh './scripts/deploy.sh "$IMAGE" "$TAG" "$BUILD_NUMBER" "$GIT_SHORT"'
            }
        }

        stage('DAST') {
            steps {
                sh '''
                    for i in $(seq 1 20); do curl -fsS "http://localhost:$PORT/healthz" && break; sleep 3; done
                    cp security/zap-rules.tsv reports/zap-rules.tsv
                    docker run --rm --network host -v "$WORKSPACE/reports":/zap/wrk:rw "$ZAP" \
                      zap-baseline.py -t "http://localhost:$PORT" -c zap-rules.tsv -m 2 -I \
                      -J zap.json -r zap.html || true
                '''
                script {
                    if (sh(script: '$GATE check dast reports/zap.json', returnStatus: true) != 0) {
                        sh 'kubectl -n "$NS" rollout undo deployment/curasecure || true'
                        error('DAST found High risk issues - deployment rolled back')
                    }
                }
            }
        }

        stage('Publish Security Report') {
            steps {
                sh '''
                    $GATE publish reports/security-summary.json "$BUILD_NUMBER" "$GIT_SHORT" "$IMAGE:$TAG"
                    kubectl -n "$NS" create configmap curasecure-security-report \
                      --from-file=security-summary.json=reports/security-summary.json \
                      --dry-run=client -o yaml | kubectl apply -f -
                '''
            }
        }
    }

    post {
        always {
            // Always produce the combined summary so blocked builds are documented too
            sh '[ -f reports/security-summary.json ] || $GATE publish reports/security-summary.json "$BUILD_NUMBER" "${GIT_SHORT:-unknown}" "blocked-before-push" || true'
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true, fingerprint: true
            sh 'docker logout || true; docker image prune -f || true'
        }
        success {
            echo "All security gates passed. Portal: http://<EC2_IP>:${env.PORT}"
        }
        failure {
            echo 'A security gate or stage failed. See the gate output above and the archived reports.'
        }
    }
}
