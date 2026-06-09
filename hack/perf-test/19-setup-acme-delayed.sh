#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Setting Up Pebble ACME Server (WITH Validation Delay) ==="
echo ""
echo "This variant does NOT set PEBBLE_VA_ALWAYS_VALID."
echo "Pebble will actually attempt to validate HTTP01 challenges,"
echo "introducing realistic latency that exercises --dns01-check-retry-period."
echo ""
echo "The validation delay simulates a real ACME server where:"
echo "  - Challenge propagation takes time"
echo "  - cert-manager must poll/retry until the challenge is valid"
echo "  - --dns01-check-retry-period controls the retry interval"
echo ""

cat <<'EOF' | oc apply -f -
apiVersion: v1
kind: Namespace
metadata:
  name: pebble-delayed
  labels:
    purpose: acme-test-server-delayed
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: pebble-config
  namespace: pebble-delayed
data:
  pebble-config.json: |
    {
      "pebble": {
        "listenAddress": "0.0.0.0:14000",
        "managementListenAddress": "0.0.0.0:15000",
        "certificate": "/test/certs/localhost/cert.pem",
        "privateKey": "/test/certs/localhost/key.pem",
        "httpPort": 5002,
        "tlsPort": 5001,
        "ocspResponderURL": "",
        "externalAccountBindingRequired": false,
        "domainBlocklist": [],
        "retryAfter": {
          "authz": 3,
          "order": 5
        }
      }
    }
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: pebble
  namespace: pebble-delayed
spec:
  replicas: 1
  selector:
    matchLabels:
      app: pebble-delayed
  template:
    metadata:
      labels:
        app: pebble-delayed
    spec:
      containers:
        - name: pebble
          image: ghcr.io/letsencrypt/pebble:latest
          command: ["/app"]
          args:
            - -config
            - /etc/pebble/pebble-config.json
            - -dnsserver
            - 127.0.0.1:8053
          env:
            - name: PEBBLE_VA_NOSLEEP
              value: "0"
          ports:
            - containerPort: 14000
              name: acme
            - containerPort: 15000
              name: management
          volumeMounts:
            - name: config
              mountPath: /etc/pebble
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
      volumes:
        - name: config
          configMap:
            name: pebble-config
---
apiVersion: v1
kind: Service
metadata:
  name: pebble
  namespace: pebble-delayed
spec:
  selector:
    app: pebble-delayed
  ports:
    - name: acme
      port: 14000
      targetPort: 14000
    - name: management
      port: 15000
      targetPort: 15000
---
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: perf-test-acme-pebble-delayed
spec:
  acme:
    server: https://pebble.pebble-delayed.svc.cluster.local:14000/dir
    skipTLSVerify: true
    privateKeySecretRef:
      name: perf-test-acme-delayed-account-key
    solvers:
      - http01:
          ingress:
            ingressClassName: openshift-default
EOF

echo ""
echo "Waiting for Pebble (delayed) to start..."
oc wait --for=condition=Available deployment/pebble -n pebble-delayed --timeout=120s

echo ""
echo "Waiting for ClusterIssuer registration..."
for i in $(seq 1 24); do
    STATUS=$(oc get clusterissuer perf-test-acme-pebble-delayed -o jsonpath='{.status.conditions[0].status}' 2>/dev/null)
    if [[ "$STATUS" == "True" ]]; then
        echo "  ClusterIssuer ready!"
        break
    fi
    echo "  [$i] Waiting... (status=$STATUS)"
    sleep 5
done

echo ""
echo "=== Pebble (Delayed Validation) Setup Complete ==="
echo ""
echo "Key differences from standard Pebble:"
echo "  - No PEBBLE_VA_ALWAYS_VALID (challenges actually verified)"
echo "  - PEBBLE_VA_NOSLEEP=0 (realistic timing)"
echo "  - retryAfter.authz=3s, retryAfter.order=5s"
echo ""
echo "This tests how --dns01-check-retry-period affects throughput:"
echo "  - Default (10s): cert-manager polls every 10s for challenge completion"
echo "  - Tuned (2-5s): More frequent polling, faster detection of completion"
echo ""
echo "Next: Run ./18-run-acme-scale.sh <scenario> <num-certs> --with-delay"
