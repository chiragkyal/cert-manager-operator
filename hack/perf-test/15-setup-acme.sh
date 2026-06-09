#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Setting Up Local ACME Server (Pebble) ==="
echo ""
echo "Pebble is a lightweight ACME server for testing."
echo "It runs in-cluster and validates challenges instantly"
echo "(PEBBLE_VA_ALWAYS_VALID=1) to isolate cert-manager performance."
echo ""

# Deploy Pebble
echo "[1/4] Deploying Pebble ACME server..."
oc apply -f "${SCRIPT_DIR}/manifests/pebble.yaml"

echo "[2/4] Waiting for Pebble pod to be ready..."
oc wait --for=condition=Available deployment/pebble -n pebble --timeout=120s

echo "[3/4] Verifying Pebble is responding..."
PEBBLE_POD=$(oc get pods -n pebble -l app=pebble -o jsonpath='{.items[0].metadata.name}')
for i in $(seq 1 12); do
    if oc exec -n pebble "${PEBBLE_POD}" -- wget -q --no-check-certificate -O - https://localhost:14000/dir 2>/dev/null | grep -q "newAccount"; then
        echo "  Pebble ACME directory is live."
        break
    fi
    echo "  Waiting for Pebble... ($i/12)"
    sleep 5
done

echo "[4/4] Verifying ClusterIssuer..."
sleep 5
oc get clusterissuer perf-test-acme-pebble

echo ""
echo "=== ACME Setup Complete ==="
echo ""
echo "ClusterIssuer: perf-test-acme-pebble"
echo "ACME Server:   https://pebble.pebble.svc.cluster.local:14000/dir"
echo ""
echo "NOTE: Pebble is configured with PEBBLE_VA_ALWAYS_VALID=1"
echo "This means challenges are validated instantly without actual"
echo "HTTP01/DNS01 solving. This isolates cert-manager's challenge"
echo "orchestration performance from external solver latency."
echo ""
echo "To test ACME issuance:"
echo "  ./16-run-acme-test.sh baseline 100"
echo "  ./16-run-acme-test.sh aggressive 100"
