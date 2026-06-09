#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"

echo "=== cert-manager Performance Test Setup ==="
echo ""

# Check prerequisites
if ! command -v oc &>/dev/null; then
    echo "ERROR: 'oc' CLI not found in PATH"
    exit 1
fi

if ! command -v jq &>/dev/null; then
    echo "ERROR: 'jq' not found in PATH"
    exit 1
fi

if ! oc whoami &>/dev/null; then
    echo "ERROR: Not logged into OpenShift cluster. Run 'oc login' first."
    exit 1
fi

echo "Cluster: $(oc whoami --show-server)"
echo "User:    $(oc whoami)"
echo ""

# Verify cert-manager operator is installed
if ! oc get certmanager cluster &>/dev/null; then
    echo "ERROR: CertManager CR 'cluster' not found. Is cert-manager-operator installed?"
    exit 1
fi

echo "[1/4] Creating test namespace..."
oc apply -f "${SCRIPT_DIR}/manifests/namespace.yaml"

echo "[2/4] Waiting for namespace to be active..."
oc wait --for=jsonpath='{.status.phase}'=Active "namespace/${NAMESPACE}" --timeout=30s

echo "[3/4] Creating test issuers (self-signed CA chain)..."
oc apply -f "${SCRIPT_DIR}/manifests/selfsigned-issuer.yaml"

echo "[4/4] Waiting for CA certificate to be ready..."
oc wait --for=condition=Ready certificate/perf-test-ca -n "${NAMESPACE}" --timeout=120s

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Issuers available:"
oc get clusterissuers perf-test-selfsigned -n "${NAMESPACE}" 2>/dev/null || true
oc get issuers -n "${NAMESPACE}"
echo ""
echo "Current cert-manager controller args:"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq .
echo ""
echo "Current cert-manager controller resources:"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq .
echo ""
echo "Next: Run './02-run-test.sh baseline 100' to start baseline test"
