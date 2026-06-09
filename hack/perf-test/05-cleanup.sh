#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"

echo "=== cert-manager Performance Test Cleanup ==="
echo ""

CLEAN_RESULTS=false
RESET_PARAMS=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --all)
            CLEAN_RESULTS=true
            RESET_PARAMS=true
            shift
            ;;
        --results)
            CLEAN_RESULTS=true
            shift
            ;;
        --reset-params)
            RESET_PARAMS=true
            shift
            ;;
        --help|-h)
            echo "Usage: $0 [--all] [--results] [--reset-params]"
            echo ""
            echo "  (no flags)     Clean test certificates and namespace only"
            echo "  --reset-params Also reset CertManager CR to baseline (defaults)"
            echo "  --results      Also remove results directory"
            echo "  --all          Clean everything (certs + params + results)"
            exit 0
            ;;
        *)
            echo "Unknown flag: $1"
            exit 1
            ;;
    esac
done

echo "[1/4] Deleting test certificates..."
oc delete certificates -n "${NAMESPACE}" -l perf-test=true --ignore-not-found=true 2>/dev/null || true

echo "[2/4] Deleting test secrets..."
oc delete secrets -n "${NAMESPACE}" -l perf-test=true --ignore-not-found=true 2>/dev/null || true
# Also clean the auto-generated secrets
oc delete secrets -n "${NAMESPACE}" -l "cert-manager.io/certificate-name" --ignore-not-found=true 2>/dev/null || true

echo "[3/4] Deleting test namespace and issuers..."
oc delete clusterissuer perf-test-selfsigned --ignore-not-found=true 2>/dev/null || true
oc delete namespace "${NAMESPACE}" --ignore-not-found=true 2>/dev/null || true

if [[ "${RESET_PARAMS}" == "true" ]]; then
    echo "[4/4] Resetting CertManager CR to baseline..."
    oc apply -f "${SCRIPT_DIR}/scenarios/baseline.yaml"
    echo "  Waiting for rollout..."
    sleep 10
    oc rollout status deployment/cert-manager -n cert-manager --timeout=120s
else
    echo "[4/4] Skipping parameter reset (use --reset-params to reset)"
fi

if [[ "${CLEAN_RESULTS}" == "true" ]]; then
    echo ""
    echo "Removing results directory..."
    rm -rf "${SCRIPT_DIR}/results"
    mkdir -p "${SCRIPT_DIR}/results"
fi

echo ""
echo "=== Cleanup Complete ==="
