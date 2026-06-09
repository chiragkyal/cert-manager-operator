#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
    echo "Usage: $0 <scenario>"
    echo ""
    echo "  scenario: baseline, moderate, or aggressive"
    echo ""
    echo "This applies the performance parameter configuration to the CertManager CR"
    echo "and waits for the controller deployment to roll out with new args."
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

SCENARIO="${1}"
SCENARIO_FILE="${SCRIPT_DIR}/scenarios/${SCENARIO}.yaml"

if [[ ! -f "${SCENARIO_FILE}" ]]; then
    echo "ERROR: Scenario file not found: ${SCENARIO_FILE}"
    echo "Available scenarios:"
    ls "${SCRIPT_DIR}/scenarios/"*.yaml 2>/dev/null | xargs -I{} basename {} .yaml
    exit 1
fi

echo "=== Applying Scenario: ${SCENARIO} ==="
echo ""

# Show what we're about to apply
echo "Configuration to apply:"
echo "---"
cat "${SCENARIO_FILE}"
echo "---"
echo ""

# Record current controller deployment generation
OLD_GEN=$(oc get deployment cert-manager -n cert-manager -o jsonpath='{.metadata.generation}')
OLD_REVISION=$(oc get deployment cert-manager -n cert-manager -o jsonpath='{.status.observedGeneration}')

echo "[1/4] Applying CertManager CR..."
oc apply -f "${SCENARIO_FILE}"

echo "[2/4] Waiting for operator to reconcile (up to 60s)..."
sleep 10

# Wait for the deployment to be updated (generation changes)
WAITED=0
MAX_WAIT=120
while [[ ${WAITED} -lt ${MAX_WAIT} ]]; do
    NEW_GEN=$(oc get deployment cert-manager -n cert-manager -o jsonpath='{.metadata.generation}')
    if [[ "${NEW_GEN}" != "${OLD_GEN}" ]]; then
        echo "  Deployment updated (generation: ${OLD_GEN} -> ${NEW_GEN})"
        break
    fi
    sleep 5
    WAITED=$((WAITED + 5))
done

if [[ ${WAITED} -ge ${MAX_WAIT} ]]; then
    echo "  NOTE: Deployment generation unchanged. If this is 'baseline', the operator"
    echo "  may have already removed overrides and no rollout is needed."
fi

echo "[3/4] Waiting for controller rollout to complete..."
oc rollout status deployment/cert-manager -n cert-manager --timeout=180s

echo "[4/4] Verifying new configuration..."
echo ""
echo "Controller args:"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq .
echo ""
echo "Controller resources:"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq .
echo ""

# Verify controller pod is healthy
echo "Controller pod status:"
oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o wide
echo ""

echo "=== Scenario '${SCENARIO}' applied successfully ==="
echo ""
echo "Wait 30 seconds for the controller to stabilize, then run:"
echo "  ./02-run-test.sh ${SCENARIO} <num-certificates>"
