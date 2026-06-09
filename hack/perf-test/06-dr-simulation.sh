#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> <num-certificates>"
    echo ""
    echo "Simulates disaster recovery by:"
    echo "  1. Creating N certificates and waiting for them to be Ready"
    echo "  2. Deleting all TLS secrets (simulating key loss)"
    echo "  3. Measuring how long cert-manager takes to re-issue all certificates"
    echo ""
    echo "Examples:"
    echo "  $0 baseline-dr 100"
    echo "  $0 aggressive-dr 300"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SCENARIO="${1}"
NUM_CERTS="${2}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-${NUM_CERTS}certs-dr-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

ISSUER_NAME="perf-test-ca-issuer"
ISSUER_KIND="Issuer"

echo "=== Disaster Recovery Simulation ==="
echo "Scenario:     ${SCENARIO}"
echo "Certificates: ${NUM_CERTS}"
echo "Run name:     ${RUN_NAME}"
echo ""

# Record controller config
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"

# Step 1: Create certificates
echo "[1/5] Creating ${NUM_CERTS} certificates..."

BULK_FILE="${RUN_DIR}/certificates.yaml"
> "${BULK_FILE}"

for i in $(seq 1 "${NUM_CERTS}"); do
    cat >> "${BULK_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: perf-dr-cert-$(printf "%04d" $i)
  namespace: ${NAMESPACE}
  labels:
    perf-test: "true"
    scenario: "${SCENARIO}"
    test-type: "dr"
spec:
  secretName: perf-dr-secret-$(printf "%04d" $i)
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "perf-dr-$(printf "%04d" $i).example.com"
  issuerRef:
    name: ${ISSUER_NAME}
    kind: ${ISSUER_KIND}
    group: cert-manager.io
---
EOF
done

oc apply -f "${BULK_FILE}" 2>&1 | tail -3

# Step 2: Wait for all to be Ready (initial issuance)
echo "[2/5] Waiting for initial issuance to complete..."

MAX_WAIT=900
ELAPSED=0
while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l test-type=dr -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
    printf "\r  Initial issuance: ${READY_COUNT}/${NUM_CERTS} ready (${ELAPSED}s)"

    if [[ ${READY_COUNT} -ge ${NUM_CERTS} ]]; then
        echo ""
        echo "  All certificates initially issued."
        break
    fi
    sleep 5
    ELAPSED=$((ELAPSED + 5))
done

if [[ ${ELAPSED} -ge ${MAX_WAIT} ]]; then
    echo ""
    echo "ERROR: Initial issuance timed out. Cannot proceed with DR simulation."
    exit 1
fi

echo ""
echo "  Stabilizing for 15 seconds..."
sleep 15

# Step 3: Delete all secrets (simulate disaster)
echo "[3/5] SIMULATING DISASTER: Deleting all certificate secrets..."
DR_START=$(date +%s)
DR_START_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

oc delete secrets -n "${NAMESPACE}" -l "cert-manager.io/certificate-name" --wait=false 2>/dev/null || true
# Also try matching the secret names directly
for i in $(seq 1 "${NUM_CERTS}"); do
    oc delete secret "perf-dr-secret-$(printf "%04d" $i)" -n "${NAMESPACE}" --ignore-not-found=true --wait=false 2>/dev/null &
done
wait

echo "  All ${NUM_CERTS} secrets deleted."
echo ""

# Step 4: Measure re-issuance time
echo "[4/5] Measuring re-issuance time..."
echo ""

PROGRESS_FILE="${RUN_DIR}/dr-progress.csv"
echo "elapsed_seconds,ready_count,total" > "${PROGRESS_FILE}"

MAX_WAIT=1800
ELAPSED=0
POLL_INTERVAL=5

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    # After secret deletion, cert-manager marks certificates as not-Ready and re-issues
    # We check for secrets existing again as the "ready" indicator
    SECRETS_COUNT=$(oc get secrets -n "${NAMESPACE}" -l "cert-manager.io/certificate-name" --no-headers 2>/dev/null | wc -l | tr -d ' ')

    # Also check certificate Ready status
    READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l test-type=dr -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')

    echo "${ELAPSED},${READY_COUNT},${NUM_CERTS}" >> "${PROGRESS_FILE}"

    PCT=$((READY_COUNT * 100 / NUM_CERTS))
    printf "\r  Re-issuance: ${READY_COUNT}/${NUM_CERTS} ready (${SECRETS_COUNT} secrets) - ${ELAPSED}s elapsed [%3d%%]" "${PCT}"

    if [[ ${READY_COUNT} -ge ${NUM_CERTS} ]]; then
        echo ""
        echo "  All certificates re-issued!"
        break
    fi

    sleep ${POLL_INTERVAL}
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

DR_END=$(date +%s)
DR_END_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
DR_DURATION=$((DR_END - DR_START))

FINAL_READY=$(oc get certificates -n "${NAMESPACE}" -l test-type=dr -o json | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')

# Step 5: Results
echo ""
echo "[5/5] Collecting DR simulation results..."

cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "test_type": "disaster_recovery",
  "num_certificates": ${NUM_CERTS},
  "dr_start_time": "${DR_START_ISO}",
  "dr_end_time": "${DR_END_ISO}",
  "issuance_duration_seconds": ${DR_DURATION},
  "certificates_ready": ${FINAL_READY},
  "certificates_failed": $((NUM_CERTS - FINAL_READY)),
  "rate_certs_per_minute": $(echo "scale=2; ${FINAL_READY} * 60 / ${DR_DURATION}" | bc 2>/dev/null || echo 0),
  "timing": {
    "min_seconds": "N/A",
    "p50_seconds": "N/A",
    "p90_seconds": "N/A",
    "p99_seconds": "N/A",
    "max_seconds": "${DR_DURATION}"
  }
}
EOF

echo ""
echo "================================================================"
echo "  DR SIMULATION RESULTS: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Scenario:            ${SCENARIO}"
echo "  Certificates:        ${NUM_CERTS}"
echo "  Re-issued:           ${FINAL_READY}"
echo "  Failed:              $((NUM_CERTS - FINAL_READY))"
echo ""
echo "  Recovery Duration:   ${DR_DURATION}s ($(echo "scale=1; ${DR_DURATION} / 60" | bc 2>/dev/null || echo "?") minutes)"
echo "  Rate:                $(echo "scale=1; ${FINAL_READY} * 60 / ${DR_DURATION}" | bc 2>/dev/null || echo "?") certs/min"
echo ""
echo "  Results saved to: ${RUN_DIR}/"
echo "================================================================"

# Auto-generate report
if [[ -x "${SCRIPT_DIR}/14-generate-report.sh" ]]; then
    echo ""
    "${SCRIPT_DIR}/14-generate-report.sh" 2>/dev/null && echo "Report updated: results/report-latest/" || true
fi
