#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> <num-certificates>"
    echo ""
    echo "Simulates a renewal storm:"
    echo "  1. Creates N certificates with very short duration (5m) and renewBefore=4m"
    echo "  2. Waits for initial issuance"
    echo "  3. Measures how quickly all certificates are renewed simultaneously"
    echo "     (they will all trigger renewal within ~1 minute of creation)"
    echo ""
    echo "Examples:"
    echo "  $0 baseline-renewal 100"
    echo "  $0 aggressive-renewal 300"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SCENARIO="${1}"
NUM_CERTS="${2}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-${NUM_CERTS}certs-renewal-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

ISSUER_NAME="perf-test-ca-issuer"
ISSUER_KIND="Issuer"

echo "=== Renewal Storm Simulation ==="
echo "Scenario:     ${SCENARIO}"
echo "Certificates: ${NUM_CERTS}"
echo "Run name:     ${RUN_NAME}"
echo ""
echo "Strategy: Certs with duration=1h1m, renewBefore=1h"
echo "          -> renewal triggers ~1 minute after issuance"
echo ""

# Record controller config
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq . > "${RUN_DIR}/controller-resources.json" 2>/dev/null || echo "{}" > "${RUN_DIR}/controller-resources.json"

# Step 1: Create short-lived certificates
echo "[1/5] Creating ${NUM_CERTS} short-lived certificates (duration=1h1m, renewBefore=1h)..."

BULK_FILE="${RUN_DIR}/certificates.yaml"
> "${BULK_FILE}"

for i in $(seq 1 "${NUM_CERTS}"); do
    cat >> "${BULK_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: perf-renewal-cert-$(printf "%04d" $i)
  namespace: ${NAMESPACE}
  labels:
    perf-test: "true"
    scenario: "${SCENARIO}"
    test-type: "renewal"
spec:
  secretName: perf-renewal-secret-$(printf "%04d" $i)
  duration: 1h1m
  renewBefore: 1h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "perf-renewal-$(printf "%04d" $i).example.com"
  issuerRef:
    name: ${ISSUER_NAME}
    kind: ${ISSUER_KIND}
    group: cert-manager.io
---
EOF
done

oc apply -f "${BULK_FILE}" 2>&1 | tail -3

# Step 2: Wait for initial issuance
echo "[2/5] Waiting for initial issuance..."

MAX_WAIT=600
ELAPSED=0
while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l test-type=renewal -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
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
    echo "ERROR: Initial issuance timed out."
    exit 1
fi

# Record initial revision counts (each renewal increments .status.revision)
echo "[3/5] Recording initial state and waiting for renewal trigger..."
oc get certificates -n "${NAMESPACE}" -l test-type=renewal -o json > "${RUN_DIR}/certs-initial.json"
INITIAL_REVISIONS=$(jq '[.items[].status.revision // 1] | add' "${RUN_DIR}/certs-initial.json")
echo "  Initial total revisions: ${INITIAL_REVISIONS}"
echo ""
echo "  Waiting for renewals to start (certs will renew after ~60s)..."
echo "  Monitoring renewal progress..."

# Step 4: Monitor renewal
RENEWAL_START=$(date +%s)
PROGRESS_FILE="${RUN_DIR}/renewal-progress.csv"
echo "elapsed_seconds,renewed_count,total,pending" > "${PROGRESS_FILE}"

TARGET_REVISIONS=$((INITIAL_REVISIONS + NUM_CERTS))
MAX_WAIT=600
ELAPSED=0
POLL_INTERVAL=5
FIRST_RENEWAL_DETECTED=false
FIRST_RENEWAL_TIME=0

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    CURRENT_JSON=$(oc get certificates -n "${NAMESPACE}" -l test-type=renewal -o json 2>/dev/null)
    CURRENT_REVISIONS=$(echo "${CURRENT_JSON}" | jq '[.items[].status.revision // 1] | add')
    RENEWED=$((CURRENT_REVISIONS - INITIAL_REVISIONS))

    # Check for Issuing condition (indicates renewal in progress)
    ISSUING_COUNT=$(echo "${CURRENT_JSON}" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Issuing" and .status=="True"))] | length')

    echo "${ELAPSED},${RENEWED},${NUM_CERTS},${ISSUING_COUNT}" >> "${PROGRESS_FILE}"

    if [[ ${RENEWED} -gt 0 ]] && [[ "${FIRST_RENEWAL_DETECTED}" == "false" ]]; then
        FIRST_RENEWAL_DETECTED=true
        FIRST_RENEWAL_TIME=${ELAPSED}
        echo ""
        echo "  First renewal detected at ${ELAPSED}s"
    fi

    printf "\r  Renewals: ${RENEWED}/${NUM_CERTS} complete, ${ISSUING_COUNT} in-progress - ${ELAPSED}s elapsed"

    if [[ ${RENEWED} -ge ${NUM_CERTS} ]]; then
        echo ""
        echo "  All certificates renewed!"
        break
    fi

    sleep ${POLL_INTERVAL}
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

RENEWAL_END=$(date +%s)
RENEWAL_DURATION=$((RENEWAL_END - RENEWAL_START))

# If first renewal was detected, calculate just the burst duration
if [[ "${FIRST_RENEWAL_DETECTED}" == "true" ]]; then
    BURST_DURATION=$((ELAPSED - FIRST_RENEWAL_TIME))
else
    BURST_DURATION=${RENEWAL_DURATION}
fi

# Step 5: Results
echo ""
echo "[5/5] Collecting results..."

FINAL_JSON=$(oc get certificates -n "${NAMESPACE}" -l test-type=renewal -o json)
FINAL_REVISIONS=$(echo "${FINAL_JSON}" | jq '[.items[].status.revision // 1] | add')
TOTAL_RENEWED=$((FINAL_REVISIONS - INITIAL_REVISIONS))

# Check controller health
CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
RESTARTS=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "test_type": "renewal_storm",
  "num_certificates": ${NUM_CERTS},
  "certificates_renewed": ${TOTAL_RENEWED},
  "total_monitoring_duration_seconds": ${RENEWAL_DURATION},
  "first_renewal_at_seconds": ${FIRST_RENEWAL_TIME},
  "burst_duration_seconds": ${BURST_DURATION},
  "issuance_duration_seconds": ${BURST_DURATION},
  "rate_certs_per_minute": $(echo "scale=2; ${TOTAL_RENEWED} * 60 / (${BURST_DURATION} + 1)" | bc 2>/dev/null || echo 0),
  "controller_restarts": ${RESTARTS},
  "timing": {
    "min_seconds": "N/A",
    "p50_seconds": "N/A",
    "p90_seconds": "N/A",
    "p99_seconds": "N/A",
    "max_seconds": "${BURST_DURATION}"
  }
}
EOF

echo ""
echo "================================================================"
echo "  RENEWAL STORM RESULTS: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Scenario:              ${SCENARIO}"
echo "  Certificates:          ${NUM_CERTS}"
echo "  Renewed:               ${TOTAL_RENEWED}"
echo ""
echo "  Time to first renewal: ${FIRST_RENEWAL_TIME}s"
echo "  Burst duration:        ${BURST_DURATION}s (from first to last renewal)"
echo "  Rate:                  $(echo "scale=1; ${TOTAL_RENEWED} * 60 / (${BURST_DURATION} + 1)" | bc 2>/dev/null || echo "?") certs/min"
echo "  Controller restarts:   ${RESTARTS}"
echo ""
echo "  Results saved to: ${RUN_DIR}/"
echo "================================================================"

# Auto-generate report
if [[ -x "${SCRIPT_DIR}/14-generate-report.sh" ]]; then
    echo ""
    "${SCRIPT_DIR}/14-generate-report.sh" 2>/dev/null && echo "Report updated: results/report-latest/" || true
fi
