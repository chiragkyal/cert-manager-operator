#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> <num-certificates> [--with-delay]"
    echo ""
    echo "Large-scale ACME HTTP01 issuance test using the local Pebble server."
    echo "Designed to stress --max-concurrent-challenges at scale (100-500 certs)."
    echo ""
    echo "Options:"
    echo "  --with-delay   Use Pebble with validation delay (tests --dns01-check-retry-period)"
    echo "                 Requires running ./19-setup-acme-delayed.sh first"
    echo ""
    echo "Examples:"
    echo "  $0 baseline-acme 100"
    echo "  $0 aggressive-acme 300"
    echo "  $0 aggressive-acme 500"
    echo "  $0 baseline-acme-delayed 100 --with-delay"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SCENARIO="${1}"
NUM_CERTS="${2}"
WITH_DELAY=false
if [[ "${3:-}" == "--with-delay" ]]; then
    WITH_DELAY=true
fi

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-${NUM_CERTS}certs-acme-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

# Auto-detect the cluster apps domain for DNS resolution during self-checks
APPS_DOMAIN=$(oc get ingresses.config.openshift.io/cluster -o jsonpath='{.spec.domain}' 2>/dev/null || echo "apps.example.com")

# Choose issuer based on delay mode
if [[ "${WITH_DELAY}" == "true" ]]; then
    ISSUER_NAME="perf-test-acme-pebble-delayed"
    PEBBLE_NS="pebble-delayed"
else
    ISSUER_NAME="perf-test-acme-pebble"
    PEBBLE_NS="pebble"
fi

echo "=== ACME Scale Test ==="
echo "Scenario:     ${SCENARIO}"
echo "Certificates: ${NUM_CERTS}"
echo "Issuer:       ${ISSUER_NAME} (HTTP01)"
echo "Apps Domain:  ${APPS_DOMAIN}"
echo "VA Delay:     ${WITH_DELAY}"
echo "Run name:     ${RUN_NAME}"
echo ""

# Verify Pebble is running
if ! oc get deployment pebble -n "${PEBBLE_NS}" &>/dev/null; then
    echo "ERROR: Pebble not deployed in namespace '${PEBBLE_NS}'."
    if [[ "${WITH_DELAY}" == "true" ]]; then
        echo "  Run ./19-setup-acme-delayed.sh first."
    else
        echo "  Run ./15-setup-acme.sh first."
    fi
    exit 1
fi

if ! oc get clusterissuer "${ISSUER_NAME}" &>/dev/null; then
    echo "ERROR: ClusterIssuer '${ISSUER_NAME}' not found."
    exit 1
fi

# Record controller config
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq . > "${RUN_DIR}/controller-resources.json" 2>/dev/null || echo "{}" > "${RUN_DIR}/controller-resources.json"

# Clean previous ACME test resources
echo "[1/6] Cleaning existing ACME test certificates..."
oc delete certificates -n "${NAMESPACE}" -l test-type=acme-scale --wait=false 2>/dev/null || true
oc delete challenges -n "${NAMESPACE}" --all --wait=false 2>/dev/null || true
oc delete orders -n "${NAMESPACE}" --all --wait=false 2>/dev/null || true
echo "  Waiting for cleanup..."
sleep 15

# Generate ACME certificates in batches (avoid massive single apply)
echo "[2/6] Creating ${NUM_CERTS} Certificate resources (ACME HTTP01)..."

BULK_DIR="${RUN_DIR}/cert-batches"
mkdir -p "${BULK_DIR}"
BATCH_SIZE=50
BATCH_NUM=0

for i in $(seq 1 "${NUM_CERTS}"); do
    BATCH_IDX=$(( (i - 1) / BATCH_SIZE ))
    BATCH_FILE="${BULK_DIR}/batch-$(printf "%03d" ${BATCH_IDX}).yaml"

    cat >> "${BATCH_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: perf-acme-scale-$(printf "%05d" $i)
  namespace: ${NAMESPACE}
  labels:
    perf-test: "true"
    test-type: "acme-scale"
    scenario: "${SCENARIO}"
spec:
  secretName: perf-acme-scale-secret-$(printf "%05d" $i)
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "perf-acme-scale-$(printf "%05d" $i).${APPS_DOMAIN}"
  issuerRef:
    name: ${ISSUER_NAME}
    kind: ClusterIssuer
    group: cert-manager.io
---
EOF
done

START_TIME=$(date +%s)

# Apply in batches to avoid overwhelming the API server
TOTAL_BATCHES=$(ls "${BULK_DIR}"/batch-*.yaml 2>/dev/null | wc -l | tr -d ' ')
BATCH_DONE=0
for BATCH_FILE in "${BULK_DIR}"/batch-*.yaml; do
    BATCH_DONE=$((BATCH_DONE + 1))
    oc apply -f "${BATCH_FILE}" 2>&1 | tail -1
    printf "\r  Applied batch %d/%d" "${BATCH_DONE}" "${TOTAL_BATCHES}"
done

SUBMIT_TIME=$(date +%s)
SUBMIT_DURATION=$((SUBMIT_TIME - START_TIME))
echo ""
echo "  ${NUM_CERTS} ACME certificates submitted in ${SUBMIT_DURATION}s"

# Wait for completion with detailed monitoring
echo "[3/6] Waiting for ACME certificates to become Ready..."
echo "  (Order → Challenge → HTTP01 Solver → Self-Check → Validation → Finalize)"
echo ""

POLL_INTERVAL=10
MAX_WAIT=1800
ELAPSED=0

PROGRESS_FILE="${RUN_DIR}/progress.csv"
echo "elapsed_seconds,ready_count,total,challenges_active,orders_pending,solver_pods" > "${PROGRESS_FILE}"

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l test-type=acme-scale -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length' | tr -cd '0-9')
    CHALLENGES=$(oc get challenges -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -cd '0-9')
    ORDERS=$(oc get orders -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -cd '0-9')
    SOLVER_PODS=$(oc get pods -n "${NAMESPACE}" -l "acme.cert-manager.io/http01-solver=true" --no-headers 2>/dev/null | wc -l | tr -cd '0-9')

    READY_COUNT=${READY_COUNT:-0}
    CHALLENGES=${CHALLENGES:-0}
    ORDERS=${ORDERS:-0}
    SOLVER_PODS=${SOLVER_PODS:-0}

    echo "${ELAPSED},${READY_COUNT},${NUM_CERTS},${CHALLENGES},${ORDERS},${SOLVER_PODS}" >> "${PROGRESS_FILE}"

    PCT=$((READY_COUNT * 100 / NUM_CERTS))
    printf "\r  Ready: %d/%d [%3d%%] | Challenges: %d | Orders: %d | Solvers: %d | %ds" \
        "${READY_COUNT}" "${NUM_CERTS}" "${PCT}" "${CHALLENGES}" "${ORDERS}" "${SOLVER_PODS}" "${ELAPSED}"

    if [[ ${READY_COUNT} -ge ${NUM_CERTS} ]]; then
        echo ""
        echo "  All ACME certificates ready!"
        break
    fi

    sleep ${POLL_INTERVAL}
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))
ISSUANCE_DURATION=$((END_TIME - SUBMIT_TIME))

if [[ ${READY_COUNT} -lt ${NUM_CERTS} ]]; then
    echo ""
    echo "  WARNING: Timed out. Only ${READY_COUNT}/${NUM_CERTS} ready after ${MAX_WAIT}s"
fi

# Collect results
echo ""
echo "[4/6] Collecting per-certificate timing..."

oc get certificates -n "${NAMESPACE}" -l test-type=acme-scale -o json > "${RUN_DIR}/certificates-final.json"

# Per-cert timing
jq -r '
  .items[] |
  select(.status.conditions[]? | select(.type=="Ready" and .status=="True")) |
  {
    created: .metadata.creationTimestamp,
    ready: (.status.conditions[] | select(.type=="Ready") | .lastTransitionTime)
  } |
  "\(.created) \(.ready)"
' "${RUN_DIR}/certificates-final.json" | while read -r created ready; do
    if [[ -n "${created}" ]] && [[ -n "${ready}" ]]; then
        if date --version &>/dev/null 2>&1; then
            C=$(date -d "${created}" +%s 2>/dev/null || echo 0)
            R=$(date -d "${ready}" +%s 2>/dev/null || echo 0)
        else
            C=$(date -jf "%Y-%m-%dT%H:%M:%SZ" "${created}" +%s 2>/dev/null || echo 0)
            R=$(date -jf "%Y-%m-%dT%H:%M:%SZ" "${ready}" +%s 2>/dev/null || echo 0)
        fi
        if [[ ${C} -gt 0 ]] && [[ ${R} -gt 0 ]]; then
            echo $((R - C))
        fi
    fi
done > "${RUN_DIR}/durations-seconds.txt"

# Statistics
echo "[5/6] Computing statistics..."

FINAL_READY=$(jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length' "${RUN_DIR}/certificates-final.json")
FINAL_FAILED=$((NUM_CERTS - FINAL_READY))

if [[ -s "${RUN_DIR}/durations-seconds.txt" ]]; then
    SORTED=$(sort -n "${RUN_DIR}/durations-seconds.txt")
    COUNT=$(echo "${SORTED}" | wc -l | tr -d ' ')
    P50_IDX=$(( (COUNT * 50 + 99) / 100 ))
    P90_IDX=$(( (COUNT * 90 + 99) / 100 ))
    P99_IDX=$(( (COUNT * 99 + 99) / 100 ))
    MIN_VAL=$(echo "${SORTED}" | head -1)
    MAX_VAL=$(echo "${SORTED}" | tail -1)
    P50_VAL=$(echo "${SORTED}" | sed -n "${P50_IDX}p")
    P90_VAL=$(echo "${SORTED}" | sed -n "${P90_IDX}p")
    P99_VAL=$(echo "${SORTED}" | sed -n "${P99_IDX}p")
else
    MIN_VAL="N/A"; MAX_VAL="N/A"; P50_VAL="N/A"; P90_VAL="N/A"; P99_VAL="N/A"
fi

# Controller health
CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
RESTARTS=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

# Peak challenge count from progress data
PEAK_CHALLENGES=$(awk -F',' 'NR>1 {print $4}' "${PROGRESS_FILE}" | sort -n | tail -1)
PEAK_SOLVERS=$(awk -F',' 'NR>1 {print $6}' "${PROGRESS_FILE}" | sort -n | tail -1)

echo "[6/6] Writing summary..."

if [[ ${ISSUANCE_DURATION} -gt 0 ]]; then
    RATE=$(echo "scale=2; ${FINAL_READY} * 60 / ${ISSUANCE_DURATION}" | bc 2>/dev/null || echo 0)
else
    RATE=0
fi

cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "test_type": "acme_scale_http01",
  "issuer": "${ISSUER_NAME}",
  "with_validation_delay": ${WITH_DELAY},
  "num_certificates": ${NUM_CERTS},
  "submit_duration_seconds": ${SUBMIT_DURATION},
  "total_duration_seconds": ${TOTAL_DURATION},
  "issuance_duration_seconds": ${ISSUANCE_DURATION},
  "certificates_ready": ${FINAL_READY},
  "certificates_failed": ${FINAL_FAILED},
  "controller_restarts": ${RESTARTS},
  "peak_concurrent_challenges": ${PEAK_CHALLENGES:-0},
  "peak_solver_pods": ${PEAK_SOLVERS:-0},
  "rate_certs_per_minute": ${RATE},
  "timing": {
    "min_seconds": "${MIN_VAL}",
    "p50_seconds": "${P50_VAL}",
    "p90_seconds": "${P90_VAL}",
    "p99_seconds": "${P99_VAL}",
    "max_seconds": "${MAX_VAL}"
  }
}
EOF

echo ""
echo "================================================================"
echo "  ACME SCALE TEST: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Scenario:              ${SCENARIO}"
echo "  Issuer:                ACME HTTP01 (${ISSUER_NAME})"
echo "  Validation Delay:      ${WITH_DELAY}"
echo "  Total Certificates:    ${NUM_CERTS}"
echo "  Ready:                 ${FINAL_READY}"
echo "  Failed:                ${FINAL_FAILED}"
echo "  Controller restarts:   ${RESTARTS}"
echo ""
echo "  Submit Duration:       ${SUBMIT_DURATION}s"
echo "  Issuance Duration:     ${ISSUANCE_DURATION}s"
echo "  Total Duration:        ${TOTAL_DURATION}s"
echo "  Rate:                  ${RATE} certs/min"
echo ""
echo "  Peak Challenges:       ${PEAK_CHALLENGES:-0}"
echo "  Peak Solver Pods:      ${PEAK_SOLVERS:-0}"
echo ""
echo "  Per-Certificate Timing:"
echo "    Min:  ${MIN_VAL}s"
echo "    P50:  ${P50_VAL}s"
echo "    P90:  ${P90_VAL}s"
echo "    P99:  ${P99_VAL}s"
echo "    Max:  ${MAX_VAL}s"
echo ""
echo "  Results saved to: ${RUN_DIR}/"
echo "================================================================"

# Auto-generate report
if [[ -x "${SCRIPT_DIR}/14-generate-report.sh" ]]; then
    echo ""
    "${SCRIPT_DIR}/14-generate-report.sh" 2>/dev/null && echo "Report updated: results/report-latest/" || true
fi
