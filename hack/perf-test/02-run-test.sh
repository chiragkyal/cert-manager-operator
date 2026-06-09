#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> <num-certificates> [issuer-type]"
    echo ""
    echo "  scenario-name:    Name tag for this run (e.g. baseline, moderate, aggressive)"
    echo "  num-certificates: Number of certificates to create (e.g. 50, 100, 300, 500)"
    echo "  issuer-type:      'ca' (default) or 'selfsigned'"
    echo ""
    echo "Examples:"
    echo "  $0 baseline 100"
    echo "  $0 moderate 300"
    echo "  $0 aggressive 500"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SCENARIO="${1}"
NUM_CERTS="${2}"
ISSUER_TYPE="${3:-ca}"

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-${NUM_CERTS}certs-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

echo "=== cert-manager Performance Test ==="
echo "Scenario:     ${SCENARIO}"
echo "Certificates: ${NUM_CERTS}"
echo "Issuer type:  ${ISSUER_TYPE}"
echo "Run name:     ${RUN_NAME}"
echo "Results dir:  ${RUN_DIR}"
echo ""

# Record cluster state before test
echo "[1/6] Recording pre-test state..."
{
    echo "--- Cluster Info ---"
    echo "Server: $(oc whoami --show-server)"
    echo "Timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    echo "--- CertManager CR ---"
    oc get certmanager cluster -o yaml
    echo ""
    echo "--- Controller Deployment ---"
    oc get deployment cert-manager -n cert-manager -o yaml
    echo ""
    echo "--- Controller Pod Status ---"
    oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o wide
} > "${RUN_DIR}/pre-test-state.txt" 2>&1

# Record controller args for this run
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq . > "${RUN_DIR}/controller-resources.json" 2>/dev/null || echo "{}" > "${RUN_DIR}/controller-resources.json"

# Clean any existing test certificates
echo "[2/6] Cleaning existing test certificates..."
oc delete certificates -n "${NAMESPACE}" -l perf-test=true --ignore-not-found=true --wait=false 2>/dev/null || true
oc delete certificaterequests -n "${NAMESPACE}" --all --ignore-not-found=true --wait=false 2>/dev/null || true
oc delete secrets -n "${NAMESPACE}" -l perf-test=true --ignore-not-found=true --wait=false 2>/dev/null || true
sleep 5

# Ensure controller pod is ready
echo "[3/6] Verifying controller pod is running..."
oc wait --for=condition=Available deployment/cert-manager -n cert-manager --timeout=120s

# Record controller pod resource usage before
CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}')
echo "Controller pod: ${CTRL_POD}"
oc adm top pod "${CTRL_POD}" -n cert-manager --no-headers 2>/dev/null > "${RUN_DIR}/resource-before.txt" || echo "metrics unavailable" > "${RUN_DIR}/resource-before.txt"

# Generate and apply certificates
echo "[4/6] Creating ${NUM_CERTS} Certificate resources..."

ISSUER_NAME="perf-test-ca-issuer"
ISSUER_KIND="Issuer"
if [[ "${ISSUER_TYPE}" == "selfsigned" ]]; then
    ISSUER_NAME="perf-test-selfsigned"
    ISSUER_KIND="ClusterIssuer"
fi

# Record the exact moment we start creating certificates
START_TIME=$(date +%s)
START_TIME_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)

# Generate all certificate YAML in a single file for bulk apply
BULK_FILE="${RUN_DIR}/certificates.yaml"
> "${BULK_FILE}"

for i in $(seq 1 "${NUM_CERTS}"); do
    cat >> "${BULK_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: perf-test-cert-$(printf "%04d" $i)
  namespace: ${NAMESPACE}
  labels:
    perf-test: "true"
    scenario: "${SCENARIO}"
spec:
  secretName: perf-test-secret-$(printf "%04d" $i)
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "perf-test-$(printf "%04d" $i).example.com"
  issuerRef:
    name: ${ISSUER_NAME}
    kind: ${ISSUER_KIND}
    group: cert-manager.io
---
EOF
done

# Apply all at once
oc apply -f "${BULK_FILE}" 2>&1 | tail -5
echo "  ... (${NUM_CERTS} certificates submitted)"

SUBMIT_TIME=$(date +%s)
SUBMIT_DURATION=$((SUBMIT_TIME - START_TIME))
echo "  Submission took ${SUBMIT_DURATION}s"

# Wait and poll for completion
echo "[5/6] Waiting for certificates to become Ready..."
echo ""

POLL_INTERVAL=5
MAX_WAIT=1800  # 30 minutes max
ELAPSED=0
LAST_READY=0

# Create a progress file
PROGRESS_FILE="${RUN_DIR}/progress.csv"
echo "elapsed_seconds,ready_count,total,pending,failed" > "${PROGRESS_FILE}"

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l perf-test=true -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
    FAILED_COUNT=$(oc get certificates -n "${NAMESPACE}" -l perf-test=true -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="False" and .reason!="Pending"))] | length')
    PENDING=$((NUM_CERTS - READY_COUNT - FAILED_COUNT))

    echo "${ELAPSED},${READY_COUNT},${NUM_CERTS},${PENDING},${FAILED_COUNT}" >> "${PROGRESS_FILE}"

    # Progress bar
    PCT=$((READY_COUNT * 100 / NUM_CERTS))
    BAR_LEN=40
    FILLED=$((PCT * BAR_LEN / 100))
    EMPTY=$((BAR_LEN - FILLED))
    BAR=$(printf '%0.s#' $(seq 1 ${FILLED} 2>/dev/null) || true)$(printf '%0.s-' $(seq 1 ${EMPTY} 2>/dev/null) || true)
    printf "\r  [${BAR}] ${READY_COUNT}/${NUM_CERTS} ready (${FAILED_COUNT} failed) - ${ELAPSED}s elapsed"

    if [[ ${READY_COUNT} -eq ${NUM_CERTS} ]]; then
        echo ""
        echo "  All certificates ready!"
        break
    fi

    # Detect stall (no progress for 120s)
    if [[ ${READY_COUNT} -eq ${LAST_READY} ]] && [[ ${ELAPSED} -gt 120 ]] && [[ ${READY_COUNT} -gt 0 ]]; then
        STALL_CHECK=$((ELAPSED % 120))
        if [[ ${STALL_CHECK} -eq 0 ]]; then
            echo ""
            echo "  WARNING: No progress in last 120s (stuck at ${READY_COUNT}/${NUM_CERTS})"
        fi
    fi
    LAST_READY=${READY_COUNT}

    sleep ${POLL_INTERVAL}
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

END_TIME=$(date +%s)
END_TIME_ISO=$(date -u +%Y-%m-%dT%H:%M:%SZ)
TOTAL_DURATION=$((END_TIME - START_TIME))
ISSUANCE_DURATION=$((END_TIME - SUBMIT_TIME))

echo ""

# Collect final results
echo "[6/6] Collecting results..."

# Get per-certificate timing data
oc get certificates -n "${NAMESPACE}" -l perf-test=true -o json > "${RUN_DIR}/certificates-final.json"

# Extract timing: creation timestamp vs Ready condition lastTransitionTime
jq -r '
  .items[] |
  {
    name: .metadata.name,
    created: .metadata.creationTimestamp,
    ready_time: (.status.conditions[]? | select(.type=="Ready") | .lastTransitionTime),
    ready_status: (.status.conditions[]? | select(.type=="Ready") | .status),
    reason: (.status.conditions[]? | select(.type=="Ready") | .reason)
  } |
  "\(.name),\(.created),\(.ready_time),\(.ready_status),\(.reason)"
' "${RUN_DIR}/certificates-final.json" > "${RUN_DIR}/cert-timings.csv"

# Add header
sed -i '' '1i\
name,created,ready_time,ready_status,reason
' "${RUN_DIR}/cert-timings.csv" 2>/dev/null || sed -i '1iname,created,ready_time,ready_status,reason' "${RUN_DIR}/cert-timings.csv"

# Calculate per-certificate duration in seconds
jq -r '
  .items[] |
  select(.status.conditions[]? | select(.type=="Ready" and .status=="True")) |
  {
    name: .metadata.name,
    created: .metadata.creationTimestamp,
    ready: (.status.conditions[] | select(.type=="Ready") | .lastTransitionTime)
  } |
  "\(.created) \(.ready)"
' "${RUN_DIR}/certificates-final.json" | while read -r created ready; do
    if [[ -n "${created}" ]] && [[ -n "${ready}" ]]; then
        # macOS date vs GNU date handling
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

# Compute statistics
FINAL_READY=$(oc get certificates -n "${NAMESPACE}" -l perf-test=true -o json | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
FINAL_FAILED=$((NUM_CERTS - FINAL_READY))

# Resource usage after
oc adm top pod "${CTRL_POD}" -n cert-manager --no-headers 2>/dev/null > "${RUN_DIR}/resource-after.txt" || echo "metrics unavailable" > "${RUN_DIR}/resource-after.txt"

# Compute P50, P90, P99 from durations
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
    MIN_VAL="N/A"
    MAX_VAL="N/A"
    P50_VAL="N/A"
    P90_VAL="N/A"
    P99_VAL="N/A"
fi

# Write summary
cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "num_certificates": ${NUM_CERTS},
  "issuer_type": "${ISSUER_TYPE}",
  "start_time": "${START_TIME_ISO}",
  "end_time": "${END_TIME_ISO}",
  "submit_duration_seconds": ${SUBMIT_DURATION},
  "total_duration_seconds": ${TOTAL_DURATION},
  "issuance_duration_seconds": ${ISSUANCE_DURATION},
  "certificates_ready": ${FINAL_READY},
  "certificates_failed": ${FINAL_FAILED},
  "rate_certs_per_minute": $(echo "scale=2; ${FINAL_READY} * 60 / ${ISSUANCE_DURATION}" | bc 2>/dev/null || echo 0),
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
echo "  RESULTS: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Scenario:            ${SCENARIO}"
echo "  Total Certificates:  ${NUM_CERTS}"
echo "  Ready:               ${FINAL_READY}"
echo "  Failed:              ${FINAL_FAILED}"
echo ""
echo "  Total Duration:      ${TOTAL_DURATION}s"
echo "  Issuance Duration:   ${ISSUANCE_DURATION}s (after all submitted)"
echo "  Rate:                $(echo "scale=1; ${FINAL_READY} * 60 / ${ISSUANCE_DURATION}" | bc 2>/dev/null || echo "?") certs/min"
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
