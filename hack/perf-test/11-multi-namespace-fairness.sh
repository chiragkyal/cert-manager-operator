#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> <num-namespaces> <certs-per-namespace>"
    echo ""
    echo "Tests fairness of certificate provisioning across multiple namespaces."
    echo "Creates N namespaces, each with M certificates, and measures whether"
    echo "all namespaces are served equally or some starve."
    echo ""
    echo "Examples:"
    echo "  $0 baseline-fairness 5 20    # 5 namespaces x 20 certs = 100 total"
    echo "  $0 aggressive-fairness 10 30  # 10 namespaces x 30 certs = 300 total"
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

SCENARIO="${1}"
NUM_NS="${2}"
CERTS_PER_NS="${3}"
TOTAL_CERTS=$((NUM_NS * CERTS_PER_NS))
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-${NUM_NS}ns-${CERTS_PER_NS}certs-fairness-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

echo "=== Multi-Namespace Fairness Test ==="
echo "Scenario:       ${SCENARIO}"
echo "Namespaces:     ${NUM_NS}"
echo "Certs per NS:   ${CERTS_PER_NS}"
echo "Total certs:    ${TOTAL_CERTS}"
echo "Run name:       ${RUN_NAME}"
echo ""

# Record controller config
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"

# Step 1: Create namespaces with ClusterIssuer (shared)
echo "[1/5] Creating ${NUM_NS} test namespaces..."
for ns_i in $(seq 1 "${NUM_NS}"); do
    NS_NAME="perf-fairness-$(printf "%02d" $ns_i)"
    oc create namespace "${NS_NAME}" --dry-run=client -o yaml | oc apply -f - 2>/dev/null
    oc label namespace "${NS_NAME}" perf-test=true fairness-test=true --overwrite 2>/dev/null
done
echo "  Done."

# Ensure ClusterIssuer exists
oc get clusterissuer perf-test-selfsigned &>/dev/null || {
    echo "ERROR: ClusterIssuer 'perf-test-selfsigned' not found. Run 01-setup.sh first."
    exit 1
}

# Step 2: Generate certificates across all namespaces
echo "[2/5] Creating ${CERTS_PER_NS} certificates in each of ${NUM_NS} namespaces..."

BULK_FILE="${RUN_DIR}/certificates.yaml"
> "${BULK_FILE}"

for ns_i in $(seq 1 "${NUM_NS}"); do
    NS_NAME="perf-fairness-$(printf "%02d" $ns_i)"
    for cert_i in $(seq 1 "${CERTS_PER_NS}"); do
        cat >> "${BULK_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: fairness-cert-$(printf "%04d" $cert_i)
  namespace: ${NS_NAME}
  labels:
    perf-test: "true"
    fairness-test: "true"
    test-namespace: "${NS_NAME}"
spec:
  secretName: fairness-secret-$(printf "%04d" $cert_i)
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "fairness-ns$(printf "%02d" $ns_i)-cert$(printf "%04d" $cert_i).example.com"
  issuerRef:
    name: perf-test-selfsigned
    kind: ClusterIssuer
    group: cert-manager.io
---
EOF
    done
done

START_TIME=$(date +%s)
oc apply -f "${BULK_FILE}" 2>&1 | tail -3
echo "  ${TOTAL_CERTS} certificates submitted."

# Step 3: Wait for completion
echo "[3/5] Waiting for all certificates to become Ready..."

MAX_WAIT=900
ELAPSED=0
POLL_INTERVAL=5
PROGRESS_FILE="${RUN_DIR}/progress.csv"
echo "elapsed_seconds,total_ready,total_certs" > "${PROGRESS_FILE}"

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    TOTAL_READY=0
    for ns_i in $(seq 1 "${NUM_NS}"); do
        NS_NAME="perf-fairness-$(printf "%02d" $ns_i)"
        NS_READY=$(oc get certificates -n "${NS_NAME}" -l fairness-test=true -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
        TOTAL_READY=$((TOTAL_READY + NS_READY))
    done

    echo "${ELAPSED},${TOTAL_READY},${TOTAL_CERTS}" >> "${PROGRESS_FILE}"
    printf "\r  Ready: ${TOTAL_READY}/${TOTAL_CERTS} - ${ELAPSED}s elapsed"

    if [[ ${TOTAL_READY} -ge ${TOTAL_CERTS} ]]; then
        echo ""
        echo "  All certificates ready!"
        break
    fi

    sleep ${POLL_INTERVAL}
    ELAPSED=$((ELAPSED + POLL_INTERVAL))
done

END_TIME=$(date +%s)
TOTAL_DURATION=$((END_TIME - START_TIME))

# Step 4: Analyze per-namespace timing (fairness)
echo ""
echo "[4/5] Analyzing per-namespace fairness..."

FAIRNESS_FILE="${RUN_DIR}/per-namespace-timing.csv"
echo "namespace,total_certs,ready_certs,first_ready_s,last_ready_s,median_ready_s" > "${FAIRNESS_FILE}"

for ns_i in $(seq 1 "${NUM_NS}"); do
    NS_NAME="perf-fairness-$(printf "%02d" $ns_i)"

    CERTS_JSON=$(oc get certificates -n "${NS_NAME}" -l fairness-test=true -o json 2>/dev/null)
    NS_TOTAL=$(echo "${CERTS_JSON}" | jq '.items | length')
    NS_READY=$(echo "${CERTS_JSON}" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')

    # Get per-cert durations for this namespace
    DURATIONS=$(echo "${CERTS_JSON}" | jq -r '
      .items[] |
      select(.status.conditions[]? | select(.type=="Ready" and .status=="True")) |
      {
        created: .metadata.creationTimestamp,
        ready: (.status.conditions[] | select(.type=="Ready") | .lastTransitionTime)
      } |
      "\(.created) \(.ready)"
    ' | while read -r created ready; do
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
    done)

    if [[ -n "${DURATIONS}" ]]; then
        SORTED=$(echo "${DURATIONS}" | sort -n)
        COUNT=$(echo "${SORTED}" | wc -l | tr -d ' ')
        FIRST=$(echo "${SORTED}" | head -1)
        LAST=$(echo "${SORTED}" | tail -1)
        MEDIAN_IDX=$(( (COUNT + 1) / 2 ))
        MEDIAN=$(echo "${SORTED}" | sed -n "${MEDIAN_IDX}p")
    else
        FIRST="N/A"
        LAST="N/A"
        MEDIAN="N/A"
    fi

    echo "${NS_NAME},${NS_TOTAL},${NS_READY},${FIRST},${LAST},${MEDIAN}" >> "${FAIRNESS_FILE}"
    printf "  %-25s %3d/%3d ready | first: %4ss | last: %4ss | median: %4ss\n" \
        "${NS_NAME}" "${NS_READY}" "${NS_TOTAL}" "${FIRST}" "${LAST}" "${MEDIAN}"
done

# Step 5: Fairness score
echo ""
echo "[5/5] Computing fairness metrics..."

# Read last_ready_s column and compute std deviation as fairness indicator
LAST_TIMES=$(awk -F',' 'NR>1 && $5!="N/A" {print $5}' "${FAIRNESS_FILE}")
if [[ -n "${LAST_TIMES}" ]]; then
    MEAN=$(echo "${LAST_TIMES}" | awk '{sum+=$1} END {printf "%.1f", sum/NR}')
    STDDEV=$(echo "${LAST_TIMES}" | awk -v mean="${MEAN}" '{sum+=($1-mean)^2} END {printf "%.1f", sqrt(sum/NR)}')
    MIN_LAST=$(echo "${LAST_TIMES}" | sort -n | head -1)
    MAX_LAST=$(echo "${LAST_TIMES}" | sort -n | tail -1)
    SPREAD=$((MAX_LAST - MIN_LAST))
else
    MEAN="N/A"
    STDDEV="N/A"
    MIN_LAST="N/A"
    MAX_LAST="N/A"
    SPREAD="N/A"
fi

cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "test_type": "multi_namespace_fairness",
  "num_namespaces": ${NUM_NS},
  "certs_per_namespace": ${CERTS_PER_NS},
  "num_certificates": ${TOTAL_CERTS},
  "issuance_duration_seconds": ${TOTAL_DURATION},
  "certificates_ready": ${TOTAL_READY:-0},
  "certificates_failed": $((TOTAL_CERTS - ${TOTAL_READY:-0})),
  "fairness": {
    "mean_last_ready_s": "${MEAN}",
    "stddev_last_ready_s": "${STDDEV}",
    "min_namespace_completion_s": "${MIN_LAST}",
    "max_namespace_completion_s": "${MAX_LAST}",
    "spread_s": "${SPREAD}"
  },
  "rate_certs_per_minute": $(echo "scale=2; ${TOTAL_CERTS} * 60 / ${TOTAL_DURATION}" | bc 2>/dev/null || echo 0),
  "timing": {
    "min_seconds": "${MIN_LAST}",
    "p50_seconds": "${MEAN}",
    "p90_seconds": "N/A",
    "p99_seconds": "N/A",
    "max_seconds": "${MAX_LAST}"
  }
}
EOF

echo ""
echo "================================================================"
echo "  FAIRNESS TEST RESULTS: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Namespaces:          ${NUM_NS}"
echo "  Certs per NS:        ${CERTS_PER_NS}"
echo "  Total:               ${TOTAL_CERTS}"
echo "  Total Duration:      ${TOTAL_DURATION}s"
echo ""
echo "  Fairness Metrics:"
echo "    Mean completion:   ${MEAN}s"
echo "    Std deviation:     ${STDDEV}s (lower = more fair)"
echo "    Fastest NS:        ${MIN_LAST}s"
echo "    Slowest NS:        ${MAX_LAST}s"
echo "    Spread:            ${SPREAD}s"
echo ""
echo "  Interpretation:"
if [[ "${SPREAD}" != "N/A" ]] && [[ ${SPREAD} -lt 5 ]]; then
    echo "    FAIR - All namespaces completed within ${SPREAD}s of each other"
elif [[ "${SPREAD}" != "N/A" ]] && [[ ${SPREAD} -lt 20 ]]; then
    echo "    ACCEPTABLE - Some variance (${SPREAD}s spread) but no starvation"
elif [[ "${SPREAD}" != "N/A" ]]; then
    echo "    UNFAIR - ${SPREAD}s spread indicates some namespaces are starved"
fi
echo ""
echo "  Results saved to: ${RUN_DIR}/"
echo "================================================================"

# Auto-generate report
if [[ -x "${SCRIPT_DIR}/14-generate-report.sh" ]]; then
    echo ""
    "${SCRIPT_DIR}/14-generate-report.sh" 2>/dev/null && echo "Report updated: results/report-latest/" || true
fi

# Cleanup helper
echo ""
echo "To clean up: oc delete ns -l fairness-test=true"
