#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> [start-count]"
    echo ""
    echo "Progressive load ramp test — increases certificate count exponentially"
    echo "to find the sustained throughput ceiling for the current configuration."
    echo ""
    echo "Sequence: 100 → 200 → 400 → 800 (doubles each iteration)"
    echo "At each step, measures issuance time and rate."
    echo "Stops if issuance takes longer than 10 minutes or certs fail."
    echo ""
    echo "Examples:"
    echo "  $0 baseline"
    echo "  $0 aggressive"
    echo "  $0 moderate 200   # start at 200 instead of 100"
    exit 1
}

if [[ $# -lt 1 ]]; then
    usage
fi

SCENARIO="${1}"
START_COUNT="${2:-100}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-progressive-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

ISSUER_NAME="perf-test-ca-issuer"
ISSUER_KIND="Issuer"
MAX_WAIT_PER_STEP=600
EXPONENTIAL_BASE=2

echo "=== Progressive Load Ramp Test ==="
echo "Scenario:     ${SCENARIO}"
echo "Sequence:     ${START_COUNT}, $((START_COUNT * 2)), $((START_COUNT * 4)), $((START_COUNT * 8))"
echo "Max wait/step: ${MAX_WAIT_PER_STEP}s"
echo "Run name:     ${RUN_NAME}"
echo ""

# Record controller config
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq . > "${RUN_DIR}/controller-resources.json" 2>/dev/null || echo "{}" > "${RUN_DIR}/controller-resources.json"

# Results CSV
RESULTS_CSV="${RUN_DIR}/progressive-results.csv"
echo "step,num_certs,issuance_seconds,rate_certs_per_min,p50_s,p90_s,p99_s,max_s,all_ready,ctrl_restarts,status" > "${RESULTS_CSV}"

STEP=0
NUM_CERTS=${START_COUNT}
OVERALL_STATUS="COMPLETED"

while true; do
    STEP=$((STEP + 1))
    echo ""
    echo "========================================"
    echo "  Step ${STEP}: ${NUM_CERTS} certificates"
    echo "========================================"

    # Clean previous certs
    echo "  Cleaning previous certificates..."
    oc delete certificates -n "${NAMESPACE}" -l perf-test=true --wait=false 2>/dev/null || true
    oc delete certificaterequests -n "${NAMESPACE}" --all --wait=false 2>/dev/null || true
    sleep 10

    # Verify controller is healthy
    CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller --no-headers -o custom-columns=NAME:.metadata.name | head -1)
    RESTARTS_BEFORE=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

    # Generate certificates
    echo "  Creating ${NUM_CERTS} Certificate resources..."
    BULK_FILE="${RUN_DIR}/step${STEP}-certificates.yaml"
    > "${BULK_FILE}"

    for i in $(seq 1 "${NUM_CERTS}"); do
        cat >> "${BULK_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: perf-prog-cert-$(printf "%05d" $i)
  namespace: ${NAMESPACE}
  labels:
    perf-test: "true"
    scenario: "${SCENARIO}"
    test-type: "progressive"
    step: "${STEP}"
spec:
  secretName: perf-prog-secret-$(printf "%05d" $i)
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "perf-prog-$(printf "%05d" $i).example.com"
  issuerRef:
    name: ${ISSUER_NAME}
    kind: ${ISSUER_KIND}
    group: cert-manager.io
---
EOF
    done

    START_TIME=$(date +%s)
    oc apply -f "${BULK_FILE}" 2>&1 | tail -3
    SUBMIT_TIME=$(date +%s)
    SUBMIT_DURATION=$((SUBMIT_TIME - START_TIME))
    echo "  Submitted ${NUM_CERTS} certs in ${SUBMIT_DURATION}s"

    # Wait for all to become Ready
    echo "  Waiting for issuance..."
    ELAPSED=0
    POLL_INTERVAL=5
    READY_COUNT=0

    while [[ ${ELAPSED} -lt ${MAX_WAIT_PER_STEP} ]]; do
        READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l test-type=progressive -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length' | tr -cd '0-9')
        READY_COUNT=${READY_COUNT:-0}

        PCT=$((READY_COUNT * 100 / NUM_CERTS))
        printf "\r  Ready: %d/%d [%3d%%] - %ds elapsed" "${READY_COUNT}" "${NUM_CERTS}" "${PCT}" "${ELAPSED}"

        if [[ ${READY_COUNT} -ge ${NUM_CERTS} ]]; then
            break
        fi

        sleep ${POLL_INTERVAL}
        ELAPSED=$((ELAPSED + POLL_INTERVAL))
    done

    END_TIME=$(date +%s)
    ISSUANCE_DURATION=$((END_TIME - SUBMIT_TIME))
    echo ""

    # Collect per-certificate timing
    DURATIONS_FILE="${RUN_DIR}/step${STEP}-durations.txt"
    oc get certificates -n "${NAMESPACE}" -l test-type=progressive -o json 2>/dev/null | jq -r '
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
    done > "${DURATIONS_FILE}"

    # Compute percentiles
    if [[ -s "${DURATIONS_FILE}" ]]; then
        SORTED=$(sort -n "${DURATIONS_FILE}")
        COUNT=$(echo "${SORTED}" | wc -l | tr -d ' ')
        P50_IDX=$(( (COUNT * 50 + 99) / 100 ))
        P90_IDX=$(( (COUNT * 90 + 99) / 100 ))
        P99_IDX=$(( (COUNT * 99 + 99) / 100 ))
        MAX_VAL=$(echo "${SORTED}" | tail -1)
        P50_VAL=$(echo "${SORTED}" | sed -n "${P50_IDX}p")
        P90_VAL=$(echo "${SORTED}" | sed -n "${P90_IDX}p")
        P99_VAL=$(echo "${SORTED}" | sed -n "${P99_IDX}p")
    else
        P50_VAL="N/A"; P90_VAL="N/A"; P99_VAL="N/A"; MAX_VAL="N/A"
    fi

    # Controller health check
    RESTARTS_AFTER=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
    NEW_RESTARTS=$((RESTARTS_AFTER - RESTARTS_BEFORE))

    # Determine status
    if [[ ${READY_COUNT} -ge ${NUM_CERTS} ]]; then
        STEP_STATUS="OK"
    elif [[ ${ELAPSED} -ge ${MAX_WAIT_PER_STEP} ]]; then
        STEP_STATUS="TIMEOUT(${READY_COUNT}/${NUM_CERTS})"
        OVERALL_STATUS="STOPPED_AT_STEP_${STEP}"
    fi

    if [[ ${NEW_RESTARTS} -gt 0 ]]; then
        STEP_STATUS="CRASH(restarts=${NEW_RESTARTS})"
        OVERALL_STATUS="CRASHED_AT_STEP_${STEP}"
    fi

    # Compute rate
    if [[ ${ISSUANCE_DURATION} -gt 0 ]]; then
        RATE=$(echo "scale=2; ${READY_COUNT} * 60 / ${ISSUANCE_DURATION}" | bc 2>/dev/null || echo 0)
    else
        RATE="INF"
    fi

    # Record result
    echo "${STEP},${NUM_CERTS},${ISSUANCE_DURATION},${RATE},${P50_VAL:-0},${P90_VAL:-0},${P99_VAL:-0},${MAX_VAL:-0},${READY_COUNT},${NEW_RESTARTS},${STEP_STATUS}" >> "${RESULTS_CSV}"

    echo ""
    echo "  Result: ${NUM_CERTS} certs | ${ISSUANCE_DURATION}s | ${RATE} certs/min | P50=${P50_VAL}s P90=${P90_VAL}s P99=${P99_VAL}s | ${STEP_STATUS}"

    # Stop conditions
    if [[ "${STEP_STATUS}" != "OK" ]]; then
        echo ""
        echo "  *** STOPPING: Step failed with status=${STEP_STATUS} ***"
        break
    fi

    # Next step: double the count
    NUM_CERTS=$((NUM_CERTS * EXPONENTIAL_BASE))

    # Safety cap at 6400 (3-worker cluster can handle more)
    if [[ ${NUM_CERTS} -gt 6400 ]]; then
        echo ""
        echo "  Reached safety cap (6400 certs). Stopping."
        break
    fi
done

# Summary
echo ""
echo "================================================================"
echo "  PROGRESSIVE LOAD RESULTS: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Scenario: ${SCENARIO}"
echo "  Status:   ${OVERALL_STATUS}"
echo ""
column -t -s ',' "${RESULTS_CSV}" 2>/dev/null || cat "${RESULTS_CSV}"
echo ""
echo "  Results saved to: ${RUN_DIR}/"
echo "================================================================"

# Write summary.json for report integration
LAST_STEP=$(tail -1 "${RESULTS_CSV}")
LAST_RATE=$(echo "${LAST_STEP}" | cut -d',' -f4)
LAST_CERTS=$(echo "${LAST_STEP}" | cut -d',' -f2)
LAST_DUR=$(echo "${LAST_STEP}" | cut -d',' -f3)

cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "test_type": "progressive_load",
  "num_certificates": ${LAST_CERTS},
  "issuance_duration_seconds": ${LAST_DUR},
  "rate_certs_per_minute": ${LAST_RATE:-0},
  "overall_status": "${OVERALL_STATUS}",
  "steps_completed": ${STEP},
  "timing": {
    "min_seconds": "N/A",
    "p50_seconds": "${P50_VAL:-0}",
    "p90_seconds": "${P90_VAL:-0}",
    "p99_seconds": "${P99_VAL:-0}",
    "max_seconds": "${MAX_VAL:-0}"
  }
}
EOF

# Auto-generate report
if [[ -x "${SCRIPT_DIR}/14-generate-report.sh" ]]; then
    echo ""
    "${SCRIPT_DIR}/14-generate-report.sh" 2>/dev/null && echo "Report updated: results/report-latest/" || true
fi
