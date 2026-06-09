#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

DURATION="${1:-300}"
INTERVAL="${2:-10}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_DIR="${RESULTS_DIR}/cluster-impact-${TIMESTAMP}"
mkdir -p "${RUN_DIR}"

echo "=== Cluster Impact & API Throttle Monitor ==="
echo "Duration:  ${DURATION}s"
echo "Interval:  ${INTERVAL}s"
echo "Output:    ${RUN_DIR}/"
echo ""
echo "Run this IN PARALLEL with a test (in another terminal):"
echo "  ./02-run-test.sh <scenario> <num-certs>"
echo ""
echo "Collecting:"
echo "  - API server request latency (P99)"
echo "  - API server throttle/rejection count"
echo "  - etcd request latency"
echo "  - cert-manager controller CPU/memory"
echo "  - Other operator pod health"
echo ""
echo "Press Ctrl+C to stop early."
echo ""

# CSV headers
cat > "${RUN_DIR}/api-metrics.csv" << 'EOF'
timestamp,ctrl_cpu_m,ctrl_mem_mi,ctrl_restarts,apiserver_p99_mutating_ms,apiserver_p99_readonly_ms,throttled_requests,etcd_p99_ms
EOF

TOKEN=$(oc whoami -t 2>/dev/null || echo "")
API_URL=$(oc whoami --show-server)
ELAPSED=0

# Snapshot of other operators at start
echo "Recording baseline cluster operator status..."
oc get clusteroperators -o json > "${RUN_DIR}/operators-before.json" 2>/dev/null || true

while [[ ${ELAPSED} -lt ${DURATION} ]]; do
    TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Controller metrics
    CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "unknown")
    RESTARTS=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
    TOP_LINE=$(oc adm top pod "${CTRL_POD}" -n cert-manager --no-headers 2>/dev/null || echo "unknown 0m 0Mi")
    CPU=$(echo "${TOP_LINE}" | awk '{print $2}' | sed 's/m$//' || echo "0")
    MEM=$(echo "${TOP_LINE}" | awk '{print $3}' | sed 's/Mi$//' || echo "0")

    # API server metrics (via prometheus if accessible)
    API_P99_MUTATING="N/A"
    API_P99_READONLY="N/A"
    THROTTLED="N/A"
    ETCD_P99="N/A"

    if [[ -n "${TOKEN}" ]]; then
        # Try to get metrics from prometheus/thanos
        PROM_URL=$(oc get route -n openshift-monitoring thanos-querier -o jsonpath='{.spec.host}' 2>/dev/null || echo "")

        if [[ -n "${PROM_URL}" ]]; then
            # API server mutating P99
            RESULT=$(curl -sk -H "Authorization: Bearer ${TOKEN}" \
                "https://${PROM_URL}/api/v1/query?query=histogram_quantile(0.99,rate(apiserver_request_duration_seconds_bucket{verb=~\"POST|PUT|PATCH|DELETE\"}[2m]))" \
                2>/dev/null | jq -r '.data.result[0].value[1] // "N/A"' 2>/dev/null || echo "N/A")
            if [[ "${RESULT}" != "N/A" ]] && [[ "${RESULT}" != "null" ]]; then
                API_P99_MUTATING=$(echo "scale=1; ${RESULT} * 1000" | bc 2>/dev/null || echo "N/A")
            fi

            # API server readonly P99
            RESULT=$(curl -sk -H "Authorization: Bearer ${TOKEN}" \
                "https://${PROM_URL}/api/v1/query?query=histogram_quantile(0.99,rate(apiserver_request_duration_seconds_bucket{verb=~\"GET|LIST|WATCH\"}[2m]))" \
                2>/dev/null | jq -r '.data.result[0].value[1] // "N/A"' 2>/dev/null || echo "N/A")
            if [[ "${RESULT}" != "N/A" ]] && [[ "${RESULT}" != "null" ]]; then
                API_P99_READONLY=$(echo "scale=1; ${RESULT} * 1000" | bc 2>/dev/null || echo "N/A")
            fi

            # Throttled requests (Priority & Fairness rejections)
            RESULT=$(curl -sk -H "Authorization: Bearer ${TOKEN}" \
                "https://${PROM_URL}/api/v1/query?query=sum(increase(apiserver_flowcontrol_rejected_requests_total[2m]))" \
                2>/dev/null | jq -r '.data.result[0].value[1] // "0"' 2>/dev/null || echo "N/A")
            THROTTLED="${RESULT}"

            # etcd P99
            RESULT=$(curl -sk -H "Authorization: Bearer ${TOKEN}" \
                "https://${PROM_URL}/api/v1/query?query=histogram_quantile(0.99,rate(etcd_request_duration_seconds_bucket[2m]))" \
                2>/dev/null | jq -r '.data.result[0].value[1] // "N/A"' 2>/dev/null || echo "N/A")
            if [[ "${RESULT}" != "N/A" ]] && [[ "${RESULT}" != "null" ]]; then
                ETCD_P99=$(echo "scale=1; ${RESULT} * 1000" | bc 2>/dev/null || echo "N/A")
            fi
        fi
    fi

    echo "${TS},${CPU},${MEM},${RESTARTS},${API_P99_MUTATING},${API_P99_READONLY},${THROTTLED},${ETCD_P99}" >> "${RUN_DIR}/api-metrics.csv"

    printf "\r  [%4ds] CPU:%5sm Mem:%5sMi Restarts:%s | API-mut-P99:%sms API-ro-P99:%sms Throttled:%s etcd-P99:%sms" \
        "${ELAPSED}" "${CPU}" "${MEM}" "${RESTARTS}" \
        "${API_P99_MUTATING}" "${API_P99_READONLY}" "${THROTTLED}" "${ETCD_P99}"

    sleep ${INTERVAL}
    ELAPSED=$((ELAPSED + INTERVAL))
done

echo ""
echo ""

# Snapshot of other operators at end
oc get clusteroperators -o json > "${RUN_DIR}/operators-after.json" 2>/dev/null || true

# Check if any operator degraded during test
echo "=== Cluster Impact Analysis ==="
echo ""
echo "Operators that became Degraded during test:"
DEGRADED_BEFORE=$(jq -r '[.items[] | select(.status.conditions[]? | select(.type=="Degraded" and .status=="True")) | .metadata.name] | sort[]' "${RUN_DIR}/operators-before.json" 2>/dev/null || echo "")
DEGRADED_AFTER=$(jq -r '[.items[] | select(.status.conditions[]? | select(.type=="Degraded" and .status=="True")) | .metadata.name] | sort[]' "${RUN_DIR}/operators-after.json" 2>/dev/null || echo "")

NEW_DEGRADED=$(comm -13 <(echo "${DEGRADED_BEFORE}" | sort) <(echo "${DEGRADED_AFTER}" | sort) 2>/dev/null || echo "")
if [[ -z "${NEW_DEGRADED}" ]]; then
    echo "  None (no new degradations)"
else
    echo "  WARNING: New degradations detected:"
    echo "${NEW_DEGRADED}" | sed 's/^/    /'
fi
echo ""

# Summary of throttle data
echo "API Throttle Summary:"
TOTAL_THROTTLED=$(awk -F',' 'NR>1 && $7!="N/A" {sum+=$7} END {print sum+0}' "${RUN_DIR}/api-metrics.csv")
echo "  Total throttled requests during monitoring: ${TOTAL_THROTTLED}"
echo ""

echo "Results saved to: ${RUN_DIR}/"
echo ""
echo "Key files:"
echo "  - api-metrics.csv        : Time-series of API server and controller metrics"
echo "  - operators-before.json  : Cluster operator state before test"
echo "  - operators-after.json   : Cluster operator state after test"
