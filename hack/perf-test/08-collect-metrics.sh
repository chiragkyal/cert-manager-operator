#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"
METRICS_DIR="${RESULTS_DIR}/metrics-$(date +%Y%m%d-%H%M%S)"
mkdir -p "${METRICS_DIR}"

DURATION="${1:-300}"
INTERVAL="${2:-10}"

echo "=== cert-manager Metrics Collector ==="
echo "Duration:  ${DURATION}s"
echo "Interval:  ${INTERVAL}s"
echo "Output:    ${METRICS_DIR}/"
echo ""
echo "Collecting: controller CPU/memory, API server latency, cert counts"
echo "Press Ctrl+C to stop early."
echo ""

# CSV headers
echo "timestamp,ctrl_cpu_cores,ctrl_memory_mi,certs_ready,certs_pending,certs_failed,ctrl_restarts" > "${METRICS_DIR}/timeseries.csv"

CTRL_POD=""
ELAPSED=0

while [[ ${ELAPSED} -lt ${DURATION} ]]; do
    TS=$(date -u +%Y-%m-%dT%H:%M:%SZ)

    # Get controller pod (may change after rollout)
    CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}' 2>/dev/null || echo "unknown")
    RESTARTS=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")

    # Resource usage
    TOP_LINE=$(oc adm top pod "${CTRL_POD}" -n cert-manager --no-headers 2>/dev/null || echo "unknown 0m 0Mi")
    CPU=$(echo "${TOP_LINE}" | awk '{print $2}' | sed 's/m$//')
    MEM=$(echo "${TOP_LINE}" | awk '{print $3}' | sed 's/Mi$//')

    # Convert CPU millicores to cores for readability
    CPU_CORES=$(echo "scale=3; ${CPU:-0} / 1000" | bc 2>/dev/null || echo "0")

    # Certificate status counts
    CERT_JSON=$(oc get certificates -n cert-perf-test -l perf-test=true -o json 2>/dev/null || echo '{"items":[]}')
    CERTS_READY=$(echo "${CERT_JSON}" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length')
    CERTS_FAILED=$(echo "${CERT_JSON}" | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="False" and .reason!="Pending" and .reason!="InProgress"))] | length')
    TOTAL_CERTS=$(echo "${CERT_JSON}" | jq '.items | length')
    CERTS_PENDING=$((TOTAL_CERTS - CERTS_READY - CERTS_FAILED))

    echo "${TS},${CPU_CORES},${MEM:-0},${CERTS_READY},${CERTS_PENDING},${CERTS_FAILED},${RESTARTS}" >> "${METRICS_DIR}/timeseries.csv"

    printf "\r  [%4ds] CPU: %sm | Mem: %sMi | Ready: %s | Pending: %s | Failed: %s | Restarts: %s" \
        "${ELAPSED}" "${CPU:-?}" "${MEM:-?}" "${CERTS_READY}" "${CERTS_PENDING}" "${CERTS_FAILED}" "${RESTARTS}"

    sleep ${INTERVAL}
    ELAPSED=$((ELAPSED + INTERVAL))
done

echo ""
echo ""

# Collect point-in-time snapshots
echo "Collecting additional metrics..."

# Controller logs (last 5 min)
oc logs deployment/cert-manager -n cert-manager --since=5m > "${METRICS_DIR}/controller-logs.txt" 2>/dev/null || true

# CertificateRequest status
oc get certificaterequests -n cert-perf-test -o wide > "${METRICS_DIR}/certificaterequests.txt" 2>/dev/null || true

# Events
oc get events -n cert-perf-test --sort-by='.lastTimestamp' > "${METRICS_DIR}/events.txt" 2>/dev/null || true

# API server metrics (if accessible)
echo "Collecting API server metrics..."
TOKEN=$(oc whoami -t 2>/dev/null || echo "")
API_URL=$(oc whoami --show-server)
if [[ -n "${TOKEN}" ]]; then
    curl -sk -H "Authorization: Bearer ${TOKEN}" \
        "${API_URL}/metrics" 2>/dev/null | grep -E "(apiserver_request_duration|apiserver_current_inflight)" \
        > "${METRICS_DIR}/apiserver-metrics.txt" 2>/dev/null || echo "Could not collect API server metrics" > "${METRICS_DIR}/apiserver-metrics.txt"
fi

echo ""
echo "=== Metrics collection complete ==="
echo "Output: ${METRICS_DIR}/"
echo ""
echo "Files:"
ls -la "${METRICS_DIR}/"
