#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <parameter> <values...>"
    echo ""
    echo "Progressively increases a single parameter to find the breaking/saturation point."
    echo "Runs a 100-cert test at each value and records results."
    echo ""
    echo "Examples:"
    echo "  $0 concurrent-workers 5 10 15 20 30 50"
    echo "  $0 kube-api-qps 20 50 100 200 500"
    echo "  $0 kube-api-burst 50 100 200 500 1000"
    echo ""
    echo "Prerequisites: 01-setup.sh must have been run."
    exit 1
}

if [[ $# -lt 3 ]]; then
    usage
fi

PARAMETER="${1}"
shift
VALUES=("$@")
NUM_CERTS=100

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="saturation-${PARAMETER}-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

echo "=== Saturation / Breaking Point Test ==="
echo "Parameter:  --${PARAMETER}"
echo "Values:     ${VALUES[*]}"
echo "Certs/run:  ${NUM_CERTS}"
echo "Output:     ${RUN_DIR}/"
echo ""

# Map parameter name to flag
get_flag() {
    local param="${1}"
    local value="${2}"
    case "${param}" in
        concurrent-workers) echo "--concurrent-workers=${value}" ;;
        kube-api-qps) echo "--kube-api-qps=${value}" ;;
        kube-api-burst) echo "--kube-api-burst=${value}" ;;
        max-concurrent-challenges) echo "--max-concurrent-challenges=${value}" ;;
        dns01-check-retry-period) echo "--dns01-check-retry-period=${value}" ;;
        *) echo "ERROR: Unknown parameter ${param}"; exit 1 ;;
    esac
}

# Results summary file
SUMMARY_FILE="${RUN_DIR}/saturation-results.csv"
echo "parameter_value,issuance_seconds,rate_certs_per_min,p50_s,p90_s,p99_s,max_s,ctrl_cpu_m,ctrl_mem_mi,restarts,status" > "${SUMMARY_FILE}"

for VALUE in "${VALUES[@]}"; do
    echo ""
    echo "========================================"
    echo "  Testing --${PARAMETER}=${VALUE}"
    echo "========================================"

    # Apply configuration
    FLAG=$(get_flag "${PARAMETER}" "${VALUE}")

    cat <<EOF | oc apply -f -
apiVersion: operator.openshift.io/v1alpha1
kind: CertManager
metadata:
  name: cluster
spec:
  managementState: Managed
  logLevel: Normal
  unsupportedConfigOverrides:
    controller:
      args:
        - "${FLAG}"
    webhook:
      args: []
    cainjector:
      args: []
  controllerConfig:
    overrideResources:
      requests:
        cpu: "1000m"
        memory: "512Mi"
      limits:
        cpu: "4000m"
        memory: "2Gi"
EOF

    echo "  Waiting for rollout..."
    sleep 10
    oc rollout status deployment/cert-manager -n cert-manager --timeout=120s
    sleep 20

    # Clean previous test certs
    oc delete certificates -n "${NAMESPACE}" -l perf-test=true --wait=false 2>/dev/null || true
    oc delete secrets -n "${NAMESPACE}" -l "cert-manager.io/certificate-name" --wait=false 2>/dev/null || true
    sleep 10

    # Run test
    echo "  Running ${NUM_CERTS}-cert test..."
    TEST_OUTPUT=$("${SCRIPT_DIR}/02-run-test.sh" "sat-${PARAMETER}-${VALUE}" "${NUM_CERTS}" 2>&1)
    echo "${TEST_OUTPUT}" | tail -20

    # Extract results from the latest run directory
    LATEST_RUN=$(ls -td "${RESULTS_DIR}"/sat-${PARAMETER}-${VALUE}-* 2>/dev/null | head -1)
    if [[ -n "${LATEST_RUN}" ]] && [[ -f "${LATEST_RUN}/summary.json" ]]; then
        ISSUANCE=$(jq -r '.issuance_duration_seconds' "${LATEST_RUN}/summary.json")
        RATE=$(jq -r '.rate_certs_per_minute' "${LATEST_RUN}/summary.json")
        P50=$(jq -r '.timing.p50_seconds' "${LATEST_RUN}/summary.json")
        P90=$(jq -r '.timing.p90_seconds' "${LATEST_RUN}/summary.json")
        P99=$(jq -r '.timing.p99_seconds' "${LATEST_RUN}/summary.json")
        MAX=$(jq -r '.timing.max_seconds' "${LATEST_RUN}/summary.json")
    else
        ISSUANCE="ERROR"
        RATE="0"
        P50="N/A"
        P90="N/A"
        P99="N/A"
        MAX="N/A"
    fi

    # Get resource usage
    CTRL_POD=$(oc get pods -n cert-manager -l app.kubernetes.io/component=controller -o jsonpath='{.items[0].metadata.name}' 2>/dev/null)
    RESTARTS=$(oc get pod "${CTRL_POD}" -n cert-manager -o jsonpath='{.status.containerStatuses[0].restartCount}' 2>/dev/null || echo "0")
    TOP_LINE=$(oc adm top pod "${CTRL_POD}" -n cert-manager --no-headers 2>/dev/null || echo "unknown 0m 0Mi")
    CPU_POST=$(echo "${TOP_LINE}" | awk '{print $2}' | sed 's/m$//' || echo "0")
    MEM_POST=$(echo "${TOP_LINE}" | awk '{print $3}' | sed 's/Mi$//' || echo "0")

    # Determine status
    STATUS="OK"
    if [[ "${RESTARTS}" -gt 0 ]]; then
        STATUS="RESTART"
    fi
    if [[ "${ISSUANCE}" == "ERROR" ]]; then
        STATUS="ERROR"
    fi

    echo "${VALUE},${ISSUANCE},${RATE},${P50},${P90},${P99},${MAX},${CPU_POST},${MEM_POST},${RESTARTS},${STATUS}" >> "${SUMMARY_FILE}"
done

# Print final summary
echo ""
echo ""
echo "================================================================"
echo "  SATURATION TEST RESULTS: --${PARAMETER}"
echo "================================================================"
echo ""
printf "  %-12s | %8s | %10s | %5s | %5s | %5s | %5s | %6s | %6s | %s\n" \
    "Value" "Time(s)" "Rate/min" "P50" "P90" "P99" "Max" "CPU(m)" "Mem" "Status"
printf "  %-12s-+-%8s-+-%10s-+-%5s-+-%5s-+-%5s-+-%5s-+-%6s-+-%6s-+-%s\n" \
    "------------" "--------" "----------" "-----" "-----" "-----" "-----" "------" "------" "------"

while IFS=',' read -r val issuance rate p50 p90 p99 max cpu mem restarts status; do
    [[ "${val}" == "parameter_value" ]] && continue
    printf "  %-12s | %8s | %10s | %5s | %5s | %5s | %5s | %6s | %6s | %s\n" \
        "${val}" "${issuance}" "${rate}" "${p50}" "${p90}" "${p99}" "${max}" "${cpu}" "${mem}" "${status}"
done < "${SUMMARY_FILE}"

echo ""
echo "  Results saved to: ${RUN_DIR}/saturation-results.csv"
echo "================================================================"

# Reset to baseline
echo ""
echo "Resetting to baseline..."
oc apply -f "${SCRIPT_DIR}/scenarios/baseline.yaml" 2>/dev/null
