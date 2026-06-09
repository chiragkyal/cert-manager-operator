#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMESPACE="cert-perf-test"
RESULTS_DIR="${SCRIPT_DIR}/results"

usage() {
    echo "Usage: $0 <scenario-name> <num-certificates>"
    echo ""
    echo "Runs an ACME (HTTP01) issuance test using the local Pebble server."
    echo "This exercises --max-concurrent-challenges and the ACME order/challenge pipeline."
    echo ""
    echo "Prerequisites:"
    echo "  - Run ./01-setup.sh first"
    echo "  - Run ./15-setup-acme.sh to deploy Pebble"
    echo ""
    echo "Examples:"
    echo "  $0 baseline-acme 50"
    echo "  $0 moderate-acme 100"
    echo "  $0 aggressive-acme 200"
    exit 1
}

if [[ $# -lt 2 ]]; then
    usage
fi

SCENARIO="${1}"
NUM_CERTS="${2}"
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RUN_NAME="${SCENARIO}-${NUM_CERTS}certs-acme-${TIMESTAMP}"
RUN_DIR="${RESULTS_DIR}/${RUN_NAME}"
mkdir -p "${RUN_DIR}"

# Auto-detect the cluster apps domain for DNS resolution during self-checks
APPS_DOMAIN=$(oc get ingresses.config.openshift.io/cluster -o jsonpath='{.spec.domain}' 2>/dev/null || echo "apps.example.com")

echo "=== ACME Performance Test ==="
echo "Scenario:     ${SCENARIO}"
echo "Certificates: ${NUM_CERTS}"
echo "Issuer:       perf-test-acme-pebble (HTTP01)"
echo "Apps Domain:  ${APPS_DOMAIN}"
echo "Run name:     ${RUN_NAME}"
echo ""

# Verify Pebble is running
if ! oc get deployment pebble -n pebble &>/dev/null; then
    echo "ERROR: Pebble not deployed. Run ./15-setup-acme.sh first."
    exit 1
fi

if ! oc get clusterissuer perf-test-acme-pebble &>/dev/null; then
    echo "ERROR: ClusterIssuer 'perf-test-acme-pebble' not found."
    exit 1
fi

# Record controller config
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].args}' | jq . > "${RUN_DIR}/controller-args.json" 2>/dev/null || echo "[]" > "${RUN_DIR}/controller-args.json"
oc get deployment cert-manager -n cert-manager -o jsonpath='{.spec.template.spec.containers[0].resources}' | jq . > "${RUN_DIR}/controller-resources.json" 2>/dev/null || echo "{}" > "${RUN_DIR}/controller-resources.json"

# Clean previous
echo "[1/5] Cleaning existing ACME test certificates..."
oc delete certificates -n "${NAMESPACE}" -l test-type=acme --wait=false 2>/dev/null || true
oc delete challenges -n "${NAMESPACE}" --all --wait=false 2>/dev/null || true
oc delete orders -n "${NAMESPACE}" --all --wait=false 2>/dev/null || true
sleep 10

# Generate ACME certificates
echo "[2/5] Creating ${NUM_CERTS} Certificate resources (ACME HTTP01)..."

BULK_FILE="${RUN_DIR}/certificates.yaml"
> "${BULK_FILE}"

for i in $(seq 1 "${NUM_CERTS}"); do
    cat >> "${BULK_FILE}" << EOF
apiVersion: cert-manager.io/v1
kind: Certificate
metadata:
  name: perf-acme-cert-$(printf "%04d" $i)
  namespace: ${NAMESPACE}
  labels:
    perf-test: "true"
    test-type: "acme"
    scenario: "${SCENARIO}"
spec:
  secretName: perf-acme-secret-$(printf "%04d" $i)
  duration: 2160h
  renewBefore: 360h
  privateKey:
    algorithm: ECDSA
    size: 256
  dnsNames:
    - "perf-acme-$(printf "%04d" $i).${APPS_DOMAIN}"
  issuerRef:
    name: perf-test-acme-pebble
    kind: ClusterIssuer
    group: cert-manager.io
---
EOF
done

START_TIME=$(date +%s)
oc apply -f "${BULK_FILE}" 2>&1 | tail -5
echo "  ... (${NUM_CERTS} ACME certificates submitted)"

SUBMIT_TIME=$(date +%s)
SUBMIT_DURATION=$((SUBMIT_TIME - START_TIME))
echo "  Submission took ${SUBMIT_DURATION}s"

# Wait for completion
echo "[3/5] Waiting for ACME certificates to become Ready..."
echo "  (This involves: Order -> Challenge -> Validation -> Finalize -> Ready)"
echo ""

POLL_INTERVAL=5
MAX_WAIT=1800
ELAPSED=0

PROGRESS_FILE="${RUN_DIR}/progress.csv"
echo "elapsed_seconds,ready_count,total,challenges_processing,orders_pending" > "${PROGRESS_FILE}"

while [[ ${ELAPSED} -lt ${MAX_WAIT} ]]; do
    READY_COUNT=$(oc get certificates -n "${NAMESPACE}" -l test-type=acme -o json 2>/dev/null | jq '[.items[] | select(.status.conditions[]? | select(.type=="Ready" and .status=="True"))] | length' | tr -d '[:space:]')
    CHALLENGES=$(oc get challenges -n "${NAMESPACE}" --no-headers 2>/dev/null | wc -l | tr -d '[:space:]')
    ORDERS=$(oc get orders -n "${NAMESPACE}" --no-headers 2>/dev/null | grep -c "pending" 2>/dev/null || true)
    READY_COUNT=$(echo "${READY_COUNT}" | tr -cd '0-9')
    CHALLENGES=$(echo "${CHALLENGES}" | tr -cd '0-9')
    ORDERS=$(echo "${ORDERS}" | tr -cd '0-9')
    READY_COUNT=${READY_COUNT:-0}
    CHALLENGES=${CHALLENGES:-0}
    ORDERS=${ORDERS:-0}

    echo "${ELAPSED},${READY_COUNT},${NUM_CERTS},${CHALLENGES},${ORDERS}" >> "${PROGRESS_FILE}"

    PCT=$((READY_COUNT * 100 / NUM_CERTS))
    printf "\r  Ready: %d/%d [%3d%%] | Challenges: %d | Orders pending: %d | %ds elapsed" \
        "${READY_COUNT}" "${NUM_CERTS}" "${PCT}" "${CHALLENGES}" "${ORDERS}" "${ELAPSED}"

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

echo ""

# Collect results
echo "[4/5] Collecting results..."

oc get certificates -n "${NAMESPACE}" -l test-type=acme -o json > "${RUN_DIR}/certificates-final.json"

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

echo "[5/5] Writing summary..."

cat > "${RUN_DIR}/summary.json" << EOF
{
  "scenario": "${SCENARIO}",
  "test_type": "acme_http01",
  "issuer": "perf-test-acme-pebble",
  "num_certificates": ${NUM_CERTS},
  "submit_duration_seconds": ${SUBMIT_DURATION},
  "total_duration_seconds": ${TOTAL_DURATION},
  "issuance_duration_seconds": ${ISSUANCE_DURATION},
  "certificates_ready": ${FINAL_READY},
  "certificates_failed": ${FINAL_FAILED},
  "controller_restarts": ${RESTARTS},
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
echo "  ACME TEST RESULTS: ${RUN_NAME}"
echo "================================================================"
echo ""
echo "  Scenario:            ${SCENARIO}"
echo "  Issuer:              ACME HTTP01 (Pebble)"
echo "  Total Certificates:  ${NUM_CERTS}"
echo "  Ready:               ${FINAL_READY}"
echo "  Failed:              ${FINAL_FAILED}"
echo "  Controller restarts: ${RESTARTS}"
echo ""
echo "  Total Duration:      ${TOTAL_DURATION}s"
echo "  Issuance Duration:   ${ISSUANCE_DURATION}s"
echo "  Rate:                $(echo "scale=1; ${FINAL_READY} * 60 / ${ISSUANCE_DURATION}" | bc 2>/dev/null || echo "?") certs/min"
echo ""
echo "  Per-Certificate Timing (includes ACME order+challenge flow):"
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
