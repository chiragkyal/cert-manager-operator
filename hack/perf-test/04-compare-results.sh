#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RESULTS_DIR="${SCRIPT_DIR}/results"

echo "=== cert-manager Performance Test Results Comparison ==="
echo ""

if [[ ! -d "${RESULTS_DIR}" ]] || [[ -z "$(ls -A "${RESULTS_DIR}" 2>/dev/null)" ]]; then
    echo "No results found in ${RESULTS_DIR}/"
    echo "Run tests first with: ./02-run-test.sh <scenario> <num-certs>"
    exit 1
fi

# Print header
printf "%-40s | %6s | %5s | %5s | %7s | %6s | %6s | %6s | %6s | %10s\n" \
    "Run" "Certs" "Ready" "Fail" "Total-s" "P50-s" "P90-s" "P99-s" "Max-s" "Rate/min"
printf "%-40s-+-%6s-+-%5s-+-%5s-+-%7s-+-%6s-+-%6s-+-%6s-+-%6s-+-%10s\n" \
    "$(printf '%0.s-' {1..40})" "------" "-----" "-----" "-------" "------" "------" "------" "------" "----------"

# Iterate through all result directories
for RUN_DIR in "${RESULTS_DIR}"/*/; do
    SUMMARY="${RUN_DIR}summary.json"
    if [[ ! -f "${SUMMARY}" ]]; then
        continue
    fi

    RUN_NAME=$(basename "${RUN_DIR}")
    SCENARIO=$(jq -r '.scenario' "${SUMMARY}")
    NUM_CERTS=$(jq -r '.num_certificates' "${SUMMARY}")
    READY=$(jq -r '.certificates_ready' "${SUMMARY}")
    FAILED=$(jq -r '.certificates_failed' "${SUMMARY}")
    TOTAL=$(jq -r '.issuance_duration_seconds' "${SUMMARY}")
    P50=$(jq -r '.timing.p50_seconds' "${SUMMARY}")
    P90=$(jq -r '.timing.p90_seconds' "${SUMMARY}")
    P99=$(jq -r '.timing.p99_seconds' "${SUMMARY}")
    MAX=$(jq -r '.timing.max_seconds' "${SUMMARY}")
    RATE=$(jq -r '.rate_certs_per_minute' "${SUMMARY}")

    printf "%-40s | %6s | %5s | %5s | %7s | %6s | %6s | %6s | %6s | %10s\n" \
        "${RUN_NAME}" "${NUM_CERTS}" "${READY}" "${FAILED}" "${TOTAL}" "${P50}" "${P90}" "${P99}" "${MAX}" "${RATE}"
done

echo ""
echo "---"
echo ""

# Group by scenario for comparison
echo "=== Summary by Scenario ==="
echo ""

for SCENARIO in baseline moderate aggressive; do
    RUNS=$(find "${RESULTS_DIR}" -name "summary.json" -path "*${SCENARIO}*" 2>/dev/null)
    if [[ -z "${RUNS}" ]]; then
        continue
    fi

    echo "--- ${SCENARIO} ---"
    for SUMMARY in ${RUNS}; do
        RUN_DIR=$(dirname "${SUMMARY}")
        RUN_NAME=$(basename "${RUN_DIR}")
        NUM_CERTS=$(jq -r '.num_certificates' "${SUMMARY}")
        TOTAL=$(jq -r '.issuance_duration_seconds' "${SUMMARY}")
        RATE=$(jq -r '.rate_certs_per_minute' "${SUMMARY}")
        P50=$(jq -r '.timing.p50_seconds' "${SUMMARY}")
        P90=$(jq -r '.timing.p90_seconds' "${SUMMARY}")
        echo "  ${NUM_CERTS} certs: ${TOTAL}s total, ${RATE} certs/min, P50=${P50}s, P90=${P90}s"
    done
    echo ""
done

# Compute improvement ratios if both baseline and tuned exist
echo "=== Improvement Analysis ==="
echo ""

BASELINE_RUNS=$(find "${RESULTS_DIR}" -name "summary.json" -path "*baseline*" 2>/dev/null | head -1)
if [[ -z "${BASELINE_RUNS}" ]]; then
    echo "No baseline results found. Run baseline first to compute improvements."
    exit 0
fi

BASELINE_DURATION=$(jq -r '.issuance_duration_seconds' "${BASELINE_RUNS}")
BASELINE_CERTS=$(jq -r '.num_certificates' "${BASELINE_RUNS}")
BASELINE_P50=$(jq -r '.timing.p50_seconds' "${BASELINE_RUNS}")

for SCENARIO in moderate aggressive; do
    TUNED_RUN=$(find "${RESULTS_DIR}" -name "summary.json" -path "*${SCENARIO}*" 2>/dev/null | head -1)
    if [[ -z "${TUNED_RUN}" ]]; then
        continue
    fi

    TUNED_DURATION=$(jq -r '.issuance_duration_seconds' "${TUNED_RUN}")
    TUNED_CERTS=$(jq -r '.num_certificates' "${TUNED_RUN}")
    TUNED_P50=$(jq -r '.timing.p50_seconds' "${TUNED_RUN}")

    if [[ "${TUNED_CERTS}" == "${BASELINE_CERTS}" ]] && [[ ${TUNED_DURATION} -gt 0 ]]; then
        SPEEDUP=$(echo "scale=2; ${BASELINE_DURATION} / ${TUNED_DURATION}" | bc 2>/dev/null || echo "?")
        P50_IMPROVEMENT=$(echo "scale=2; ${BASELINE_P50} / ${TUNED_P50}" | bc 2>/dev/null || echo "?")
        echo "${SCENARIO} vs baseline (${BASELINE_CERTS} certs):"
        echo "  Total time: ${BASELINE_DURATION}s -> ${TUNED_DURATION}s (${SPEEDUP}x faster)"
        echo "  P50 time:   ${BASELINE_P50}s -> ${TUNED_P50}s (${P50_IMPROVEMENT}x faster)"
        echo ""
    else
        echo "${SCENARIO}: Different cert counts (${TUNED_CERTS} vs ${BASELINE_CERTS}), manual comparison needed."
        echo ""
    fi
done
