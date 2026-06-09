#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

NUM_CERTS="${1:-100}"
SLEEP_BETWEEN=60

echo "============================================================"
echo "  FULL PERFORMANCE TEST SUITE"
echo "  Certificates per test: ${NUM_CERTS}"
echo "============================================================"
echo ""
echo "This will run the complete test suite:"
echo "  1. Setup environment"
echo "  2. Baseline test"
echo "  3. Moderate tuning test"
echo "  4. Aggressive tuning test"
echo "  5. DR simulation (aggressive)"
echo "  6. Results comparison"
echo ""
echo "Estimated time: ~30-60 minutes (depending on ${NUM_CERTS} certs)"
echo ""
read -p "Continue? [y/N] " -n 1 -r
echo ""
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 0
fi

echo ""
echo "============================================================"
echo "  STEP 1: Setup"
echo "============================================================"
"${SCRIPT_DIR}/01-setup.sh"
echo ""
sleep 10

echo "============================================================"
echo "  STEP 2: Baseline Test (default parameters)"
echo "============================================================"
"${SCRIPT_DIR}/03-apply-scenario.sh" baseline
sleep 30
"${SCRIPT_DIR}/02-run-test.sh" baseline "${NUM_CERTS}"
echo ""

echo "Cleaning test certs before next scenario..."
oc delete certificates -n cert-perf-test -l perf-test=true --ignore-not-found=true --wait=true 2>/dev/null || true
oc delete secrets -n cert-perf-test -l "cert-manager.io/certificate-name" --ignore-not-found=true 2>/dev/null || true
sleep ${SLEEP_BETWEEN}

echo "============================================================"
echo "  STEP 3: Moderate Tuning Test"
echo "============================================================"
"${SCRIPT_DIR}/03-apply-scenario.sh" moderate
sleep 30
"${SCRIPT_DIR}/02-run-test.sh" moderate "${NUM_CERTS}"
echo ""

echo "Cleaning test certs before next scenario..."
oc delete certificates -n cert-perf-test -l perf-test=true --ignore-not-found=true --wait=true 2>/dev/null || true
oc delete secrets -n cert-perf-test -l "cert-manager.io/certificate-name" --ignore-not-found=true 2>/dev/null || true
sleep ${SLEEP_BETWEEN}

echo "============================================================"
echo "  STEP 4: Aggressive Tuning Test"
echo "============================================================"
"${SCRIPT_DIR}/03-apply-scenario.sh" aggressive
sleep 30
"${SCRIPT_DIR}/02-run-test.sh" aggressive "${NUM_CERTS}"
echo ""

echo "============================================================"
echo "  STEP 5: DR Simulation (aggressive tuning)"
echo "============================================================"
echo "Cleaning before DR test..."
oc delete certificates -n cert-perf-test -l perf-test=true --ignore-not-found=true --wait=true 2>/dev/null || true
oc delete secrets -n cert-perf-test -l "cert-manager.io/certificate-name" --ignore-not-found=true 2>/dev/null || true
sleep 30
"${SCRIPT_DIR}/06-dr-simulation.sh" aggressive-dr "${NUM_CERTS}"
echo ""

echo "============================================================"
echo "  STEP 6: Results Comparison"
echo "============================================================"
"${SCRIPT_DIR}/04-compare-results.sh"

echo ""
echo "============================================================"
echo "  STEP 7: Generate Visual Report"
echo "============================================================"
"${SCRIPT_DIR}/14-generate-report.sh"

echo ""
echo "============================================================"
echo "  FULL TEST SUITE COMPLETE"
echo "============================================================"
echo ""
echo "Results directory: ${SCRIPT_DIR}/results/"
echo "Visual report:     ${SCRIPT_DIR}/results/report-latest/report.html"
echo ""
echo "To reset to defaults:"
echo "  ${SCRIPT_DIR}/03-apply-scenario.sh baseline"
echo ""
echo "To cleanup everything:"
echo "  ${SCRIPT_DIR}/05-cleanup.sh --all"
