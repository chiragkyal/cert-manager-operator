# cert-manager Performance Testing Toolkit

Performance test suite for validating cert-manager tuning parameters on OpenShift (RFE-5620).

## Prerequisites

- `oc` CLI logged into your OpenShift cluster with cluster-admin
- cert-manager-operator installed and CertManager CR `cluster` in `Managed` state
- `jq` and `bc` installed locally

## Quick Start

```bash
export KUBECONFIG=/path/to/kubeconfig

# 1. Setup test namespace and issuers
./01-setup.sh

# 2. Run baseline test (default parameters)
./02-run-test.sh baseline 100

# 3. Apply tuned parameters and test
./03-apply-scenario.sh moderate
./02-run-test.sh moderate 100

# 4. Compare results
./04-compare-results.sh
```

## Complete Test Matrix

### Scenario 1: Throughput Under Load

| Test | Script | What it measures |
|------|--------|------------------|
| 1.1 Default Config | `./02-run-test.sh baseline N` | Issuance rate with defaults |
| 1.2 Tuned Config | `./02-run-test.sh moderate N` | Issuance rate with tuned params |
| 1.3 DR Simulation | `./06-dr-simulation.sh <scenario> N` | Recovery time after secret deletion |
| 1.4 Renewal Storm | `./10-renewal-storm.sh <scenario> N` | Mass renewal handling |

### Scenario 2: Latency

| Test | Script | What it measures |
|------|--------|------------------|
| 2.1 Per-cert latency | `./02-run-test.sh` (auto) | P50/P90/P99 time from creation to Ready |
| 2.2 API/etcd latency | `./12-cluster-impact.sh 300 10` | API server P99, etcd P99 during test |

### Scenario 3: Resource Stability

| Test | Script | What it measures |
|------|--------|------------------|
| 3.1 Pod stability | `./08-collect-metrics.sh 300 10` | CPU/memory/restarts over time |
| 3.2 Post-burst health | `./02-run-test.sh` (auto) | Zero restarts, all certs Ready |

### Scenario 4: API Throttling

| Test | Script | What it measures |
|------|--------|------------------|
| 4. Throttle detection | `./12-cluster-impact.sh 600 10` | `apiserver_flowcontrol_rejected_requests_total` |

### Scenario 5: Multi-Namespace Fairness

| Test | Script | What it measures |
|------|--------|------------------|
| 5. Fairness | `./11-multi-namespace-fairness.sh <scenario> 10 30` | Per-namespace timing spread |

### Scenario 6: Cluster Impact

| Test | Script | What it measures |
|------|--------|------------------|
| 6. Other services | `./12-cluster-impact.sh 600 10` | ClusterOperator degradations, API latency for others |

### Scenario 7: Breaking Point / Saturation

| Test | Script | What it measures |
|------|--------|------------------|
| 7a. Workers | `./13-saturation-test.sh concurrent-workers 5 10 15 20 30 50` | Where workers stop helping |
| 7b. QPS | `./13-saturation-test.sh kube-api-qps 20 50 100 200 500` | Where QPS saturates API |
| 7c. Burst | `./13-saturation-test.sh kube-api-burst 50 100 200 500 1000` | Burst ceiling |

## Recommended Full Run (new cluster)

```bash
export KUBECONFIG=/path/to/kubeconfig

# Phase 1: Setup
./01-setup.sh
./09-check-cluster-health.sh

# Phase 2: Baseline (runs in ~5 min)
./03-apply-scenario.sh baseline
./02-run-test.sh baseline 100
./02-run-test.sh baseline 300

# Phase 3: Moderate (runs in ~8 min)
./03-apply-scenario.sh moderate
./02-run-test.sh moderate 100
./02-run-test.sh moderate 300

# Phase 4: Aggressive (runs in ~8 min)
./03-apply-scenario.sh aggressive
./02-run-test.sh aggressive 100
./02-run-test.sh aggressive 300

# Phase 5: DR Simulation (runs in ~5 min)
./06-dr-simulation.sh aggressive-dr 300

# Phase 6: Renewal Storm (runs in ~5 min per)
./03-apply-scenario.sh baseline
./10-renewal-storm.sh baseline-renewal 100
./03-apply-scenario.sh aggressive
./10-renewal-storm.sh aggressive-renewal 100

# Phase 7: Multi-namespace fairness (runs in ~10 min)
./03-apply-scenario.sh baseline
./11-multi-namespace-fairness.sh baseline-fairness 10 30
./03-apply-scenario.sh aggressive
./11-multi-namespace-fairness.sh aggressive-fairness 10 30

# Phase 8: Cluster impact (run in PARALLEL with a test)
# Terminal 1:
./12-cluster-impact.sh 600 10
# Terminal 2:
./02-run-test.sh aggressive 300

# Phase 9: Saturation / Breaking point (runs ~30 min)
./13-saturation-test.sh concurrent-workers 5 10 15 20 30 50
./13-saturation-test.sh kube-api-qps 20 50 100 200 500

# Phase 10: Compare all
./04-compare-results.sh

# Cleanup
./05-cleanup.sh --all
```

## Parameters Under Test

| Parameter | Default | Description |
|-----------|---------|-------------|
| `--concurrent-workers` | 5 | Goroutine workers per controller (~18 controllers) |
| `--kube-api-qps` | 20 | Max sustained API requests/sec (client-side) |
| `--kube-api-burst` | 50 | Token-bucket burst above QPS |
| `--max-concurrent-challenges` | 60 | Max ACME challenges in processing state |
| `--dns01-check-retry-period` | 10s | Wait between propagation checks |

## Test Scenarios (Predefined)

| Scenario | workers | qps | burst | challenges | Resources |
|----------|---------|-----|-------|------------|-----------|
| baseline | 5 | 20 | 50 | 60 | none |
| moderate | 10 | 50 | 100 | 120 | 500m-2/256Mi-1Gi |
| aggressive | 20 | 150 | 300 | 300 | 1-4/512Mi-2Gi |
| workers-only | 15 | 20 | 50 | 60 | none |
| qps-only | 5 | 100 | 200 | 60 | none |
| challenges-only | 5 | 20 | 50 | 200 | none |

## Directory Layout

```
hack/perf-test/
├── 01-setup.sh                   # Create namespaces, issuers
├── 02-run-test.sh                # Run a throughput test with N certificates
├── 03-apply-scenario.sh          # Apply parameter scenario to CertManager CR
├── 04-compare-results.sh         # Compare results across all runs
├── 05-cleanup.sh                 # Tear down test resources
├── 06-dr-simulation.sh           # Disaster recovery (delete secrets, measure re-issue)
├── 07-run-all.sh                 # Automated: baseline + moderate + aggressive
├── 08-collect-metrics.sh         # Live resource usage collector
├── 09-check-cluster-health.sh    # Pre-flight cluster health check
├── 10-renewal-storm.sh           # Short-lived certs, mass renewal
├── 11-multi-namespace-fairness.sh # Fairness across N namespaces
├── 12-cluster-impact.sh          # API throttle + operator degradation monitor
├── 13-saturation-test.sh         # Progressive increase to find breaking point
├── manifests/                    # Test issuer YAML
├── scenarios/                    # CertManager CR configurations
└── results/                      # Test output (gitignored)
```

## Definition of Done

1. Test reports showing impact of each parameter at multiple load levels
2. Per-parameter min/max guidelines with breaking points identified
3. Multi-namespace fairness confirmed
4. API server / etcd latency impact quantified
5. Zero controller instability across all tuned configurations
6. No degradation of other cluster services during tests
