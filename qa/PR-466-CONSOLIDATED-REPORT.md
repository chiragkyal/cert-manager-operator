# PR #466 — consolidated QA report

**Recommendation: request changes.** The core operand TLS implementation passed the completed checks. Two findings were confirmed: the running operator does not adopt TLS policy changes, and the documented HTTP ServiceMonitor cannot scrape the new HTTPS metrics endpoints.

**Tested:** 2026-10-05 · [PR #466](https://github.com/openshift/cert-manager-operator/pull/466) · commit `b116f756e5333645814aeabfc0569933111bc5be`. Local macOS/Go operator with upstream cert-manager `v1.20.3` and trust-manager `v0.20.3`; existing worktree changes were captured in the evidence.

## Results

| Passed | Failed observations | Interrupted | Corrected / restored | Total assertions |
|---:|---:|---:|---:|---:|
| **742** | **10** | **7** | **2** | **761** |

**Five distinct failing TLS checks map to one code finding (F1).** The ten failed observations include repeat verification of those checks. Totals include controls and retries; they are not counts of unique test cases. The two corrected/restored records concern a test expectation and a cleanup difference, not product defects. F2's reproduction records PASS because the expected HTTP scrape failure was demonstrated.

## Coverage

| Area | Result |
|---|---|
| Baseline, Strict default, Intermediate, Modern, Custom TLS 1.2/1.3, Old, and return to Legacy | Operand and fresh-operator behavior passed; existing operator failures listed below |
| Actual protocol/cipher negotiation across three metrics and two webhook listeners | PASS for operands, including TLS 1.3 cipher-argument removal |
| Metrics/webhook CA and DNS verification; operator serving certificate and HTTPS authorization | PASS |
| Certificate issuance/reissuance, Bundle distribution and trust-manager serving Certificate readiness | PASS; fresh-generation/exact CA distribution also verified separately |
| Six invalid API inputs, scoped metrics RBAC, Role/RoleBinding recreation and TLS feature claims | PASS |
| Unrelated APIServer updates, trust-manager argument repair, operand restarts, CA persistence and override precedence | PASS |
| Focused Go tests | Four packages passed; operator command package had no tests |
| Real Prometheus scraping | HTTP failed; verified HTTPS passed — F2 |

The table summarizes the complete QA scope. Failure-related profiles and monitoring behavior received additional verification with fresh-operator and operand controls.

## F1 — running operator retains its startup TLS policy

**Priority: high · code lifecycle gap.** After a cluster profile change, the existing operator metrics listener keeps its previous policy. A fresh process using the same binary and the five operand listeners follow the new policy correctly.

| Profile / probe | Expected | Existing operator — actual |
|---|---|---|
| Strict Modern / TLS 1.2 | Reject | **Accepted** |
| Strict Custom TLS 1.2 / excluded AES256-GCM cipher | Reject | **Accepted** |
| Strict Custom minimum TLS 1.3 / TLS 1.2 | Reject | **Accepted** |
| Strict Old / TLS 1.0 | Accept | **Rejected** |
| Strict Old / TLS 1.1 | Accept | **Rejected** |

All five failures were confirmed through repeated comparisons with a working TLS 1.3 control and stable process/certificate identity within each comparison.

**Recommended fix:** reconfigure the operator listener or trigger a managed restart when the honored APIServer TLS fields change. The startup-only lookup in [cmd.go](https://github.com/openshift/cert-manager-operator/blob/b116f756e5333645814aeabfc0569933111bc5be/pkg/cmd/operator/cmd.go) matches the observed behavior. If startup-only support is intentional, explicitly resolve and document the restart requirement.

[Five-case reproduction evidence](pr-466-evidence/tls-failures.json)

## F2 — documented HTTP ServiceMonitor fails

**Priority: medium · documentation/migration gap.** The PR enables HTTPS metrics even at the default TLS configuration, but the documented ServiceMonitor does not configure HTTPS or certificate trust.

| Configuration | Expected | Actual |
|---|---|---|
| Documented HTTP ServiceMonitor | Collect metrics | **3/3 DOWN**, HTTP 400 |
| HTTPS with metrics CA and correct Service DNS identities | Collect metrics with certificate verification | **3/3 UP**, no scrape errors |

**Recommended fix:** update [operand_metrics.md](https://github.com/openshift/cert-manager-operator/blob/b116f756e5333645814aeabfc0569933111bc5be/docs/operand_metrics.md) with verified HTTPS examples and migration guidance. The pod's HTTPS annotation does not update an existing ServiceMonitor.

[HTTP and verified HTTPS evidence](pr-466-evidence/monitoring-targets.json)

## Team cross-verification

Use the [step-by-step manual commands](pr-466-evidence/manual-reproduction.md) for setup, every failed profile, positive controls and restoration.

**F1, shortest reproduction:**

1. Start the PR operator at default/Legacy TLS settings; confirm TLS 1.2 works.
2. Set Strict Modern and wait for operand arguments and rollouts to converge.
3. Probe the original operator: it still accepts TLS 1.2, although Modern requires rejection.
4. Start a fresh follower under Modern: it rejects TLS 1.2. Confirm TLS 1.3 works on both, then restore the saved configuration.

**F2:** at baseline, apply the documented HTTP monitor and observe three DOWN/400 targets. Replace it with the [tested HTTPS monitor definitions](pr-466-evidence/https-servicemonitors.json); all three targets become UP.

Connection refusal, timeouts or a failed positive control are **inconclusive**, not TLS-policy rejections.

## Qualifications and final state

API disruption interrupted checks. Measurements affected by listener loss or missing positive controls were excluded from the confirmed failures, and the affected scenarios were retested successfully.

At the final checks, all four operands were ready, test resources were removed, and monitoring/TLS behavior was restored. APIServer adherence remained explicitly `LegacyAdheringComponentsOnly` because the API forbids removing it once set. The last platform snapshot still had ten progressing operators; broad platform recovery was not awaited.

**Not established:** packaged OLM install/upgrade, production/FIPS images, natural certificate rotation or long-term soak, disabled feature gates, live API-unavailable startup, or TLS groups/curves.

**Test provenance:** this assessment consolidates initial testing and cross-verification on two independent OpenShift environments: GCP / 5.0 nightly and AWS / 5.1 CI. Coverage above is the overall assessment; not every scenario was repeated in each environment.

The [common evidence index](pr-466-evidence/README.md) contains [all assertions](pr-466-evidence/CHECKS.md), full observations, manual commands and a compressed archive of the original logs and snapshots. Share this report with the `pr-466-evidence/` directory.
