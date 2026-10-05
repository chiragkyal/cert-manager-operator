# PR #466 — common evidence

This is the common evidence set for the [consolidated report](../PR-466-CONSOLIDATED-REPORT.md). Assertions and findings are grouped together; original timestamps, environment identities and source classifications remain traceable.

| File | Contents |
|---|---|
| [CHECKS.md](CHECKS.md) | All 761 qualified assertions in one chronological table |
| [results.jsonl](results.jsonl) | Full observations, common IDs, source locations and qualifications |
| [summary.json](summary.json) | Consolidated totals and finding counts |
| [tls-failures.json](tls-failures.json) | Five TLS failures, all ten failed observations, fresh-listener controls and repeated comparisons |
| [monitoring-targets.json](monitoring-targets.json) | Actual HTTP and verified HTTPS Prometheus targets |
| [manual-reproduction.md](manual-reproduction.md) | Setup, commands, expected/actual behavior and restoration |
| [https-servicemonitors.json](https-servicemonitors.json) | Tested, CA-verified HTTPS monitor definitions |
| [unit-tests.log](unit-tests.log) | Original focused Go package results |
| [sources.json](sources.json) | Environment metadata, original file paths and archive hashes |
| [raw-evidence.tar.gz](raw-evidence.tar.gz) | Original logs, snapshots, reports and drivers, compressed |
| [SHA256SUMS](SHA256SUMS) | Checksums for these common files |

Totals: **742 PASS, 10 FAIL, 7 INTERRUPTED, 1 CORRECTED, 1 RESTORED**. Ten failed observations represent five distinct TLS checks. Successful reproduction of the HTTP monitoring incompatibility is recorded as PASS.

No new live tests were performed. This combines testing and cross-verification on two independent environments; it does not relabel them as one physical cluster. Interrupted/corrected results retain their original measurements in JSON. The duplicate dated directories have been removed from the workspace; their complete source files remain in the archive.

To inspect raw records, extract raw-evidence.tar.gz into an empty directory. Each results.jsonl record identifies its original archive member, line number and assertion ID. sources.json supplies the corresponding SHA-256. Original scripts require the PR checkout and a new kubeconfig/output directory before reuse.

Share the consolidated report together with this entire directory, preserving their relative paths. Kubeconfig contents, private keys, bearer credentials, the operator binary and Python caches are excluded.

[build_evidence.py](build_evidence.py) regenerates this directory offline. Run it from the repository root with `python3 qa/pr-466-evidence/build_evidence.py`. It reads the original directories if both exist, otherwise verifies and uses the archive in temporary storage. `--from-archive` explicitly selects the archive. Temporary source copies are removed automatically; no cluster connection is made.

Live operator output, when present, is kept separately in the ignored `qa/runtime/` directory. The archive retains the historical log snapshot used by this assessment.
