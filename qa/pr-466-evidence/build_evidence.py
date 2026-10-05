#!/usr/bin/env python3
"""Rebuild common evidence from original files or their archive, entirely offline."""
import argparse
import collections
import copy
import datetime
import hashlib
import html
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

HERE = Path(__file__).resolve().parent
QA = HERE.parent
ROOT = QA.parent
HEAD = "b116f756e5333645814aeabfc0569933111bc5be"
EXPECTED = {"PASS": 742, "FAIL": 10, "INTERRUPTED": 7, "CORRECTED": 1, "RESTORED": 1}
ENVIRONMENTS = [
    {
        "id": "gcp-ocp-5.0",
        "cluster": "ci-ln-605hqdt-72292",
        "openshift": "5.0.0-0.nightly-2026-09-29-171841",
        "directory": "pr-466-2026-10-05",
        "assertion_prefix": "QA-",
    },
    {
        "id": "aws-ocp-5.1",
        "cluster": "ci-op-32nzi86y-ea007-6xtww",
        "openshift": "5.1.0-0.ci-2026-10-05-053659-test-ci-op-32nzi86y-latest",
        "directory": "pr-466-repro-2026-10-05",
        "assertion_prefix": "R-",
    },
]
SOURCE_PATTERNS = {
    "private_key_pem": rb"-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----",
    "kubeconfig_key_data": rb"""client-key-data\s*["']?\s*:\s*["']?[A-Za-z0-9+/=]{32,}""",
    "bearer_value": rb"\bBearer\s+[A-Za-z0-9_.=-]{24,}",
    "jwt_value": rb"\beyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}",
}


def dump(name, value):
    (HERE / name).write_text(json.dumps(value, indent=2) + "\n")


def clean_cell(value):
    if not isinstance(value, str):
        value = json.dumps(value, ensure_ascii=False)
    return value.replace("|", "&#124;").replace("\r", "").replace("\n", "<br>")


def decode_cell(value):
    return html.unescape(value.replace("<br>", "\n"))


def qualified_rows(folder, prefix):
    """Use the reviewed CHECKS classifications, without rewriting source evidence."""
    rows = {}
    for line in (folder / "CHECKS.md").read_text().splitlines():
        if not re.match(r"^\| " + re.escape(prefix) + r"\d+ \|", line):
            continue
        cells = [decode_cell(x.strip()) for x in line.strip().strip("|").split("|")]
        if prefix == "QA-":
            key, time, result, test, expected, observed = cells
            phase = None
        else:
            key, time, phase, result, test, expected, observed, _ = cells
        rows[key] = dict(time=time, phase=phase, result=result, test=test,
                         expected=expected, observed=observed)
    return rows


def load_assertions():
    records = []
    for env in ENVIRONMENTS:
        folder = QA / env["directory"]
        classifications = qualified_rows(folder, env["assertion_prefix"])
        original = []
        for source in sorted((folder / "evidence").rglob("results.jsonl")):
            for line_number, line in enumerate(source.read_text().splitlines(), 1):
                if line.strip():
                    original.append((json.loads(line), source, line_number))
        original.sort(key=lambda x: x[0]["time"])
        assert len(original) == len(classifications)
        for index, (raw, source, line_number) in enumerate(original, 1):
            source_id = env["assertion_prefix"] + f"{index:03d}"
            qualified = classifications[source_id]
            assert raw["time"][11:19] == qualified["time"], source_id
            if qualified["phase"]:
                assert raw["phase"] == qualified["phase"], source_id
            assert raw["test"] == qualified["test"] or raw["test"] == "Bundle webhook and distribution", source_id
            record = copy.deepcopy(raw)
            record["test"] = qualified["test"]
            record["expected"] = qualified["expected"]
            record["result"] = qualified["result"]
            # Keep original observations in JSON, even when their interpretation changed.
            if record != raw:
                record["recorded"] = copy.deepcopy(raw)
            if record["result"] != raw["result"]:
                record["qualification"] = qualified["observed"]
            if raw["test"] == "Bundle webhook and distribution":
                record["qualification"] = qualified["expected"]
            record["provenance"] = {
                "environment": env["id"],
                "source_assertion_id": source_id,
                "archive_member": source.relative_to(QA).as_posix(),
                "source_line": line_number,
            }
            records.append(record)
    records.sort(key=lambda x: (x["time"], x["provenance"]["environment"]))
    for index, record in enumerate(records, 1):
        record["id"] = f"QA-{index:04d}"
    assert dict(collections.Counter(r["result"] for r in records)) == EXPECTED
    assert len(records) == 761
    return records


def make_findings(records):
    repeat_path = QA / ENVIRONMENTS[1]["directory"] / "evidence/reproduction-summary.json"
    confirmations = json.loads(repeat_path.read_text())["cases"]
    cases = []
    for index, confirmation in enumerate(confirmations, 1):
        phase, test = confirmation["phase"], confirmation["test"]
        failures = [r for r in records if r["phase"] == phase and r["test"] == test and r["result"] == "FAIL"]
        assert len(failures) == 2
        observations = []
        for failure in failures:
            env = failure["provenance"]["environment"]
            fresh_test = test.replace("operator-existing", "operator-fresh")
            def controls(name):
                return [
                    {"assertion_id": r["id"], "time": r["time"], "result": r["result"], "observed": r["observed"]}
                    for r in records
                    if r["provenance"]["environment"] == env and r["phase"] == phase
                    and r["test"] == name and r["result"] == "PASS"
                ]
            fresh = controls(fresh_test)
            positive = controls("operator-existing TLS1.3")
            assert fresh and positive, (phase, env)
            observations.append({
                "assertion_id": failure["id"],
                "time": failure["time"],
                "provenance": failure["provenance"],
                "existing_operator": failure["observed"],
                "fresh_operator_controls": fresh,
                "existing_operator_positive_controls": positive,
            })
        cases.append({
            "case_id": f"F1.{index}", "phase": phase, "test": test,
            "expected": "accept" if phase == "strict-old" else "reject",
            "observations": observations,
            "repeated_comparison": {
                "provenance": {
                    "environment": ENVIRONMENTS[1]["id"],
                    "archive_member": repeat_path.relative_to(QA).as_posix(),
                },
                "measurement": confirmation,
            },
        })
    dump("tls-failures.json", {"finding": "F1", "unique_failing_checks": 5, "failed_observations": 10, "cases": cases})

    configurations = []
    for scheme, name in [
        ("http", "documented HTTP ServiceMonitor fails on HTTPS metrics"),
        ("https", "CA-verified HTTPS ServiceMonitors scrape all operands"),
    ]:
        observations = []
        for env in ENVIRONMENTS:
            assertions = [r for r in records if r["provenance"]["environment"] == env["id"] and r["test"] == name]
            assert len(assertions) == 1
            assertion = assertions[0]
            path = QA / env["directory"] / f"evidence/monitoring/monitoring-{scheme}-targets.json"
            targets = json.loads(path.read_text())
            assert len(targets) == 3
            if scheme == "http":
                assert all(t["health"] == "down" and "400" in t["lastError"] for t in targets)
            else:
                assert all(t["health"] == "up" and not t["lastError"] for t in targets)
            observations.append({
                "assertion_id": assertion["id"], "time": assertion["time"],
                "provenance": {"environment": env["id"], "archive_member": path.relative_to(QA).as_posix()},
                "targets": targets,
            })
        configurations.append({"scheme": scheme, "observations": observations})
    dump("monitoring-targets.json", {"finding": "F2", "configurations": configurations})


def render_checks(records):
    lines = [
        "# Consolidated assertion evidence", "",
        "761 assertions: 742 PASS, 10 FAIL, 7 INTERRUPTED, 1 CORRECTED, 1 RESTORED.", "",
        "Repeated checks retain separate records. Timestamps and environment identities are original. "
        "JSON links identify the exact line in [results.jsonl](results.jsonl). "
        "Original classifications/observations and archive locations are retained there; "
        "[sources.json](sources.json) maps environments and source files.", "",
        "| ID | UTC timestamp | Phase | Result | Check | Expected | Observation |", "|---|---|---|---|---|---|---|",
    ]
    for index, record in enumerate(records, 1):
        obs = record["observed"]
        if record.get("qualification"):
            observation = "Qualification: " + record["qualification"]
        elif record["test"] == "deployment arguments and rollout" and record["result"] == "PASS":
            observation = "Desired TLS arguments and current rollout verified; full observation in JSON."
        elif isinstance(obs, dict) and "accepted" in obs:
            observation = {k: v for k, v in obs.items() if k in ["accepted", "protocol", "cipher", "error", "status", "prometheus"]}
        elif isinstance(obs, dict) and "existing" in obs:
            observation = {k: v for k, v in obs.items() if k in ["protocol", "reproduced", "same_pid"]}
        elif isinstance(obs, dict) and "conditions" in obs:
            observation = {k: v for k, v in obs.items() if k in ["conditions", "generation", "revision", "target_key", "source_sha256", "target_sha256"]}
        else:
            observation = obs
        if not isinstance(observation, str):
            observation = json.dumps(observation, ensure_ascii=False)
        if len(observation) > 650:
            observation = observation[:650] + "… [full observation in JSON]"
        cells = [
            f'[{record["id"]}](results.jsonl#L{index})',
            record["time"], record["phase"], record["result"], record["test"],
            record["expected"], observation,
        ]
        lines.append("| " + " | ".join(clean_cell(x) for x in cells) + " |")
    (HERE / "CHECKS.md").write_text("\n".join(lines) + "\n")


def make_manual():
    source = QA / ENVIRONMENTS[1]["directory"] / "REPORT.md"
    text = source.read_text()
    text = text[text.index("## Manual reproduction appendix"):].strip()
    text = text.replace("## Manual reproduction appendix", "# Manual reproduction appendix", 1)
    def replace_link(match):
        label, target = match.groups()
        if target.startswith(("http://", "https://", "#")):
            return match.group()
        if re.fullmatch(r"evidence/strict-(?:modern|custom12|custom13|old)-repeat-comparisons.json", target):
            return "[" + label + "](tls-failures.json)"
        if target.startswith("../../"):
            path = Path(target[6:]).as_posix()
            assert not Path(path).is_absolute() and ".." not in Path(path).parts
            return "[" + label + "](https://github.com/openshift/cert-manager-operator/blob/" + HEAD + "/" + path + ")"
        raise AssertionError("Unmapped manual link: " + target)
    text = re.sub(r"\[([^\]]*)\]\(([^)]+)\)", replace_link, text)
    (HERE / "manual-reproduction.md").write_text(text + "\n")


def archive_sources():
    files = []
    temporary = HERE / "raw-evidence.tmp.tar.gz"
    with tarfile.open(temporary, "w:gz", compresslevel=9) as archive:
        for env in ENVIRONMENTS:
            folder = QA / env["directory"]
            for path in sorted(folder.rglob("*")):
                assert not path.is_symlink(), str(path)
                if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc" or path.name == ".DS_Store":
                    continue
                assert "kubeconfig" not in path.name.lower(), str(path)
                data = path.read_bytes()
                for label, pattern in SOURCE_PATTERNS.items():
                    assert not re.search(pattern, data), (str(path), label)
                member = path.relative_to(QA).as_posix()
                digest = hashlib.sha256(data).hexdigest()
                info = tarfile.TarInfo(member)
                info.size = len(data)
                info.mode = 0o644
                info.mtime = int(path.stat().st_mtime)
                archive.addfile(info, io.BytesIO(data))
                files.append({"archive_member": member, "original_repo_path": (Path("qa") / path.relative_to(QA)).as_posix(),
                              "bytes": len(data), "sha256": digest})
    expected = {item["archive_member"]: item for item in files}
    with tarfile.open(temporary, "r:gz") as archive:
        seen = set()
        for member in archive:
            assert member.isfile() and member.name in expected
            data = archive.extractfile(member).read()
            assert hashlib.sha256(data).hexdigest() == expected[member.name]["sha256"]
            seen.add(member.name)
        assert seen == set(expected)
    temporary.replace(HERE / "raw-evidence.tar.gz")
    return files


def build():
    records = load_assertions()
    (HERE / "results.jsonl").write_text("".join(json.dumps(record, ensure_ascii=False) + "\n" for record in records))
    render_checks(records)
    make_findings(records)
    make_manual()
    # Identical, already tested monitor definitions; preserve their exact bytes.
    monitor_a = (QA / ENVIRONMENTS[0]["directory"] / "https-servicemonitors.json").read_bytes()
    monitor_b = (QA / ENVIRONMENTS[1]["directory"] / "https-servicemonitors.json").read_bytes()
    assert json.loads(monitor_a) == json.loads(monitor_b)
    (HERE / "https-servicemonitors.json").write_bytes(monitor_b)
    (HERE / "unit-tests.log").write_bytes((QA / ENVIRONMENTS[0]["directory"] / "evidence/unit-tests.log").read_bytes())
    dump("summary.json", {
        "commit": HEAD, "assertions": 761, "counts": EXPECTED, "unique_failing_tls_checks": 5,
        "findings": ["F1", "F2"],
        "first_assertion_utc": records[0]["time"], "last_assertion_utc": records[-1]["time"],
        "note": "Counts include repeated observations. F2 expected-failure reproduction assertions are PASS. No new tests were executed to build this evidence set.",
    })
    source_files = archive_sources()
    dump("sources.json", {
        "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "commit": HEAD, "environments": ENVIRONMENTS,
        "archive": "raw-evidence.tar.gz", "files": source_files,
        "note": "A point-in-time copy of the original reports, scripts and raw evidence. File bytes are unchanged; SHA-256 identifies each archived file. Credentials, operator binary and Python caches are excluded.",
    })
    readme = """# PR #466 — common evidence

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
"""
    (HERE / "README.md").write_text(readme)
    # Validate source-record reconstruction without relying on display truncation.
    for record in records:
        provenance = record["provenance"]
        source = QA / provenance["archive_member"]
        raw = json.loads(source.read_text().splitlines()[provenance["source_line"] - 1])
        recreated = record.get("recorded") or {key: record[key] for key in raw}
        assert recreated == raw, record["id"]
    for path in HERE.glob("*.json"):
        json.loads(path.read_text())
    manual = (HERE / "manual-reproduction.md").read_text()
    for block in re.findall(r"\x60\x60\x60bash\n(.*?)\n\x60\x60\x60", manual, re.S):
        checked = subprocess.run(["bash", "-n"], input=block, text=True, capture_output=True)
        assert checked.returncode == 0, checked.stderr
    for path in HERE.glob("*.md"):
        for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", path.read_text()):
            if target.startswith(("http://", "https://", "#")):
                continue
            target = target.split("#", 1)[0]
            if target == "SHA256SUMS":
                continue
            assert (path.parent / target).exists(), (path.name, target)
    checksums = []
    for path in sorted(HERE.iterdir()):
        if path.is_file() and path.name != "SHA256SUMS":
            checksums.append(hashlib.sha256(path.read_bytes()).hexdigest() + "  " + path.name)
    (HERE / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
    print(json.dumps({
        "directory": str(HERE.relative_to(ROOT)), "assertions": len(records), "counts": EXPECTED,
        "source_files_preserved": len(source_files), "raw_archive_bytes": (HERE / "raw-evidence.tar.gz").stat().st_size,
        "common_bytes": sum(p.stat().st_size for p in HERE.iterdir() if p.is_file()),
        "validation": "source reconstruction, classifications, archive hashes, links and manual shell syntax passed",
    }, indent=2))


def main():
    global QA
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--from-archive", action="store_true", help="verify and rebuild from the archived sources")
    args = parser.parse_args()
    present = [(QA / env["directory"]).is_dir() for env in ENVIRONMENTS]
    if not args.from_archive and all(present):
        build()
        return
    if not args.from_archive and any(present):
        parser.error("Only some original directories exist; use --from-archive to select the complete archived source set.")
    manifest = json.loads((HERE / "sources.json").read_text())
    expected = {entry["archive_member"]: entry["sha256"] for entry in manifest["files"]}
    original_qa = QA
    with tempfile.TemporaryDirectory(prefix="pr466-evidence-") as temporary:
        with tarfile.open(HERE / "raw-evidence.tar.gz", "r:gz") as archive:
            members = archive.getmembers()
            assert len(members) == len(expected)
            assert {member.name for member in members} == set(expected)
            for member in members:
                path = Path(member.name)
                assert member.isfile() and not path.is_absolute() and ".." not in path.parts
                assert path.parts[0] in {env["directory"] for env in ENVIRONMENTS}
                assert hashlib.sha256(archive.extractfile(member).read()).hexdigest() == expected[member.name]
            archive.extractall(temporary, filter="data")
        QA = Path(temporary)
        try:
            build()
        finally:
            QA = original_qa


if __name__ == "__main__":
    main()
