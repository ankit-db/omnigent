"""Exercise the trusted CLI against simulated GitHub/PyPI service boundaries."""

from __future__ import annotations

import base64
import copy
import importlib.util
import io
import json
import os
import subprocess
import sys
import zipfile
from datetime import UTC, datetime
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = ROOT / ".github/scripts"
HEAD, BASE = "a" * 40, "b" * 40
REPO = "example/project"
PREFIX = f"repos/{REPO}"
POLICY = {"python_patch_packages": ["ruff"], "cooldown_days": 7}
LOCK = """version = 1
[[package]]
name = "ruff"
version = "0.15.1"
source = { registry = "https://pypi.org/simple" }
wheels = [{ url = "https://files.pythonhosted.org/ruff.whl", hash = "sha256:abc", size = 42 }]
[[package]]
name = "werkzeug"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }
"""


@pytest.fixture
def policy_module(monkeypatch):
    monkeypatch.syspath_prepend(str(SCRIPTS))
    spec = importlib.util.spec_from_file_location(
        "dependabot_automerge", SCRIPTS / "dependabot_automerge.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def api():
    pull = {
        "number": 123,
        "state": "open",
        "draft": False,
        "changed_files": 1,
        "user": {"login": "dependabot[bot]", "type": "Bot"},
        "head": {"sha": HEAD, "repo": {"full_name": REPO}},
        "base": {"sha": BASE, "ref": "main"},
        "labels": [],
    }
    routes = {
        f"{PREFIX}/pulls/123": pull,
        f"{PREFIX}/pulls/123/files?per_page=100&page=1": [
            {"filename": "uv.lock", "status": "modified"}
        ],
        f"{PREFIX}/pulls/123/reviews?per_page=100&page=1": [],
        f"{PREFIX}/pulls/123/commits?per_page=100&page=1": [],
        f"{PREFIX}/issues/123/timeline?per_page=100&page=1": [],
        f"{PREFIX}/contents/.github/MAINTAINER?ref=main": {
            "content": base64.b64encode(b"maintainer").decode()
        },
    }
    for sha, text in ((BASE, LOCK), (HEAD, LOCK.replace("0.15.1", "0.15.2"))):
        routes[f"{PREFIX}/git/trees/{sha}"] = {
            "tree": [{"path": "uv.lock", "mode": "100644", "sha": sha}],
            "truncated": False,
        }
        routes[f"{PREFIX}/git/blobs/{sha}"] = {
            "encoding": "base64",
            "content": base64.b64encode(text.encode()).decode(),
        }
    for name in ("Security Scan", "Trivy CVE Scan (repository)", "Trivy CVE Scan (dev-tools)"):
        routes[name] = {
            "total_count": 1,
            "check_runs": [
                {
                    "id": 1,
                    "app": {"slug": "github-actions"},
                    "status": "completed",
                    "conclusion": "success",
                }
            ],
        }
    for run_id, workflow in enumerate(("trivy.yml", "ci.yml", "lint.yml"), start=11):
        routes[
            f"{PREFIX}/actions/workflows/{workflow}/runs?head_sha={HEAD}&event=pull_request&per_page=100"
        ] = {
            "workflow_runs": [
                {"id": run_id, "head_sha": HEAD, "status": "completed", "conclusion": "success"}
            ]
        }
    routes[f"{PREFIX}/actions/runs/11/artifacts?per_page=100"] = {
        "total_count": 1,
        "artifacts": [{"name": "trivy-cve-report-repository", "id": 12, "expired": False}],
    }
    return {
        "routes": routes,
        "pypi": {
            "info": {"version": "0.15.2"},
            "urls": [
                {
                    "url": "https://files.pythonhosted.org/ruff.whl",
                    "digests": {"sha256": "abc"},
                    "size": 42,
                    "yanked": False,
                    "upload_time_iso_8601": "2020-01-01T00:00:00Z",
                }
            ],
        },
        "report": {
            "Results": [
                {
                    "Target": "uv.lock",
                    "Type": "uv",
                    "Packages": [{"Name": "ruff", "Version": "0.15.2"}],
                    "Vulnerabilities": [
                        {
                            "PkgName": "werkzeug",
                            "InstalledVersion": "1.0.0",
                            "Severity": "CRITICAL",
                            "VulnerabilityID": "CVE-existing",
                        }
                    ],
                }
            ]
        },
    }


def run_cli(
    tmp_path,
    api,
    *,
    mode="report",
    sweep=False,
    approval=False,
    scan=False,
    merge_token="test-merge-token",
):
    (tmp_path / "api.json").write_text(json.dumps(api))
    gh = tmp_path / "gh"
    gh.write_text(
        f"#!{sys.executable}\n"
        + """
import base64, io, json, os, sys, zipfile
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
root = Path(os.environ['PILOT_FIXTURES'])
data = json.loads((root / 'api.json').read_text())
args = sys.argv[1:]
with (root / 'calls.jsonl').open('a') as log:
    log.write(json.dumps(args) + '\\n')
if args[:2] == ['pr', 'list']:
    print(json.dumps(data.get('pulls', [{'number': 123}])))
elif args[:2] == ['pr', 'merge']:
    assert os.environ['GH_TOKEN'] == 'test-merge-token'
    assert args == ['pr', 'merge', '123', '--repo', 'example/project',
                    '--squash', '--match-head-commit', 'a' * 40]
    sys.exit(data.get('merge_exit', 0))
elif args[0] == 'api':
    assert os.environ['GH_TOKEN'] == 'test-only'
    endpoint = args[1]
    if endpoint.endswith('/artifacts/12/zip'):
        count = sum(json.loads(line) == args
                    for line in (root / 'calls.jsonl').read_text().splitlines())
        if count == 1 and 'first_artifact' in data:
            sys.stdout.buffer.write(base64.b64decode(data['first_artifact']))
            sys.exit(0)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as archive:
            archive.writestr('trivy-results.json', json.dumps(data['report']))
        sys.stdout.buffer.write(buf.getvalue())
    else:
        if '/check-runs?' in endpoint:
            endpoint = parse_qs(urlsplit(endpoint).query)['check_name'][0]
        value = data['routes'][endpoint]
        if endpoint.endswith('/pulls/123') and 'pull_after' in data:
            count = sum(json.loads(line) == args
                        for line in (root / 'calls.jsonl').read_text().splitlines())
            if count > 1:
                value = data['pull_after']
        print(json.dumps(value))
else:
    raise AssertionError(args)
"""
    )
    gh.chmod(0o755)
    (tmp_path / "sitecustomize.py").write_text("""
import io, json, os, urllib.request
from pathlib import Path
def fixture_urlopen(url, timeout):
    assert url == 'https://pypi.org/pypi/ruff/0.15.2/json'
    root = Path(os.environ['PILOT_FIXTURES'])
    (root / 'pypi-called').touch()
    data = json.loads((root / 'api.json').read_text())
    if data.get('pypi_timeout'):
        raise TimeoutError('simulated PyPI timeout')
    return io.BytesIO(json.dumps(data['pypi']).encode())
urllib.request.urlopen = fixture_urlopen
""")
    args = [
        sys.executable,
        str(SCRIPTS / ("maintainer_approval.py" if approval else "dependabot_automerge.py")),
        "--repository",
        REPO,
    ]
    if not sweep:
        args += ["--pr-number", "123"]
    if not sweep and not approval:
        args += ["--expected-head", HEAD]
    if scan:
        workflow = yaml.safe_load((ROOT / ".github/workflows/security-scan.yml").read_text())
        step = next(s for s in workflow["jobs"]["scan"]["steps"] if s.get("id") == "dependabot")
        (tmp_path / "python3").symlink_to(sys.executable)
        args = ["bash", "-e", "-c", step["run"]]
    env = dict(
        os.environ,
        PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
        PYTHONPATH=str(tmp_path),
        PILOT_FIXTURES=str(tmp_path),
        GH_TOKEN="test-only",
        DEPENDABOT_MERGE_TOKEN=merge_token,
        DEPENDABOT_AUTOMERGE_MODE=mode,
        GITHUB_OUTPUT=str(tmp_path / "outputs"),
        GITHUB_STEP_SUMMARY=str(tmp_path / "summary"),
        REPO=REPO,
        PR="123",
        HEAD_SHA=HEAD,
    )
    process = subprocess.run(args, cwd=ROOT, env=env, text=True, capture_output=True, timeout=30)
    calls_file = tmp_path / "calls.jsonl"
    calls = (
        [json.loads(line) for line in calls_file.read_text().splitlines()]
        if calls_file.exists()
        else []
    )
    return process, calls


def test_report_mode_is_read_only_and_existing_advisories_do_not_disqualify(tmp_path, api):
    process, calls = run_cli(tmp_path, api, sweep=True)
    assert process.returncode == 0, process.stderr
    assert "eligible (ruff==0.15.2)" in process.stdout
    assert all(call[:2] != ["pr", "merge"] for call in calls)
    assert "Mode: `report`" in (tmp_path / "summary").read_text()


def test_merge_uses_exact_head_after_completed_reports(tmp_path, api):
    process, calls = run_cli(tmp_path, api, mode="merge", sweep=True)
    assert process.returncode == 0, process.stderr
    assert calls[-1] == [
        "pr",
        "merge",
        "123",
        "--repo",
        REPO,
        "--squash",
        "--match-head-commit",
        HEAD,
    ]
    assert "Merged after policy" in process.stdout


@pytest.mark.parametrize("candidate", ["eligible", "held", "not_evaluated"])
def test_security_workflow_step_emits_the_policy_decision(tmp_path, api, candidate):
    eligible = ""
    if candidate != "not_evaluated":
        if candidate == "held":
            api["routes"][f"{PREFIX}/pulls/123"]["labels"] = [{"name": "hold-automerge"}]
        process, calls = run_cli(tmp_path, api, mode="merge", scan=True)
        assert process.returncode == 0, process.stdout + process.stderr
        eligible = "true" if candidate == "eligible" else "false"
        assert (tmp_path / "outputs").read_text() == f"eligible={eligible}\n"
        assert not any(call[:2] == ["pr", "merge"] for call in calls)

    workflow = yaml.safe_load((ROOT / ".github/workflows/security-scan.yml").read_text())
    audit = next(
        s for s in workflow["jobs"]["scan"]["steps"] if s["name"] == "OSV advisory scan (uv.lock)"
    )
    assert audit["if"] == "${{ steps.gate.outputs.scan == 'true' }}"
    assert audit["env"]["DEPENDABOT_ELIGIBLE"] == "${{ steps.dependabot.outputs.eligible }}"
    (tmp_path / "changed.txt").write_text("uv.lock\n")
    for name, command in (
        ("uv", "printf 'ruff==0.15.2\\n'"),
        ("uvx", 'echo "$*" >> "$GITHUB_WORKSPACE/audit-calls"'),
    ):
        stub = tmp_path / name
        stub.write_text(f"#!/bin/sh\n{command}\n")
        stub.chmod(0o755)
    # Keep the production shell's temporary requirements files inside this scenario.
    script = audit["run"].replace("/tmp/uv-req", str(tmp_path / "uv-req"))
    process = subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=tmp_path,
        env=dict(
            os.environ,
            PATH=f"{tmp_path}{os.pathsep}{os.environ['PATH']}",
            GITHUB_WORKSPACE=str(tmp_path),
            DEPENDABOT_ELIGIBLE=eligible,
        ),
        text=True,
        capture_output=True,
        timeout=10,
    )
    assert process.returncode == 0, process.stdout + process.stderr
    audit_calls = tmp_path / "audit-calls"
    if candidate == "eligible":
        assert not audit_calls.exists()
        assert "Trivy policy is enforced by the merge worker" in process.stdout
    else:
        assert audit_calls.read_text().splitlines() == [
            f"pip-audit --requirement {tmp_path}/uv-req.txt --no-deps",
            f"pip-audit --requirement {tmp_path}/uv-req-ag.txt --no-deps",
        ]


def test_merge_mode_never_falls_back_to_workflow_token(tmp_path, api):
    process, calls = run_cli(tmp_path, api, mode="merge", sweep=True, merge_token="")
    assert process.returncode != 0
    assert "requires a GitHub App token" in process.stderr
    assert calls == []


@pytest.mark.parametrize("change", ["head", "hold"])
def test_candidate_changed_during_scanning_is_not_merged(tmp_path, api, change):
    api["pull_after"] = copy.deepcopy(api["routes"][f"{PREFIX}/pulls/123"])
    if change == "head":
        api["pull_after"]["head"]["sha"] = "c" * 40
    else:
        api["pull_after"]["labels"] = [{"name": "hold-automerge"}]
    process, calls = run_cli(tmp_path, api, mode="merge", sweep=True)
    assert process.returncode == 0, process.stderr
    assert "human review or retry required" in process.stdout
    assert not any(call[:2] == ["pr", "merge"] for call in calls)


@pytest.mark.parametrize(
    "mode,fault,expected",
    [
        ("report", None, 1),
        ("merge", None, 0),
        ("merge", "hold", 1),
        ("merge", "ghost", 1),
        ("merge", "timestamp", 1),
        ("merge", "timeout", 1),
    ],
)
def test_real_approval_entry_point_preserves_review_unless_pilot_enabled(
    tmp_path, api, mode, fault, expected
):
    if fault == "hold":
        api["routes"][f"{PREFIX}/pulls/123"]["labels"] = [{"name": "hold-automerge"}]
    elif fault == "ghost":
        api["routes"][f"{PREFIX}/pulls/123"]["user"] = None
    elif fault == "timestamp":
        api["pypi"]["urls"][0]["upload_time_iso_8601"] = "2020-01-01T00:00:00"
    elif fault == "timeout":
        api["pypi_timeout"] = True
    process, calls = run_cli(tmp_path, api, mode=mode, approval=True)
    assert process.returncode == expected, process.stdout + process.stderr
    if expected:
        assert "awaiting approval from a maintainer" in process.stdout
    assert not any(call[:2] == ["pr", "merge"] for call in calls)


def test_human_approval_does_not_depend_on_pypi(tmp_path, api):
    api["routes"][f"{PREFIX}/pulls/123/reviews?per_page=100&page=1"] = [
        {"user": {"login": "maintainer"}, "state": "APPROVED", "commit_id": HEAD}
    ]
    api["pypi_timeout"] = True
    process, _calls = run_cli(tmp_path, api, mode="merge", approval=True)
    assert process.returncode == 0, process.stdout + process.stderr
    assert "Current head approved" in process.stdout
    assert not (tmp_path / "pypi-called").exists()


@pytest.mark.parametrize(
    "fault",
    [
        "author",
        "fork",
        "draft",
        "base",
        "hold",
        "waiver",
        "manifest",
        "symlink",
        "head",
        "review",
        "hash",
        "size",
        "null_files",
        "yanked",
        "young",
    ],
)
def test_ineligible_changes_keep_human_review(tmp_path, api, fault):
    pull = api["routes"][f"{PREFIX}/pulls/123"]
    if fault == "author":
        pull["user"]["login"] = "contributor"
    elif fault == "fork":
        pull["head"]["repo"]["full_name"] = "contributor/project"
    elif fault == "draft":
        pull["draft"] = True
    elif fault == "base":
        pull["base"]["ref"] = "release/v1"
    elif fault in {"hold", "waiver"}:
        pull["labels"] = [{"name": "hold-automerge" if fault == "hold" else "skip-security-scan"}]
    elif fault == "manifest":
        api["routes"][f"{PREFIX}/pulls/123/files?per_page=100&page=1"][0]["filename"] = (
            "pyproject.toml"
        )
    elif fault == "symlink":
        api["routes"][f"{PREFIX}/git/trees/{HEAD}"]["tree"][0]["mode"] = "120000"
    elif fault == "head":
        pull["head"]["sha"] = "c" * 40
    elif fault == "review":
        api["routes"][f"{PREFIX}/pulls/123/reviews?per_page=100&page=1"] = [
            {"user": {"login": "maintainer"}, "state": "CHANGES_REQUESTED"}
        ]
    elif fault == "hash":
        api["pypi"]["urls"][0]["digests"]["sha256"] = "different"
    elif fault == "size":
        api["pypi"]["urls"][0]["size"] += 1
    elif fault == "null_files":
        api["routes"][f"{PREFIX}/pulls/123/files?per_page=100&page=1"] = None
    elif fault == "yanked":
        api["pypi"]["urls"][0]["yanked"] = True
    elif fault == "young":
        api["pypi"]["urls"][0]["upload_time_iso_8601"] = "2100-01-01T00:00:00Z"
    process, _calls = run_cli(tmp_path, api, mode="merge")
    assert process.returncode == 0, process.stderr
    assert (tmp_path / "outputs").read_text() == "eligible=false\n"
    assert "Human review required" in process.stdout


@pytest.mark.parametrize(
    "fault",
    [
        "failed_scan",
        "pending_scan",
        "missing_scan",
        "newer_scan",
        "missing_inventory",
        "wrong_inventory",
        "severe",
        "pending_ci",
        "merge_blocked",
    ],
)
def test_no_merge_without_reports_and_required_checks(tmp_path, api, fault):
    scan = api["routes"]["Trivy CVE Scan (repository)"]
    if fault == "failed_scan":
        scan["check_runs"][0]["conclusion"] = "failure"
    elif fault == "pending_scan":
        scan["check_runs"][0]["status"] = "in_progress"
    elif fault == "missing_scan":
        scan["check_runs"] = []
    elif fault == "newer_scan":
        scan["check_runs"].append(
            dict(scan["check_runs"][0], id=2, status="queued", conclusion=None)
        )
    elif fault == "missing_inventory":
        api["report"]["Results"][0]["Packages"] = []
    elif fault == "wrong_inventory":
        api["report"]["Results"][0]["Target"] = "another/uv.lock"
    elif fault == "severe":
        api["report"]["Results"][0]["Vulnerabilities"].append(
            {
                "PkgName": "ruff",
                "InstalledVersion": "0.15.2",
                "Severity": "HIGH",
                "VulnerabilityID": "CVE-new",
            }
        )
    elif fault == "merge_blocked":
        api["merge_exit"] = 1
    elif fault == "pending_ci":
        api["routes"][
            f"{PREFIX}/actions/workflows/ci.yml/runs?head_sha={HEAD}&event=pull_request&per_page=100"
        ]["workflow_runs"][0]["status"] = "in_progress"
    process, calls = run_cli(tmp_path, api, mode="merge", sweep=True)
    assert process.returncode == 0, process.stderr
    assert "Merged after policy" not in process.stdout
    assert "human review or retry required" in process.stdout
    if fault != "merge_blocked":
        assert not any(call[:2] == ["pr", "merge"] for call in calls)


def test_changed_package_with_medium_advisory_can_merge(tmp_path, api):
    api["report"]["Results"][0]["Vulnerabilities"].append(
        {
            "PkgName": "ruff",
            "InstalledVersion": "0.15.2",
            "Severity": "MEDIUM",
            "VulnerabilityID": "CVE-remaining",
        }
    )
    process, calls = run_cli(tmp_path, api, mode="merge", sweep=True)
    assert process.returncode == 0, process.stderr
    assert calls[-1][:2] == ["pr", "merge"]


@pytest.mark.parametrize("fault", ["zip", "deflate", "null_files"])
def test_bad_candidate_does_not_stop_later_merges(tmp_path, api, fault):
    api["pulls"] = [{"number": 122}, {"number": 123}]
    for endpoint, value in list(api["routes"].items()):
        if "/pulls/123" in endpoint:
            api["routes"][endpoint.replace("/pulls/123", "/pulls/122")] = copy.deepcopy(value)
    if fault == "null_files":
        api["routes"][f"{PREFIX}/pulls/122/files?per_page=100&page=1"] = None
    else:
        data = b"not a zip file"
        if fault == "deflate":
            buffer = io.BytesIO()
            filename = "trivy-results.json"
            with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_DEFLATED) as archive:
                archive.writestr(filename, json.dumps(api["report"]))
            damaged = bytearray(buffer.getvalue())
            damaged[30 + len(filename)] = 7  # Invalid DEFLATE block type.
            data = bytes(damaged)
        api["first_artifact"] = base64.b64encode(data).decode()
    process, calls = run_cli(tmp_path, api, mode="merge", sweep=True)
    assert process.returncode == 0, process.stdout + process.stderr
    summary = (tmp_path / "summary").read_text()
    assert "#122: human review or retry required" in summary
    assert "#123: eligible" in summary
    assert "Merged after policy" in summary
    assert [call[2] for call in calls if call[:2] == ["pr", "merge"]] == ["123"]


@pytest.mark.parametrize(
    "change",
    [
        "minor",
        "prerelease",
        "downgrade",
        "runtime",
        "source",
        "dependencies",
        "new_package",
        "settings",
        "conditional",
    ],
)
def test_lock_policy_rejects_changes_outside_patch_scope(policy_module, change):
    before = policy_module.tomllib.loads(LOCK)
    after = copy.deepcopy(before)
    after["package"][0]["version"] = "0.15.2"
    if change == "minor":
        after["package"][0]["version"] = "0.16.0"
    elif change == "prerelease":
        after["package"][0]["version"] = "0.15.2rc1"
    elif change == "downgrade":
        after["package"][0]["version"] = "0.15.0"
    elif change == "runtime":
        after["package"][1]["version"] = "1.0.1"
    elif change == "source":
        after["package"][0]["source"] = {"registry": "https://other.example/simple"}
    elif change == "dependencies":
        after["package"][0]["dependencies"] = [{"name": "werkzeug"}]
    elif change == "new_package":
        after["package"].append({"name": "new", "version": "1"})
    elif change == "settings":
        after["revision"] = 2
    elif change == "conditional":
        after["package"].append(dict(after["package"][0], version="0.15.3"))
    with pytest.raises(policy_module.NeedsReview):
        policy_module.lock_changes(before, after, POLICY)


def test_age_uses_registry_timestamp_and_accepts_exact_boundary(policy_module, api):
    package = policy_module.tomllib.loads(LOCK.replace("0.15.1", "0.15.2"))["package"][0]
    package["wheels"][0]["upload-time"] = "1900-01-01T00:00:00Z"
    with pytest.raises(policy_module.NeedsReview, match="cooldown"):
        policy_module.validate_release(package, api["pypi"], 7, datetime(2020, 1, 7, tzinfo=UTC))
    policy_module.validate_release(package, api["pypi"], 7, datetime(2020, 1, 8, tzinfo=UTC))
