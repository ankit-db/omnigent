#!/usr/bin/env python3
"""Evaluate a small Dependabot pilot using trusted policy and read-only PR data."""

from __future__ import annotations

import argparse
import base64
import io
import json
import os
import re
import subprocess
import zipfile
from datetime import UTC, datetime, timedelta
from pathlib import Path
from urllib.parse import urlencode
from urllib.request import urlopen

import tomllib
from maintainer_approval import gh_json, latest_decisive_reviews, paginated

POLICY = Path(__file__).resolve().parents[1] / "dependabot-automerge.json"
REPORT_CHECKS = ("Security Scan", "Trivy CVE Scan (repository)", "Trivy CVE Scan (dev-tools)")


class NeedsReview(ValueError):
    """The PR does not meet the unattended-merge policy."""


def require(condition: bool, reason: str) -> None:
    if not condition:
        raise NeedsReview(reason)


def patch_upgrade(old: str, new: str) -> bool:
    if not all(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", v) for v in (old, new)):
        return False
    before, after = (tuple(map(int, v.split("."))) for v in (old, new))
    return before[:2] == after[:2] and after[2] > before[2]


def lock_changes(before: dict, after: dict, policy: dict) -> list[dict]:
    require(
        {k: v for k, v in before.items() if k != "package"}
        == {k: v for k, v in after.items() if k != "package"},
        "Lockfile resolution settings changed",
    )
    indexes = []
    for lock in (before, after):
        by_name: dict[str, list[dict]] = {}
        for package in lock["package"]:
            by_name.setdefault(package["name"], []).append(package)
        indexes.append(by_name)
    old_packages, new_packages = indexes
    require(old_packages.keys() == new_packages.keys(), "Packages were added or removed")
    changes = []
    for name, old in old_packages.items():
        new = new_packages[name]
        if old == new:
            continue
        require(name in policy["python_patch_packages"], f"{name} requires human review")
        require(len(old) == len(new) == 1, f"{name} has multiple conditional versions")
        previous, current = old[0], new[0]
        require(
            patch_upgrade(previous["version"], current["version"]),
            f"{name} is not a patch upgrade",
        )
        require(
            current["source"] == {"registry": "https://pypi.org/simple"},
            f"{name} is not from PyPI",
        )
        mutable = {"version", "sdist", "wheels"}
        require(
            {k: v for k, v in previous.items() if k not in mutable}
            == {k: v for k, v in current.items() if k not in mutable},
            f"{name} changed its source, dependencies, or resolution markers",
        )
        changes.append(current)
    require(bool(changes), "No eligible package upgrades")
    return changes


def validate_release(package: dict, release: dict, cooldown_days: int, now: datetime) -> None:
    name, version = package["name"], package["version"]
    require(release["info"]["version"] == version, f"{name}: registry version mismatch")
    files = {entry["url"]: entry for entry in release["urls"]}
    artifacts = package.get("wheels", []) + ([package["sdist"]] if "sdist" in package else [])
    require(bool(artifacts), f"{name}: no locked artifacts")
    cutoff = now - timedelta(days=cooldown_days)
    for artifact in artifacts:
        published = files.get(artifact["url"])
        require(published is not None, f"{name}: artifact is absent from PyPI")
        require(not published["yanked"], f"{name}: artifact is yanked")
        require(
            artifact["hash"] == f"sha256:{published['digests']['sha256']}"
            and artifact["size"] == published["size"],
            f"{name}: artifact does not match PyPI",
        )
        uploaded = datetime.fromisoformat(published["upload_time_iso_8601"])
        require(uploaded <= cutoff, f"{name}: artifact has not completed the cooldown")


def read_lock(repository: str, sha: str) -> dict:
    tree = gh_json(["api", f"repos/{repository}/git/trees/{sha}"])
    require(not tree.get("truncated"), "Git tree is incomplete")
    entries = [entry for entry in tree["tree"] if entry["path"] == "uv.lock"]
    require(len(entries) == 1 and entries[0]["mode"] == "100644", "uv.lock must be a regular file")
    blob = gh_json(["api", f"repos/{repository}/git/blobs/{entries[0]['sha']}"])
    require(blob["encoding"] == "base64", "Unexpected lockfile encoding")
    return tomllib.loads(base64.b64decode(blob["content"]).decode())


def evaluate(repository: str, number: int, expected_head: str | None = None) -> dict:
    pull = gh_json(["api", f"repos/{repository}/pulls/{number}"])
    require(pull["state"] == "open" and not pull["draft"], "PR is closed or draft")
    require(
        pull["user"]["login"] == "dependabot[bot]" and pull["user"]["type"] == "Bot",
        "Not a Dependabot PR",
    )
    require(pull["head"]["repo"]["full_name"] == repository, "Fork PR requires review")
    require(pull["base"]["ref"] == "main", "Only main is covered by the pilot")
    head, base = pull["head"]["sha"], pull["base"]["sha"]
    require(expected_head is None or head == expected_head, "PR head changed during evaluation")
    labels = {label["name"] for label in pull["labels"]}
    require(
        not labels & {"hold-automerge", "skip-security-scan"},
        "A hold or scan-waiver label is present",
    )
    files = paginated(f"repos/{repository}/pulls/{number}/files")
    require(
        pull["changed_files"] == len(files) == 1
        and files[0]["filename"] == "uv.lock"
        and files[0]["status"] == "modified",
        "Pilot accepts only uv.lock changes; manifests and other files need review",
    )
    reviews = paginated(f"repos/{repository}/pulls/{number}/reviews")
    require(
        all(r["state"] != "CHANGES_REQUESTED" for r in latest_decisive_reviews(reviews).values()),
        "A reviewer has requested changes",
    )
    policy = json.loads(POLICY.read_text())
    changes = lock_changes(read_lock(repository, base), read_lock(repository, head), policy)
    now = datetime.now(UTC)
    for package in changes:
        url = f"https://pypi.org/pypi/{package['name']}/{package['version']}/json"
        with urlopen(url, timeout=30) as response:
            validate_release(package, json.load(response), policy["cooldown_days"], now)
    return {
        "head": head,
        "base": base,
        "packages": [f"{p['name']}=={p['version']}" for p in changes],
    }


def require_advisory_policy(report: dict, packages: list[str]) -> None:
    require(isinstance(report.get("Results"), list), "Incomplete Trivy report")
    inventory = set()
    for result in report["Results"]:
        if result.get("Target") != "uv.lock" or result.get("Type") != "uv":
            continue
        for package in result.get("Packages", []):
            inventory.add(f"{package['Name']}=={package['Version']}")
        for vulnerability in result.get("Vulnerabilities", []):
            pin = f"{vulnerability['PkgName']}=={vulnerability['InstalledVersion']}"
            if pin in packages:
                require(
                    vulnerability["Severity"] in {"LOW", "MEDIUM"},
                    f"{pin}: {vulnerability['VulnerabilityID']} requires human review",
                )
    require(set(packages) <= inventory, "Trivy did not inventory every changed package")


def require_reports(repository: str, head: str, packages: list[str]) -> None:
    for name in REPORT_CHECKS:
        # Filter server-side before pagination; large CI matrices fill the first page.
        query = urlencode({"check_name": name, "per_page": 100})
        response = gh_json(["api", f"repos/{repository}/commits/{head}/check-runs?{query}"])
        require(response["total_count"] <= 100, f"Too many {name} checks to evaluate")
        runs = [run for run in response["check_runs"] if run["app"]["slug"] == "github-actions"]
        require(bool(runs), f"Waiting for {name}")
        latest = max(runs, key=lambda run: run["id"])
        require(
            latest["status"] == "completed" and latest["conclusion"] == "success",
            f"Waiting for successful {name}",
        )
    # Require actual CI completion, even if Merge Ready treats an absent
    # path-filtered check as skippable while its workflow is being created.
    latest = None
    for workflow in ("ci.yml", "lint.yml", "trivy.yml"):
        query = urlencode({"head_sha": head, "event": "pull_request", "per_page": 100})
        response = gh_json(
            ["api", f"repos/{repository}/actions/workflows/{workflow}/runs?{query}"]
        )
        runs = response["workflow_runs"]
        require(bool(runs), f"No {workflow} run for this head")
        latest = max(runs, key=lambda run: run["id"])
        require(
            latest["head_sha"] == head
            and latest["status"] == "completed"
            and latest["conclusion"] == "success",
            f"Latest {workflow} run did not succeed",
        )
    artifacts = gh_json(
        ["api", f"repos/{repository}/actions/runs/{latest['id']}/artifacts?per_page=100"]
    )
    require(artifacts["total_count"] <= 100, "Trivy artifact listing is incomplete")
    reports = [
        a
        for a in artifacts["artifacts"]
        if a["name"] == "trivy-cve-report-repository" and not a["expired"]
    ]
    require(len(reports) == 1, "Missing or ambiguous Trivy repository report")
    data = subprocess.run(
        ["gh", "api", f"repos/{repository}/actions/artifacts/{reports[0]['id']}/zip"],
        check=True,
        capture_output=True,
    ).stdout
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        require_advisory_policy(json.loads(archive.read("trivy-results.json")), packages)


def sweep(repository: str, mode: str) -> None:
    if mode == "merge":
        require(
            bool(os.environ.get("DEPENDABOT_MERGE_TOKEN")),
            "Merge mode requires a GitHub App token",
        )
    pulls = gh_json(
        [
            "pr",
            "list",
            "--repo",
            repository,
            "--author",
            "app/dependabot",
            "--state",
            "open",
            "--limit",
            "100",
            "--json",
            "number",
        ]
    )
    require(len(pulls) < 100, "Dependabot PR listing reached its limit; refusing a partial sweep")
    rows = ["## Dependabot auto-merge pilot", "", f"Mode: `{mode}`", ""]
    for pull in pulls:
        number = pull["number"]
        try:
            decision = evaluate(repository, number)
            packages = ", ".join(decision["packages"])
            rows.append(f"- #{number}: eligible ({packages})")
            require_reports(repository, decision["head"], decision["packages"])
            if mode == "merge":
                current = gh_json(["api", f"repos/{repository}/pulls/{number}"])
                require(
                    current["head"]["sha"] == decision["head"]
                    and current["base"]["sha"] == decision["base"],
                    "PR changed during evaluation",
                )
                require(
                    not current["draft"] and current["state"] == "open",
                    "PR is now closed or draft",
                )
                require(
                    not {label["name"] for label in current["labels"]}
                    & {"hold-automerge", "skip-security-scan"},
                    "PR was put on hold",
                )
                reviews = paginated(f"repos/{repository}/pulls/{number}/reviews")
                require(
                    all(
                        r["state"] != "CHANGES_REQUESTED"
                        for r in latest_decisive_reviews(reviews).values()
                    ),
                    "A reviewer has requested changes",
                )
                # No --admin or queued --auto: GitHub enforces required checks
                # now, against precisely the head whose policy/report we read.
                subprocess.run(
                    [
                        "gh",
                        "pr",
                        "merge",
                        str(number),
                        "--repo",
                        repository,
                        "--squash",
                        "--match-head-commit",
                        decision["head"],
                    ],
                    check=True,
                    env=dict(os.environ, GH_TOKEN=os.environ["DEPENDABOT_MERGE_TOKEN"]),
                )
                rows.append("  - Merged after policy and required checks passed.")
        except (NeedsReview, KeyError, ValueError, OSError, subprocess.CalledProcessError) as exc:
            rows.append(f"- #{number}: human review or retry required: {exc}")
    summary = "\n".join(rows) + "\n"
    print(summary)
    if path := os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(path, "a") as output:
            output.write(summary)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True)
    parser.add_argument("--pr-number", type=int)
    parser.add_argument("--expected-head")
    args = parser.parse_args()
    mode = os.environ.get("DEPENDABOT_AUTOMERGE_MODE", "report") or "report"
    require(mode in {"report", "merge"}, "Unknown Dependabot auto-merge mode")
    if args.pr_number is None:
        sweep(args.repository, mode)
        return 0
    try:
        decision = evaluate(args.repository, args.pr_number, args.expected_head)
        print(json.dumps(decision))
        eligible = "true"
    except (NeedsReview, KeyError, ValueError, OSError, subprocess.CalledProcessError) as exc:
        print(f"Human review required: {exc}")
        eligible = "false"
    if path := os.environ.get("GITHUB_OUTPUT"):
        with open(path, "a") as output:
            output.write(f"eligible={eligible}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
