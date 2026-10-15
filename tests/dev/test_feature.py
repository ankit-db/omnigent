"""Tests for the feature-agent driver's pure helpers (``dev/feature.py``).

The worktree and subprocess plumbing (``main``) is exercised manually.
"""

from __future__ import annotations

import json

import pytest

from dev.feature import build_payload, ticket_key


@pytest.mark.parametrize(
    ("url", "key"),
    [
        ("https://linear.app/omnigent/issue/OMNI-1234", "omni-1234"),
        ("https://linear.app/omnigent/issue/OMNI-1234/add-session-rename", "omni-1234"),
        ("  https://linear.app/omnigent/issue/omni-7/  ", "omni-7"),
    ],
)
def test_ticket_key_from_linear_issue_url(url: str, key: str) -> None:
    assert ticket_key(url) == key


@pytest.mark.parametrize(
    "url",
    [
        "",
        "OMNI-1234",
        "https://github.com/omnigent-ai/omnigent/issues/1234",
        "https://linear.app/omnigent/project/OMNI-1234",
        "http://linear.app/omnigent/issue/OMNI-1234",
        "https://evil.example.com/linear.app/omnigent/issue/OMNI-1234",
        "https://linear.app/omnigent/issue/OMNI-1234/slug/extra",
    ],
)
def test_ticket_key_rejects_non_linear_issue_urls(url: str) -> None:
    with pytest.raises(ValueError, match="not a Linear issue URL"):
        ticket_key(url)


def test_payload_carries_the_ticket_and_only_enabled_flags() -> None:
    url = "https://linear.app/omnigent/issue/OMNI-1234/slug"
    assert json.loads(build_payload(f" {url} ")) == {"feature_url": url}
    assert json.loads(build_payload(url, skip_push=True, public=True)) == {
        "feature_url": url,
        "skip_push": True,
        "public": True,
    }
    with pytest.raises(ValueError):
        build_payload("https://github.com/omnigent-ai/omnigent/issues/1")
