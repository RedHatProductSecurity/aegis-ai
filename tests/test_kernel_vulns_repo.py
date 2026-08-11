from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from aegis_ai.kernel_vulns_repo import describe_git_error, sync_vulns_repo


def test_sync_vulns_repo_clones_when_missing(tmp_path: Path, monkeypatch) -> None:
    repo_path = tmp_path / "vulns"
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        return MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = sync_vulns_repo(repo_path, "https://example.com/vulns")

    assert result is True
    assert calls == [["git", "clone", "https://example.com/vulns", str(repo_path)]]


def test_sync_vulns_repo_pulls_when_present(tmp_path: Path, monkeypatch) -> None:
    repo_path = tmp_path / "vulns"
    repo_path.mkdir()
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append((cmd, kwargs.get("cwd")))
        return MagicMock(returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = sync_vulns_repo(repo_path, "https://example.com/vulns")

    assert result is True
    assert calls == [(["git", "pull"], repo_path)]


def test_sync_vulns_repo_clone_failure_propagates(tmp_path: Path, monkeypatch) -> None:
    repo_path = tmp_path / "vulns"

    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, stderr="clone exploded")

    monkeypatch.setattr(subprocess, "run", fake_run)

    with pytest.raises(subprocess.CalledProcessError):
        sync_vulns_repo(repo_path, "https://example.com/vulns")


def test_sync_vulns_repo_pull_failure_is_swallowed(tmp_path: Path, monkeypatch) -> None:
    repo_path = tmp_path / "vulns"
    repo_path.mkdir()

    def fake_run(cmd, **kwargs):
        raise subprocess.CalledProcessError(1, cmd, stderr="pull exploded")

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = sync_vulns_repo(repo_path, "https://example.com/vulns")

    assert result is False


def test_sync_vulns_repo_pull_timeout_is_swallowed(tmp_path: Path, monkeypatch) -> None:
    repo_path = tmp_path / "vulns"
    repo_path.mkdir()

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, timeout=1)

    monkeypatch.setattr(subprocess, "run", fake_run)

    result = sync_vulns_repo(repo_path, "https://example.com/vulns")

    assert result is False


def test_describe_git_error_prefers_stderr() -> None:
    exc = subprocess.CalledProcessError(1, ["git", "pull"], stderr="fatal: not found\n")

    assert describe_git_error(exc) == "fatal: not found"


def test_describe_git_error_falls_back_when_stderr_is_empty() -> None:
    exc = subprocess.CalledProcessError(1, ["git", "pull"], stderr="")

    assert describe_git_error(exc) == str(exc)


def test_describe_git_error_falls_back_when_stderr_is_missing() -> None:
    exc = subprocess.TimeoutExpired(["git", "pull"], timeout=1)
    exc.stderr = None

    assert describe_git_error(exc) == str(exc)
