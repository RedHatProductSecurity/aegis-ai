import subprocess

import pathspec
import pytest


def _git_tracked_files() -> list[str]:
    try:
        result = subprocess.run(
            ["git", "ls-files"],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        pytest.skip("git is not available")
    if result.returncode != 0:
        pytest.skip("not in a git repository")
    return result.stdout.splitlines()


def test_no_tracked_files_excluded_by_dockerignore():
    tracked = _git_tracked_files()

    with open(".dockerignore") as f:
        spec = pathspec.PathSpec.from_lines("gitignore", f)

    excluded = [f for f in tracked if spec.match_file(f)]
    assert not excluded, "git-tracked files excluded by .dockerignore:\n" + "\n".join(
        f"  {f}" for f in excluded
    )
