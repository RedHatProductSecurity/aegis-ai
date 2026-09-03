"""Shared git sync for the local Linux kernel vulnerabilities metadata clone.

Both the kernel CVE lookup tool (``toolsets/tools/kernel_cves``) and the
kernel classifier's offline training pipeline
(``kernel_classifier/training_input.py``) need an up-to-date local clone of
the upstream ``linux/security/vulns`` repo. This module is the single
clone-or-pull implementation for that repo so the two callers share one
source URL and one set of timeouts instead of drifting independently.

``git.kernel.org`` is blocked on some Red Hat production networks
(AEGIS-484), so the default source is ``kernel.googlesource.com``, which
mirrors the same repo at the same path under a different host.
"""

import logging
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

DEFAULT_VULNS_GIT_URL = "https://kernel.googlesource.com/pub/scm/linux/security/vulns"

GIT_CLONE_TIMEOUT = 300  # seconds
GIT_PULL_TIMEOUT = 60  # seconds


def describe_git_error(exc: Exception) -> str:
    """Return a readable error detail for a failed git subprocess call.

    Prefers the captured stderr; falls back to the exception's own repr when
    stderr is absent or empty (e.g. the process was killed before it could
    write anything), so callers never end up with a blank error message.
    """
    stderr = getattr(exc, "stderr", None)
    detail = stderr.strip() if isinstance(stderr, str) else ""
    return detail or str(exc)


def sync_vulns_repo(
    repo_path: Path,
    git_url: str = DEFAULT_VULNS_GIT_URL,
    *,
    clone_timeout: int = GIT_CLONE_TIMEOUT,
    pull_timeout: int = GIT_PULL_TIMEOUT,
) -> bool:
    """Clone *git_url* into *repo_path* if missing or incomplete, else pull the
    latest history.

    A *repo_path* that exists but has no ``.git`` subdirectory is treated as
    an incomplete clone (e.g. left behind by a clone that was interrupted or
    timed out) and is removed and re-cloned rather than pulled — pulling
    inside a non-repo directory would fail and get misreported as "stale
    data" when there was never any valid data there.

    Raises ``subprocess.CalledProcessError`` or ``subprocess.TimeoutExpired``
    if the initial clone fails — callers decide how to react to a repo that
    was never successfully established. A failed pull on an already-working
    repo is logged and swallowed so callers keep working with stale data
    rather than losing an otherwise-usable clone.

    Returns True if the repo is confirmed current (clone or pull succeeded),
    False if a pull failed and the existing clone was left as-is.
    """
    if repo_path.exists() and not (repo_path / ".git").exists():
        logger.warning("Removing incomplete clone at %s and re-cloning", repo_path)
        shutil.rmtree(repo_path)

    if not repo_path.exists():
        repo_path.parent.mkdir(parents=True, exist_ok=True)
        logger.info("Cloning %s into %s...", git_url, repo_path)
        subprocess.run(
            ["git", "clone", git_url, str(repo_path)],
            check=True,
            capture_output=True,
            text=True,
            timeout=clone_timeout,
        )
        return True

    try:
        subprocess.run(
            ["git", "pull"],
            cwd=repo_path,
            check=True,
            capture_output=True,
            text=True,
            timeout=pull_timeout,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as exc:
        logger.warning(
            "Git pull failed for %s, using stale data: %s",
            repo_path,
            describe_git_error(exc),
        )
        return False
