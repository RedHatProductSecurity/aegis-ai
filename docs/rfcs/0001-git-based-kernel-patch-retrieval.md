# RFC for Git-Based Kernel Patch Retrieval

## Summary

Replace HTTP-based patch fetching in the kernel impact classifier with
git-based retrieval from a local Linux kernel clone. Backport patch
resolution uses a multi-remote strategy: gregkh/linux (GitHub) as the
preferred source — the same source al-kernel uses — with the kernel.org
stable tree as a fallback to avoid single-source dependency on a
personal GitHub mirror. Supplemental HTML feature extraction is retained
as an HTTP-based enrichment layer.

## Motivation

The kernel impact classifier currently fetches raw patches and rendered
commit HTML pages over HTTP for every classification request. This
introduces several problems:

1. **kernel.org CGI cannot resolve stable-backport SHAs.** Backport
   commits live on per-version branches (`linux-X.Y.y`) that the CGI
   endpoint cannot serve. The current workaround tries four URL
   templates in sequence and falls back to GitHub's gregkh/linux mirror
   — coupling production reliability to GitHub availability and adding
   per-commit HTTP round-trips.

2. **Fragile multi-source probing.** Three files independently implement
   a "try URLs until one succeeds" pattern for patches, each with its
   own HTTP client (`httpx`, `urllib`). Failures surface as timeouts or
   silent skips rather than explicit resolution errors.

3. **Redundant implementations.** The ML training scraper
   (`cve_data_scraper.py`) already retrieves patches via `git show`
   from a local clone with a stable remote. The runtime classifier
   duplicates this with HTTP. The two paths use different remotes
   (kernel.org stable vs. gregkh/linux) and different resolution
   strategies, creating an inconsistency in which commits can be
   resolved.

4. **Rate limits and availability.** HTTP requests are subject to
   remote service health, rate limits, and connection timeouts. A local
   git clone eliminates this class of failure for patch retrieval.

The training scraper's git-based approach has proven reliable. This RFC
proposes generalising that approach into a shared module with a
multi-remote fallback strategy for backport resolution, and reserving
HTTP solely for supplemental HTML feature extraction where no git
equivalent exists.

## Scope

### In scope

- New shared `KernelLinuxRepo` module for local clone management
- Replacing HTTP patch fetching in the runtime classifier
- Replacing HTTP patch fetching in the eval cache population script
- Consolidating the training scraper's inline git management
- SHA resolution via local object database with multi-remote fetch
- Multi-remote fallback for backport resolution (gregkh/linux preferred,
  kernel.org stable as fallback)

### Out of scope

- Supplemental HTML feature extraction (retained as HTTP)
- Changes to the XGBoost model or feature extraction logic
- Changes to the vulns.git metadata pipeline (already git-based)
- Changes to the severity cascade or reconciliation rules

## Current Architecture

### HTTP-based patch retrieval (runtime)

The classifier in `src/aegis_ai/kernel_classifier/__init__.py` defines
two sets of URL templates and fetches data over HTTP:

```python
PATCH_URL_TEMPLATES = [
    "https://git.kernel.org/.../torvalds/linux.git/patch/?id={hash}",
    "https://git.kernel.org/.../stable/linux.git/patch/?id={hash}",
    "https://git.kernel.org/.../next/linux-next.git/patch/?id={hash}",
    "https://github.com/gregkh/linux/commit/{hash}.patch",  # fallback
]

HTML_COMMIT_URL_TEMPLATES = [
    "https://github.com/gregkh/linux/commit/{hash}",
    "https://git.kernel.org/.../stable/linux.git/commit/?id={hash}",
]
```

`_fetch_patches()` iterates through `PATCH_URL_TEMPLATES` per SHA until
a 200 response with >100 chars is received. `_fetch_commit_html()` does
the same with `HTML_COMMIT_URL_TEMPLATES` for supplemental features.

### HTTP-based cache population (evals)

`evals/utils/populate_kernel_cve_cache.py` reimplements the same
pattern to populate the eval disk cache. It imports the URL templates
from the classifier module.

### Git-based patch retrieval (training scraper)

`src/aegis_ai_ml/.../cve_data_scraper.py` already uses a local clone
with `git show` for patches. It manages its own clone lifecycle, adds a
`stable` remote pointing at `git://git.kernel.org/.../stable/linux.git`
(not gregkh/linux), and implements multi-strategy commit resolution
(`_ensure_commit_exists`).

### Supplemental HTML feature extraction

`src/aegis_ai/kernel_classifier/html.py` strips rendered HTML pages and
runs regex-based feature detection. The features it extracts (`skb`,
`write`, `lock`, `dma`, `packet`, `race`, `hardware`, `nullptr`,
`_has_code`, `_has_rip`) supplement patch-derived features via OR-merge.
Critically, `_has_code` and `_has_rip` feed the `kernel_panic_plus_uaf`
interaction rule in the cascade, which can escalate MODERATE → IMPORTANT
(R11). The XGBoost model was trained with these HTML-derived features.

Rendered HTML pages are a web resource with no git equivalent. The
classifier already treats HTML as optional enrichment and degrades
gracefully when unavailable.

### Data flow

```
vulns.git ──parse──▶ commit SHAs
                          │
              ┌───────────┴───────────┐
              ▼                       ▼
     _fetch_patches()        _fetch_commit_html()
     (HTTP → git)            (HTTP, retained)
              │                       │
              ▼                       ▼
    extract_patch_features   extract_html_features
              │                       │
              └───────┬───────────────┘
                      ▼ (OR-merge)
              merged feature flags
                      │
                      ▼
              apply_flag_cascade
                      │
                      ▼
              XGBoost predict
                      │
                      ▼
              apply_cascade (R5–R12)
                      │
                      ▼
                impact label
```

### Files that make HTTP requests for patches/commits

| File | Patches (HTTP) | HTML (HTTP) |
|------|:--------------:|:-----------:|
| `src/aegis_ai/kernel_classifier/__init__.py` | Yes | Yes |
| `evals/utils/populate_kernel_cve_cache.py` | Yes | Yes |
| `src/aegis_ai_ml/.../cve_data_scraper.py` | No (already git) | Yes (`urllib`) |

## Proposed Design

### New module: `KernelLinuxRepo`

**Location:** `src/aegis_ai/kernel_classifier/git_repo.py`

A thread-safe manager for a local Linux kernel git clone with
multi-remote support. Follows the same lifecycle pattern as the existing
`KernelVulnsRepo` in `src/aegis_ai/toolsets/tools/kernel_cves/`.

#### Public API

```python
class KernelLinuxRepo:
    """Manages a local Linux kernel git clone with multi-remote support.

    Provides git-based patch retrieval and commit resolution, eliminating
    HTTP requests to kernel.org CGI endpoints.  Uses three remotes:
    torvalds/linux (mainline), gregkh/linux (preferred backport source),
    and kernel.org stable (fallback backport source).
    """

    def __init__(self, base_dir: Path):
        """Set repo paths. No I/O performed."""

    def setup(self) -> None:
        """Clone if missing; add gregkh + stable remotes if absent;
        time-gated fetch.

        Thread-safe via threading.Lock. Idempotent — safe to call from
        multiple threads or repeated async invocations.
        """

    def resolve_commit(self, commit_hash: str) -> bool:
        """Return True if the SHA exists in the local object database.

        If the commit is not found locally, triggers incremental fetches
        (origin, then gregkh, then stable) subject to rate limiting.
        """

    def get_patch(self, commit_hash: str) -> str | None:
        """Return `git show <sha>` output (commit message + unified diff).

        Calls resolve_commit first. Returns None if the commit cannot be
        resolved after fetching all remotes.
        """
```

#### Remote layout

| Remote | URL | Purpose |
|--------|-----|---------|
| `origin` | `https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git` | Mainline commits |
| `gregkh` | `https://github.com/gregkh/linux.git` | Preferred backport source — all stable branches (`linux-X.Y.y`). The same source al-kernel uses. |
| `stable` | `https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git` | Fallback backport source — official kernel.org stable tree. Used when gregkh/linux is unavailable. |

**Why three remotes:** gregkh/linux is a personal GitHub mirror
maintained by Greg Kroah-Hartman. While it is the de facto standard for
stable-tree access (and al-kernel's primary source), it is not official
kernel.org infrastructure. It depends on a single maintainer and on
GitHub availability. The kernel.org stable tree
(`git.kernel.org/.../stable/linux.git`) is the upstream canonical
source maintained by the kernel community's own infrastructure. Both
trees contain the same stable-backport commits on `linux-X.Y.y`
branches, but may differ in fetch performance, availability, and update
timing.

Using gregkh/linux as the preferred remote preserves consistency with
al-kernel. Adding the kernel.org stable tree as a fallback ensures
backport resolution does not depend on any single external service.

#### Commit resolution strategy

Ordered; short-circuits on first success:

1. `git cat-file -e <sha>` — check local object database
2. `git fetch origin` (rate-limited) — mainline; recheck
3. `git fetch gregkh` (rate-limited) — preferred backport source; recheck
4. `git fetch stable` (rate-limited) — fallback backport source; recheck
5. Return `False`

Rate limiting uses a per-remote timestamp file, defaulting to one fetch
per `AEGIS_KERNEL_REPO_UPDATE_INTERVAL` seconds. A failed resolution
may trigger an immediate retry fetch (bypassing the interval) to handle
newly-published commits. If a remote is unreachable during a fetch
attempt, the algorithm logs a warning and proceeds to the next remote
without blocking.

#### Configuration

| Environment variable | Default | Description |
|---------------------|---------|-------------|
| `AEGIS_KERNEL_LINUX_REPO_DIR` | `{config_dir}/kernel_linux` | Path to the local Linux kernel clone |
| `AEGIS_KERNEL_REPO_UPDATE_INTERVAL` | `3600` | Minimum seconds between remote fetches |

#### Async bridging

All public methods perform synchronous subprocess calls. Async callers
(the classifier's `classify()` pipeline) use `asyncio.to_thread()`:

```python
patch = await asyncio.to_thread(repo.get_patch, commit_hash)
```

#### Thread safety

A `threading.Lock` protects clone, remote-add, and fetch operations
(the only mutations). `git show` and `git cat-file -e` are read-only
and do not require the lock on a healthy repository.

### Changes to `KernelImpactClassifier`

#### `_fetch_patches` — replaced with git

```python
async def _fetch_patches(self, commit_hashes: list[str]) -> list[tuple[str, str]]:
    """Fetch raw patches from local Linux kernel git clone.

    Uses KernelLinuxRepo with torvalds (origin), gregkh, and stable
    remotes to resolve any commit SHA, including stable-backport
    hashes on linux-X.Y.y branches.
    """
    repo = self._get_linux_repo()
    await asyncio.to_thread(repo.setup)
    patches = []
    for sha in commit_hashes:
        patch = await asyncio.to_thread(repo.get_patch, sha)
        if patch and len(patch) > 100:
            patches.append((sha, patch))
        else:
            logger.warning(
                "Could not retrieve patch for %s from git "
                "(tried origin, gregkh, and stable remotes)",
                sha[:12],
            )
    return patches
```

#### `_fetch_commit_html` — unchanged (HTTP retained)

The method, its `httpx` client, and `HTML_COMMIT_URL_TEMPLATES` remain
exactly as they are today. Supplemental HTML feature extraction
continues to fetch rendered web pages from GitHub (gregkh/linux) and
kernel.org via HTTP.

#### `html.py` — unchanged

No modifications. `extract_html_features` and `strip_html` are
unaffected.

#### Constants removed

| Constant | Action |
|----------|--------|
| `PATCH_URL_TEMPLATES` | Removed — no longer needed |
| `_GREGKH_FALLBACK_TEMPLATE` | Removed — no longer needed |
| `HTML_COMMIT_URL_TEMPLATES` | Retained — still used by `_fetch_commit_html` |

#### `classify()` pipeline — unchanged structure

The pipeline order and supplemental HTML OR-merge are preserved:

1. `_fetch_patches()` via git **(changed)**
2. `_extract_features()` on patches (unchanged)
3. `_fetch_commit_html()` via HTTP (unchanged)
4. `extract_html_features()` supplements patch features (unchanged)
5. `_apply_flag_cascade()` (unchanged)
6. `_predict()` (unchanged)

### Changes to eval infrastructure

#### `populate_kernel_cve_cache.py`

Phase 2 patch fetch (`_fetch_patches`) is rewritten to use
`KernelLinuxRepo.get_patch()`, writing `.patch` files in the same cache
format. Phase 2 HTML fetch (`_fetch_html`) remains HTTP — no change.

The `PATCH_URL_TEMPLATES` import is removed. The
`HTML_COMMIT_URL_TEMPLATES` import is retained.

#### `kernel_patch_cache.py`

No changes. The disk cache reader is source-agnostic — it reads
`.patch` and `.html` files regardless of how they were populated.

#### `conftest.py`

No changes. Monkeypatches target `_fetch_patches` and
`_fetch_commit_html` on the `KernelImpactClassifier` class. Both method
signatures are preserved; only the internal implementation of
`_fetch_patches` changes.

### Changes to training scraper

`cve_data_scraper.py` replaces its inline git management with
`KernelLinuxRepo`:

| Removed (inline) | Replaced by |
|-------------------|-------------|
| `setup_linux_repo()` | `KernelLinuxRepo.setup()` |
| `_ensure_stable_remote_available()` | Handled inside `setup()` — adds `gregkh` + `stable` remotes |
| `_ensure_commit_exists()` | `KernelLinuxRepo.resolve_commit()` |
| `fetch_commit_info_from_linux_repo()` subprocess calls | `KernelLinuxRepo.get_patch()` |

This also **fixes an existing gap**: the training scraper currently adds
only a kernel.org `stable` remote, with no gregkh/linux fallback. After
consolidation, all pipelines use the same three-remote strategy
(origin + gregkh + stable) and share the same resolution algorithm.

`fetch_commit_html()` remains HTTP (`urllib`) — no change.

## Backward Compatibility

| Concern | Impact |
|---------|--------|
| **Eval cache format** | No change — `.patch` and `.html` files are identical |
| **`conftest.py` monkeypatching** | No change — method signatures preserved |
| **XGBoost model** | No retraining needed — same feature inputs |
| **HTML-derived features** | Identical — `html.py` and `_fetch_commit_html` unchanged |
| **`httpx` dependency** | Still required for HTML fetch and LLM providers |
| **`git show` vs HTTP `.patch` format** | `git show` includes the commit message and unified diff in a slightly different layout than `git format-patch`. The feature extractor uses content-based regex and is format-tolerant. Validated in Phase 2 of the roadmap. |

## Risks and Mitigations

| Risk | Likelihood | Impact | Mitigation |
|------|:----------:|:------:|------------|
| **Clone lost on pod rollout** | Certain | High | No PVC exists in the current deployment. The repo currently has no Kubernetes manifests with persistent volumes — even the existing vulns.git clone is re-cloned on every pod start. For vulns.git (small, fast) this is tolerable; for a linux kernel clone (500 MB–3 GB) it is not. A cold clone from torvalds + fetch from gregkh + stable could take 10–30 minutes depending on network. **Requires a PersistentVolumeClaim** mounted at `AEGIS_KERNEL_LINUX_REPO_DIR` (or the parent `config_dir`) to survive pod rollouts. See open question 4. |
| **Initial clone is slow** (~3 GB full, ~500 MB treeless) | Certain (first run) | Medium | Use `git clone --filter=blob:none` (treeless partial clone). Blobs fetched on-demand by `git show`. Clone happens once *if* the volume is persistent. Without persistence this cost is paid on every pod start — unacceptable for production. |
| **Disk space** | Certain | Low | ~500 MB treeless, ~3 GB full. Already a requirement for the training pipeline. Configurable location via env var. PVC sizing should account for growth over kernel release cycles. |
| **`git show` output triggers different feature flags than HTTP patches** | Low | Medium | Phase 2 validation: run classifier on eval CVE set with both paths, compare feature flags and predictions. Feature extractor uses content-based regex that is format-tolerant. |
| **gregkh/linux unavailable or discontinued** | Medium | Medium | gregkh/linux is a personal GitHub mirror — not kernel.org infrastructure. Depends on a single maintainer (Greg KH) and GitHub availability. Mitigated by the kernel.org stable fallback remote: the resolution algorithm falls through to `git fetch stable` when `git fetch gregkh` fails or the commit is absent. Both trees carry the same stable-backport commits. |
| **kernel.org stable tree diverges from gregkh/linux** | Low | Low | Both are mirrors of the same upstream stable branches. Temporary divergence (hours) is possible during release windows. The resolution algorithm tries gregkh first (faster sync to Greg KH's pushes), with kernel.org stable as a safety net for the reverse case. |
| **Container/CI environments** | Low | Low | `git` is already a hard dependency (vulns.git clone). No new requirement. |
| **Concurrent access to repo** | Low | Low | `threading.Lock` for mutations (proven pattern from `KernelVulnsRepo`). Read-only git operations (`git show`, `git cat-file -e`) are lock-free. |
| **HTML fetch still depends on HTTP** | N/A | N/A | By design. HTML is supplemental — classifier degrades gracefully when unavailable. No change to this resilience. |

## Implementation Roadmap

### Phase 1: Core git module

Introduce `KernelLinuxRepo` as a tested, standalone module.

| Step | File | Description |
|------|------|-------------|
| 1a | `src/aegis_ai/kernel_classifier/git_repo.py` | Implement `KernelLinuxRepo`: clone, `gregkh` + `stable` remote add, rate-limited multi-remote fetch, `resolve_commit()`, `get_patch()`. Thread-safe via `threading.Lock`. |
| 1b | `tests/unit/kernel_classifier/test_git_repo.py` | Unit tests with mocked `subprocess.run` — clone, remote add, fetch, resolve, get_patch. Test rate-limiting and error handling. |
| 1c | `docs/env-vars.md` | Document `AEGIS_KERNEL_LINUX_REPO_DIR` and `AEGIS_KERNEL_REPO_UPDATE_INTERVAL`. |

**Exit criteria:** Unit tests green. Manual integration: resolve a known
stable-backport SHA that fails on kernel.org CGI.

### Phase 2: Replace HTTP patch fetching in classifier

Swap `_fetch_patches` to use `KernelLinuxRepo`. Keep `_fetch_commit_html`
as HTTP.

| Step | File | Description |
|------|------|-------------|
| 2a | `src/aegis_ai/kernel_classifier/__init__.py` | Rewrite `_fetch_patches()` to use `KernelLinuxRepo`. Remove `PATCH_URL_TEMPLATES` and `_GREGKH_FALLBACK_TEMPLATE`. Keep `HTML_COMMIT_URL_TEMPLATES` and `httpx` import. |
| 2b | — | Parity validation: run classifier on eval CVE set with both old (HTTP) and new (git) paths. Compare active features, predictions, confidence. |
| 2c | `src/aegis_ai/toolsets/tools/kernel_classifier/__init__.py` | Verify end-to-end integration (no code changes expected). |

**Exit criteria:** Feature flags and predictions match across eval set.
HTML supplemental flags still fire as before.

### Phase 3: Update eval infrastructure

Align eval cache population with the git-based patch path.

| Step | File | Description |
|------|------|-------------|
| 3a | `evals/utils/populate_kernel_cve_cache.py` | Rewrite `_fetch_patches()` to use `KernelLinuxRepo`. Keep `_fetch_html()` as HTTP. |
| 3b | `evals/utils/kernel_patch_cache.py` | No changes expected — verify cache reader is source-agnostic. |
| 3c | `evals/conftest.py` | No changes expected — verify monkeypatches still work. |
| 3d | — | Full eval suite run; confirm no regressions. |

**Exit criteria:** Eval suite green. No regression in cache hit rates or
eval metrics.

### Phase 4: Consolidate training scraper

Eliminate duplicate git management in `cve_data_scraper.py`.

| Step | File | Description |
|------|------|-------------|
| 4a | `src/aegis_ai_ml/.../cve_data_scraper.py` | Remove `setup_linux_repo()`, `_ensure_stable_remote_available()`, `_ensure_commit_exists()`. Replace with `KernelLinuxRepo` (adds gregkh remote alongside existing stable, uses unified resolution algorithm). Keep `fetch_commit_html()` as HTTP. |
| 4b | — | Run scraper on CVE subset; diff output against pre-refactor baseline. |

**Exit criteria:** Scraper output identical (patches, commit JSON). All
pipelines share the same three-remote strategy and resolution algorithm.

### Phase 5: Cleanup

| Step | Description |
|------|-------------|
| 5a | Remove `PATCH_URL_TEMPLATES` from any remaining imports. |
| 5b | Update module docstrings to reflect git-based patch flow + HTTP supplemental HTML flow. |
| 5c | Audit `httpx` usage — confirm still needed (yes: HTML fetch + LLM providers). |
| 5d | Update developer documentation and deployment guides. |

## Alternatives Considered

### A. Replace both patches and HTML with git

Eliminate HTTP entirely by extracting HTML-derived features from `git
show` output instead of rendered web pages.

**Rejected.** The XGBoost model was trained with HTML-derived features.
The rendered page context (crash reports, call stacks as rendered by
GitHub/kernel.org) may surface patterns differently than raw git text.
The `_has_code` + `_has_rip` → `kernel_panic_plus_uaf` cascade path
directly affects severity escalation (R11). Changing the feature source
risks silent model drift without retraining. The HTML fetch is already
supplemental and degrades gracefully.

### B. Use kernel.org stable tree as the sole backport remote

Use `git.kernel.org/.../stable/linux.git` as the only backport remote,
matching what the training scraper does today. Drop gregkh/linux.

**Rejected as sole source.** The kernel.org stable tree is official
infrastructure and contains the same backport commits, making it a
viable source. However, al-kernel uses gregkh/linux as its primary
source, and the existing runtime HTTP fallback that successfully
resolves backport SHAs already uses gregkh/linux. Switching to
kernel.org stable as the only source would break consistency with
al-kernel without a clear reliability advantage.

**Adopted as fallback.** The proposed design uses both: gregkh/linux as
the preferred backport remote (consistency with al-kernel) and
kernel.org stable as a fallback (resilience against gregkh/linux
unavailability). See "Commit resolution strategy" for the ordering.

### D. Use gregkh/linux as the sole backport remote

Use `github.com/gregkh/linux.git` as the only backport remote.

**Rejected.** gregkh/linux is a personal GitHub mirror, not official
kernel.org infrastructure. It is maintained by a single individual (Greg
Kroah-Hartman) and depends on GitHub's availability. While it is the de
facto standard for stable-tree access and al-kernel's primary source,
treating it as the sole backport remote creates a single point of
failure. If Greg KH stops maintaining the mirror, changes its structure,
or GitHub experiences an extended outage, backport resolution would fail
with no fallback. The kernel.org stable tree provides the necessary
safety net at negligible cost (one additional `git remote add` and a
fallback fetch step).

### C. Keep HTTP for patches but switch to gregkh/linux only

Simplify `PATCH_URL_TEMPLATES` to a single gregkh/linux entry and
remove the kernel.org CGI URLs.

**Rejected.** This reduces but does not eliminate the HTTP dependency
for patches. It still subjects every classification request to network
round-trips and GitHub availability. A local git clone with the same
remote provides strictly better reliability with no external dependency
at read time.

## Open Questions

1. **Treeless vs. full clone.** `git clone --filter=blob:none` reduces
   initial clone to ~500 MB but fetches blobs on-demand for each `git
   show`. For the expected workload (a few commits per CVE), on-demand
   blob fetch adds negligible latency. Should we default to treeless
   clone, or is full clone preferable for environments with restricted
   outbound network access after initial setup?

2. **Shared clone with training scraper.** Should the runtime classifier
   and training scraper share a single clone directory, or maintain
   independent clones? A shared clone saves disk space but introduces
   concurrent-access considerations during training runs.

3. **Repository update strategy.** The linux kernel repo is
   substantially larger than vulns.git, making `git fetch` across three
   remotes a non-trivial operation (seconds to minutes depending on
   staleness). Several update strategies are possible:

   - **Request-triggered with cooldown** (current `KernelVulnsRepo`
     pattern). `setup()` is called on every classification request and
     fetches if more than `AEGIS_KERNEL_REPO_UPDATE_INTERVAL` seconds
     have elapsed. Simple and self-maintaining, but adds latency to the
     first request after the cooldown expires. For vulns.git (small
     repo, 600 s interval), this works well. For the kernel repo (3
     remotes, much larger), the fetch cost during a request may be
     unacceptable.

   - **Request-triggered fetch only on resolution failure.** `setup()`
     only clones/adds remotes; routine fetches are skipped.
     `resolve_commit()` triggers a fetch only when `git cat-file -e`
     fails — i.e., the commit is not in the local object database. This
     avoids fetch latency for already-cached commits (the common case,
     since most CVE fix commits are published well before analysis) and
     only pays the cost when encountering a genuinely new SHA. The risk
     is that the local repo accumulates staleness for commits that are
     never explicitly requested, but for this use case that is harmless.

   - **Background cron / scheduled task.** A periodic job (systemd
     timer, Kubernetes CronJob, cron) runs `git fetch` on all remotes
     on a fixed schedule (e.g., every 6 hours). The runtime classifier
     never fetches — it only reads from the local object database.
     Provides predictable latency on every request, but requires
     operational infrastructure and does not self-heal if the cron
     fails.

   - **Hybrid: cron for freshness + request-triggered for misses.**
     A background job keeps the repo reasonably fresh. If
     `resolve_commit()` encounters a miss, it triggers an on-demand
     fetch as a fallback. Combines predictable latency with
     self-healing, at the cost of slightly more operational complexity.

   The right choice depends on deployment context (standalone service
   vs. container fleet vs. developer laptop) and acceptable
   first-request latency. The `AEGIS_KERNEL_REPO_UPDATE_INTERVAL` env
   var provides a tuning knob regardless of which strategy is chosen,
   but the default behavior — and whether on-demand fetch is tied to
   cooldown timers or resolution failures — needs to be decided.

4. **Persisting the kernel repo across pod rollouts.** The current
   deployment has **no PersistentVolumeClaims**. The repo contains no
   Helm charts or Kubernetes manifests with persistent volumes — the
   Tekton pipeline uses only `emptyDir` and Secret volumes. Even the
   existing vulns.git clone under `config_dir/kernel_cves` is not
   persisted; it is re-cloned on every pod start.

   For vulns.git (tens of MB, clones in seconds) this is a tolerable
   cold-start cost. A linux kernel clone (500 MB–3 GB, 10–30 minutes
   to clone + fetch three remotes) cannot be re-cloned on every pod
   rollout in production. Several approaches exist:

   - **PVC mounted at `config_dir` or `AEGIS_KERNEL_LINUX_REPO_DIR`.**
     The straightforward solution. A ReadWriteOnce PVC survives pod
     restarts and rollouts on the same node. Sizing should account for
     the kernel clone (~5 GB headroom for treeless + growth), vulns.git,
     and other caches under `config_dir`. This also fixes the existing
     vulns.git re-clone cost as a side benefit.

   - **ReadWriteMany (RWX) PVC or NFS.** If multiple replicas need
     concurrent read access to the same clone, an RWX volume (e.g.,
     CephFS, NFS) allows sharing. Write contention for `git fetch`
     would still need coordination (the `threading.Lock` handles
     in-process contention but not cross-pod). A single-writer /
     multi-reader pattern (one pod fetches, others read) may be needed.

   - **Pre-warmed image layer or init container.** Bake a recent
     snapshot of the kernel clone into the container image (or a
     sidecar image), and copy/rsync it into an `emptyDir` on pod
     start. Avoids PVC infrastructure but increases image size and
     requires periodic image rebuilds to keep the snapshot fresh.

   - **External shared storage (S3/object store + git bundle).**
     Periodically `git bundle` the repo and store it in S3 or an
     internal object store. An init container downloads and unbundles on
     pod start. Faster than a full clone but still minutes of cold-start
     time and requires bundle maintenance infrastructure.

   This decision is coupled to open question 3 (update strategy). If a
   background cron handles fetches, the PVC must be writable by the cron
   job's pod. If request-triggered, the application pod needs write
   access. The PVC approach is the simplest and most operationally
   standard; it should likely be implemented for `config_dir` broadly,
   not just the kernel clone, since other caches (vulns.git, CWE, CISA
   KEV) would also benefit from persistence.
