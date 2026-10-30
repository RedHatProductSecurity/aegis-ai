# Evaluation suite for Aegis features

This directory holds **pytest**-driven evaluations built on **pydantic-evals**. Each feature test builds a `Dataset` of cases (usually CVE IDs plus expected outputs), runs the real Aegis feature through `rh_feature_agent`, and scores outputs with programmatic and LLM-based evaluators. CVE data comes from a **checked-in OSIDB cache** (`evals/osidb_cache/` by default): `evals/conftest.py` wraps `osidb_tool` so runs stay stable when the live OSIDB changes.

The suite is meant to catch regressions, compare LLM behavior, and validate changes to Aegis itself. Evaluators that call an LLM use the **eval LLM** (see below), which defaults to the same model as the rest of Aegis unless you override it.


## Running the evaluation suite

From the repository root:

| Command | What it runs |
| ------- | ------------ |
| `make eval` | `uv run pytest -vv -s --show-capture=no evals` |
| `make eval-debug` | Same as `eval`, but `AEGIS_LLM_MAX_JOBS=1`, DEBUG log level, and CLI logging enabled (easier single-threaded debugging) |
| `make eval-in-parallel` | `uv run pytest -vv -n auto evals` (pytest-xdist) |

To process an ad-hoc set of CVEs without modifying the canonical list (`eval-kernel-cves.csv`):

```bash
uv run python evals/features/cve/generate_kernel_eval_csv.py --cves CVE-2025-12345 CVE-2026-67890
```

Optional **independent LLM for evaluators** (LLM judges and scoring judges), while Aegis still uses your normal app settings:

```bash
export AEGIS_EVALS_LLM_HOST="https://…"
export AEGIS_EVALS_LLM_MODEL="…"
export AEGIS_EVALS_LLM_API_KEY="…"
```

### Kernel eval ground truth

The kernel suggest-impact eval (`test_suggest_impact_kernel_cves.py`) compares AEGIS predictions against OSIDB ground truth stored in `eval-kernel-cves.csv`.

**Files** (all under `evals/features/cve/`):

| File | Role |
| ---- | ---- |
| `eval-kernel-cves.csv` | Canonical CSV of CVE IDs with OSIDB ground truth (`OSIDB Impact`, `OSIDB CVSS`, `OSIDB CVSS Vector`). Committed to the repo so evals are reproducible without OSIDB access. Add new CVEs with `generate_kernel_eval_csv.py --cves`. |
| `generate_kernel_eval_csv.py` | Queries OSIDB for each CVE's impact and CVSS score. Without `--cves`, re-processes all CVEs already in the CSV. Requires a Kerberos ticket (`kinit`). |

**Caches** (populated by `make populate-kernel-caches` or `make prepare-kernel-eval`):

| Directory | Role | Populate script |
| --------- | ---- | --------------- |
| `evals/osidb_cache/` | OSIDB CVE data (auto-populated on first eval miss) | `evals/utils/osidb_cache.py` |
| `evals/kernel_cve_context_cache/` | Kernel CVE metadata + commit hashes from linux-vulns repo | `evals/utils/populate_kernel_cve_cache.py` |
| `evals/kernel_patch_cache/` | Raw git patches (`patches/`) and commit HTML pages (`html/`) | `evals/utils/populate_kernel_cve_cache.py` (phase 2) |

All three caches are checked into the repo so evals run without network access (except for the LLM API).

**Regenerating ground truth and caches when you add a new kernel CVE:**

```bash
# Add new CVEs and regenerate ground truth + caches:
uv run python evals/features/cve/generate_kernel_eval_csv.py --cves CVE-2026-99999
make populate-kernel-caches

# Or re-process all existing CVEs and rebuild caches:
make prepare-kernel-eval
```

Individual steps (if needed):

```bash
make generate-kernel-eval       # regenerate eval-kernel-cves.csv from OSIDB (requires kinit)
make populate-kernel-caches     # populate kernel CVE context + patch/HTML caches
```

A session-scoped conftest fixture will **fail** if the CSV is missing.

### Kernel memory-corruption and race regressions (AEGIS-545)

The SuggestImpact dataset includes a focused group with hard assertions for
`AC`, `C`, `I`, `A`, and the impact label when supplied for the positive
memory-corruption/race regressions. Negative controls require `C:N/I:N`, guarding
against invented kernel-memory impact. Their AC/A/impact expectations remain
part of the general soft vector, score, and impact comparisons. The hard
assertions fail even when the similarity scores exceed their thresholds.
Run just this group (live LLM inference, cached tool evidence):

```bash
uv run pytest -vv -s --show-capture=no evals/features/cve/test_suggest_impact.py --kernel-memory-regressions-only
```

The default SuggestImpact run evaluates the complete dataset, including these
regressions, with each case executed once.

| CVE | Coverage and hard assertions | Calibration expectations |
| --- | --- | --- |
| CVE-2026-98432 | IPv4 TCP option UAF; attacker-induced handshake/teardown and retransmission race, kernel heap disclosure and writes. Require `AC:L/C:H/I:H/A:H` and CRITICAL. | 9.8 |
| CVE-2025-38052 | TIPC asynchronous encryption races namespace teardown; a reported read-after-free must not erase plausible kernel-memory impact. Existing RH/NIST vectors: `AC:L/C:H/I:H/A:H`. | 7.8; no expected impact label |
| CVE-2025-40248 | vsock transport lifetime race induced by concurrent connect/sendmsg and signals. Require `AC:L/C:H/I:H/A:H` (CVEORG) and IMPORTANT. | 7.8 |
| CVE-2023-53733 | Negative control: failed traffic-control filter binding affects internal state/references. Require `C:N/I:N`. | Existing dataset: `AC:L/A:H`, MODERATE, 5.5 (soft) |
| CVE-2022-50865 | Negative control: TCP backlog-limit arithmetic can drop packets, without a kernel-memory access primitive. Require `C:N/I:N`. | RH: `AC:H/A:L`, LOW, 3.7 (soft) |

**Control scope and baseline.** The backlog fix
`ec791d8149ff60c40ad2074af3b92a39c916a03f` changes a socket queue-limit
calculation, not a kernel-memory read/write primitive. Its cached RH and CVEORG
vectors disagree about AC and A. The filter-binding fix
`9cb36faedeafb9720ac236aeae2ea57091d90a09` balances references on hardware-offload
error paths; the upstream patch does not demonstrate attacker-controlled memory
reuse or establish the extent of an outage. Both are useful controls for
unjustified C/I inflation. Exact availability and severity calibration is a
different question from the AEGIS-545 memory-corruption/attacker-race invariant.

A live control baseline on 2026-10-30 used `gemini-3.8-flash`, the kernel
classifier enabled, and the original prompts from `origin/main` commit
`b7690d4d1452472afc82482a0b00f8394955fd2c`. A temporary pytest plugin extracted
the original prompt literals with AST parsing and replaced the runtime
constants, including the imported kernel-rule alias; production files were
not edited.

| CVE | Observed origin/main assessment | Original all-metrics hard assertion |
| --- | --- | --- |
| CVE-2022-50865 | IMPORTANT 7.5, `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | Failed AC, A, and impact: this calibration discrepancy predates AEGIS-545. |
| CVE-2023-53733 | MODERATE 5.5, `CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H` | Passed. |

These observations do not replace source ground truth. C/I-only hard checks
retain the controls' relevant invariant, while their original vector/score/impact
expectations continue to expose calibration differences through soft scores.
The positive cases retain exact AC/CIA assertions and supplied impact labels;
CVE-2026-98432 requires CRITICAL with no failure waiver.

**CVE-2026-98432 evidence**, retrieved 2026-10-30:

- `osidb_cache/CVE-2026-98432.json` is a live OSIDB response serialized by
  `write_cache_entry` (affects omitted). RH and CVEORG both supply the vector
  `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`; OSIDB reports CRITICAL.
  The corresponding row in `eval-kernel-cves.csv` uses this OSIDB ground truth.
- The [public Linux CNA record](https://cveawg.mitre.org/api/cve/CVE-2026-98432)
  reports the same 9.8 CRITICAL vector and explains the attacker-controlled race,
  stale-option disclosure, and kernel-write primitives.
- `kernel_cve_context_cache/CVE-2026-98432.json` contains the real Linux vulns
  repository JSON and mbox retrieved from its configured
  [Google mirror](https://kernel.googlesource.com/pub/scm/linux/security/vulns/+/refs/heads/master/cve/published/2026/).
  `metadata.source_files` records the retrieval URLs. The mirrored CNA metrics
  were checked against the public CVE API when captured.
- `external_references_cache/09a2ecf5167032b71946bf5a6d6a24cb6bc51208108e3ccfd44d503400e49d11.json`
  serves that same decoded mbox under the original kernel.org URL from OSIDB.
  The kernel.org HTTP endpoint returned an Anubis challenge, so this cache uses
  the genuine mirrored advisory with the normal email sanitization/truncation.
- All eight referenced fix commits have raw patches and stripped commit-page
  text in `kernel_patch_cache/{patches,text}/`, fetched by
  `populate_kernel_cve_cache.py` from the `gregkh/linux` GitHub mirror.
  These include mainline `e3f33b0a1d89d738e2b913dab519226eaf76e15b` and stable
  `b3b027ef0cd322bfa839b9aaf5b27551eea54cf6`.
- `ghsa_cache/CVE-2026-98432.json` is the authentic raw
  [OSV.dev response](https://api.osv.dev/v1/vulns/CVE-2026-98432) captured during
  the live regression run by `ghsa_cache_retrieve` / `write_ghsa_cache_entry`
  (enumerated versions omitted by the normal cache writer). Its CVSS vector
  and all eight git fix commits match the CNA. Deterministic tests exercise
  cache-only retrieval and the same filtered description/ranges used by the
  OSV tool, rejecting any live fallback on a missing fixture.

Deterministic evaluator and cache-completeness checks run with
`uv run pytest tests/test_impact_regression_evaluator.py`.

### Configuration Notes

If `AEGIS_EVALS_LLM_HOST` is `https://generativelanguage.googleapis.com`, the suite configures a **Google** eval model; otherwise it uses an **OpenAI-compatible** client against `{AEGIS_EVALS_LLM_HOST}/v1/`. If these variables are unset, evaluators reuse `default_llm_model` / `default_llm_settings` from app settings (`evals/features/common.py`).

**Aegis** inference and tools (not the eval LLM) are controlled by the same variables as in the rest of the project; see the top-level [README.md](../README.md#quick-start).

**Optional exit policy:** if `AEGIS_EVALS_MIN_PASSED` is set to an integer, pytest is forced to exit successfully when at least that many tests have passed (see `evals/conftest.py`). Useful for partial CI or smoke runs.


## Results and failures

- If any **assertion** fails, any **evaluator** raises, or any **score** is below `MIN_SCORE_THRESHOLD`, the test fails and `handle_eval_report` collects a single `AssertionError` listing unsatisfied checks.
- Cases may set `metadata["known_to_fail_evaluators"]` with evaluator names; failures from those evaluators are **ignored** for that case (still scored, but do not fail the run).
- Reports print per-case inputs, expected output, actual output, scores, assertions, and reasons. Numeric scores are shown with **✔** or **✗** depending on `MIN_SCORE_THRESHOLD`. Per-case **durations** are included only when `llm_max_jobs == 1` (parallel runs omit them as misleading).
- For **suggest affected components**, the rendered output column shows **component lists only** (easier to read).
- At session end, the suite logs a short **summary per feature** (coverage, average scores per evaluator, assertion ratio, timings).

Example failure line shape:

```
FAILED evals/features/cve/test_suggest_cwe.py::test_eval_suggest_cwe - AssertionError: Unsatisfied assertion(s):
suggest-cwe-for-CVE-2025-23395: SuggestCweEvaluator(): score below threshold: -0.95 < 0.1
```


## Tunables and environment

| Name | Location | Description | Default |
| ---- | -------- | ----------- | ------- |
| `EXPLANATION_MIN_LEN` | [common.py](features/common.py) | Minimum explanation length; below this, `FeatureMetricsEvaluator` proportionally reduces the score (not applied to Identify PII or CVSS diff outputs). | 80 |
| `HIGH_CONFIDENCE_PENALTY_DIVISOR` | [common.py](features/common.py) | When confidence exceeds the base score, the gap is divided by this and subtracted (`reflect_confidence`). | 4.0 |
| `LOW_CONFIDENCE_PENALTY_DIVISOR` | [common.py](features/common.py) | When confidence is below the base score, the gap is divided by this and added (`reflect_confidence`). | 4.0 |
| `MIN_SCORE_THRESHOLD` | [common.py](features/common.py) | Scores below this fail the case (unless the evaluator is in `known_to_fail_evaluators`). | 0.1 |
| `FIELD_RUBRICS` | [common.py](features/common.py) | Shared LLM rubrics for title, description, statement, and mitigation semantic scoring. | (see file) |

Eval-specific environment variables (eval LLM, suggest-affected-components sampling, cache path, `AEGIS_EVALS_MIN_PASSED`) are documented in [docs/env-vars.md](../docs/env-vars.md#eval-settings).


## Common evaluators

Used by all CVE feature evals that import `common_feature_evals`:

| Name | Location | Score | Assertion | Description |
| ---- | -------- | ----- | --------- | ----------- |
| `FeatureMetricsEvaluator` | [common.py](features/common.py) | ✓ | | Starts from `output.confidence`, then applies explanation-length penalty when applicable (see `EXPLANATION_MIN_LEN`). |
| `ToolsUsedEvaluator` | [common.py](features/common.py) | | ✓ | Asserts that `osidb_tool` appears in `tools_used`. |


## Feature-specific evaluators

| Name | Location | Score | Assertion | Description |
| ---- | -------- | ----- | --------- | ----------- |
| `CVSSDiffEvaluator` | [test_cvss_diff.py](features/cve/test_cvss_diff.py) | | ✓ | Explanation is empty iff Red Hat and NVD CVSS vectors match (valid vectors required). |
| `LLMJudge` (`ExplanationIsRelevant`) | [test_cvss_diff.py](features/cve/test_cvss_diff.py) | | ✓ | Empty explanation or text explaining why Red Hat’s CVSS vector differs from NVD’s. |
| `IdentifyPIIEvaluator` | [test_identify_pii.py](features/cve/test_identify_pii.py) | | ✓ | `contains_PII` matches expectation; explanation empty iff no PII. |
| `LLMJudge` (`ExplanationProvidedIfNeeded`) | [test_identify_pii.py](features/cve/test_identify_pii.py) | | ✓ | If `contains_PII` is true, explanation is non-empty. |
| `LLMJudge` (`ExplanationEmptyOrBulletedList`) | [test_identify_pii.py](features/cve/test_identify_pii.py) | | ✓ | Explanation empty or uses bullet lines starting with `-`. |
| `LLMJudge` (`TitleEvaluator`) | [test_suggest_description.py](features/cve/test_suggest_description.py) | ✓ | | Semantic match for `suggested_title` vs expected (only when the case supplies an expected title). Rubric: `FIELD_RUBRICS["suggest-title"]`. |
| `LLMJudge` (`DescriptionEvaluator`) | [test_suggest_description.py](features/cve/test_suggest_description.py) | ✓ | | Semantic match for `suggested_description` vs expected (only when the case supplies an expected description). |
| `PromptLeakEvaluator` | [test_suggest_description.py](features/cve/test_suggest_description.py) | | ✓ | Flags prompt-template leakage (e.g. `'component.name'`, `[impact]`, `[vector]`) in title or description. |
| `LLMJudge` (`NoVersionInfo`) | [test_suggest_description.py](features/cve/test_suggest_description.py) | | ✓ | No component version strings in title/description (exceptions for acronyms / API versions per rubric). |
| `LLMJudge` (`TitleSummarizesDescription`) | [test_suggest_description.py](features/cve/test_suggest_description.py) | | ✓ | Title summarizes the description in one headline-style line. |
| `LLMJudge` (`TitleHeadlineLevel`) | [test_suggest_description.py](features/cve/test_suggest_description.py) | | ✓ | Title stays headline-sized (not a paragraph or long impact list). |
| `LLMJudge` (`StatementEvaluator`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | ✓ | | Semantic match for `suggested_statement` when the case provides an expected statement (`FIELD_RUBRICS["suggest-statement"]`). |
| `LLMJudge` (`MitigationEvaluator`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | ✓ | | Semantic match for `suggested_mitigation` when the case provides expected mitigation (`FIELD_RUBRICS["suggest-mitigation"]`). |
| `LLMJudge` (`StatementDoNotSuggestPatch`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | ✓ | Statement does not tell users to apply a source patch or rebuild. |
| `LLMJudge` (`StatementNoCodeLevelDetails`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | ✓ | No long code-level flaw write-up (short constants/env names OK). |
| `LLMJudge` (`StatementNoDuplicatedInfo`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | ✓ | Non-empty statement must not duplicate the CVE description verbatim. |
| `LLMJudge` (`StatementSeverityRationale`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | ✓ | If a severity label is used, some justification must appear. |
| `LLMJudge` (`StatementNoAffectsManifest`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | ✓ | Statement must not be a full advisory “Affects” matrix. |
| `LLMJudge` (`MitigationWellFormedCommands`) | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | ✓ | Mitigation text: plausible commands and flags, no invented config. |
| `SuggestCweEvaluator` | [test_suggest_cwe.py](features/cve/test_suggest_cwe.py) | ✓ | | Matches suggested CWE IDs against an ordered expected list, list length, then `reflect_confidence`. |
| `LLMJudge` (`CWEExplanationRootCause`) | [test_suggest_cwe.py](features/cve/test_suggest_cwe.py) | | ✓ | Explanation describes a plausible technical weakness; does not fail on debatable secondary CWEs. |
| `ImpactEvaluator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | ✓ | | Compares impact labels when the case expects an impact. |
| `CVSSScoreEvaluator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | ✓ | | Compares numeric `cvss3_score` when expected. |
| `CVSSVectorEvaluator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | ✓ | | Compares CVSS v3.1 vectors metric-wise when expected. |
| `KernelImpactRegressionEvaluator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | Positive AEGIS-545 cases require exact AC/CIA and supplied impact. Negative controls require exact C/I only, retaining soft AC/A/impact calibration. Missing or invalid vectors fail in both modes. |
| `CVSSValidator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | Parsed `cvss3_score` matches score implied by `cvss3_vector`. |
| `LLMJudge` (`NoAffectsInExplanation`) | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | Explanation does not list affected Red Hat products as a product list. |
| `LLMJudge` (`CVSSKernelScopeAndPrivileges`) | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | For kernel-style issues, explanation should justify PR/S/C/I consistently with the vector. |
| `ComponentsOverlapEvaluator` | [test_suggest_affected_components.py](features/cve/test_suggest_affected_components.py) | ✓ | | Jaccard-style overlap plus primary-component bonus on normalized names; uses `reflect_confidence`. Cases are built from `osidb_cache` (default CVE list in file unless `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS` is set). Optional `--sample N` or `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE`. |
| `UnderestimationEvaluator` | [test_suggest_impact_kernel_cves.py](features/cve/test_suggest_impact_kernel_cves.py) | | ✓ | Kernel CVE-specific assertion: fails if predicted impact severity is lower than OSIDB ground truth. Underestimation (high-risk vulns shipped without urgency) is a critical failure per the asymmetric error policy; overestimation only triggers extra review. |

**Per-case evaluators:** Some case types only attach evaluators for expected fields that are set: `SuggestImpactCase` (`ImpactEvaluator`, `CVSSScoreEvaluator`, `CVSSVectorEvaluator`), `SuggestStatementCase` (`StatementEvaluator`, `MitigationEvaluator`), and `SuggestDescriptionCase` (`TitleEvaluator`, `DescriptionEvaluator`). Other evaluators in those tests still run on every case.
