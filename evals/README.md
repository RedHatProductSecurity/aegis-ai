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

Optional **independent LLM for evaluators** (LLM judges and scoring judges), while Aegis still uses your normal app settings:

```bash
export AEGIS_EVALS_LLM_HOST="https://…"
export AEGIS_EVALS_LLM_MODEL="…"
export AEGIS_EVALS_LLM_API_KEY="…"
```

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
| `CVSSValidator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | Parsed `cvss3_score` matches score implied by `cvss3_vector`. |
| `LLMJudge` (`NoAffectsInExplanation`) | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | Explanation does not list affected Red Hat products as a product list. |
| `LLMJudge` (`CVSSKernelScopeAndPrivileges`) | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | ✓ | For kernel-style issues, explanation should justify PR/S/C/I consistently with the vector. |
| `ComponentsOverlapEvaluator` | [test_suggest_affected_components.py](features/cve/test_suggest_affected_components.py) | ✓ | | Jaccard-style overlap plus primary-component bonus on normalized names; uses `reflect_confidence`. Cases are built from `osidb_cache` (default CVE list in file unless `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_CVE_IDS` is set). Optional `--sample N` or `AEGIS_EVALS_SUGGEST_AFFECTED_COMPONENTS_SAMPLE`. |

**Per-case evaluators:** Some case types only attach evaluators for expected fields that are set: `SuggestImpactCase` (`ImpactEvaluator`, `CVSSScoreEvaluator`, `CVSSVectorEvaluator`), `SuggestStatementCase` (`StatementEvaluator`, `MitigationEvaluator`), and `SuggestDescriptionCase` (`TitleEvaluator`, `DescriptionEvaluator`). Other evaluators in those tests still run on every case.
