# Evaluation suite for Aegis features

This evaluation suite is designed to systematically test and validate the features of Aegis.  It provides a collection of automated tests and benchmarks to ensure that Aegis features perform as expected, maintain reliability, and meet quality standards.  The evaluation suite covers a range of scenarios, including edge cases, to help developers identify regressions and improve the robustness of the Aegis features.  It can be used to measure or compare the suitability of the underlying LLMs as well as to evaluate proposed changes to the Aegis code itself.


## Running the evaluation suite

Optionally, you can enable an independent LLM for evaluation:
```
export AEGIS_EVALS_LLM_HOST="https://mistral-small-24b-w8a8-maas-apicast-production.apps.prod.rhoai.rh-aiservices-bu.com:443"
export AEGIS_EVALS_LLM_MODEL="mistral-small-24b-w8a8"
export AEGIS_EVALS_LLM_API_KEY="XXX"
```

To run the evaluation suite, run the following command in the top-level directory of this repository:
```
make eval
```

**How CVE IDs are chosen:** The suite uses only what's in the cache. **Component-intelligence** discovers cases by scanning `evals/osidb_cache/` for CVE JSON files that have title, description, and components. By default it uses the curated list in `evals/component_intel_cve_ids.txt` (novel ecosystems, github.com-style components); set `COMPONENT_INTEL_EVAL_CVE_IDS` to override. **CVE evals** (suggest statement/impact/CWE/description, identify PII, CVSS diff) each define a hardcoded list of `(cve_id, expected_output)` cases; at run time they filter to only those cases whose CVE ID exists in the cache (`cve_ids_in_cache()`). So the set of CVE IDs actually run is the intersection of the hardcoded list and the cache. In CI no live OSIDB is used; if a case's CVE is missing from the cache that case is skipped (or the whole test is skipped if no cases remain). To add or update cases, add the corresponding `evals/osidb_cache/CVE-*.json` files (e.g. by running evals locally with OSIDB access).

**Cache format:** Cache entries exclude the `affects` array to reduce size (affects can be very large). New cache entries are fetched with `include_affects=False`; use `python -m evals.scripts.strip_cache_affects` to strip affects from existing files. Use `python -m evals.scripts.prune_osidb_cache` to remove cache files not required by evals or the curated list.

The LLM used by Aegis during the evaluation as well as access to tools used by Aegis can be controlled by environment variables, as described in the top-level [README.md](../README.md#quick-start).  Some evaluators in the suite use an LLM to verify assertions on the output of Aegis features.  For this purpose, the suite currently uses the same LLM as Aegis itself but this may be extended in the future to use another LLM in order to make the evaluation independent of the implementation.

If you have sufficient system resources and LLM capacity, you can run the evaluation in parallel to get the evaluation results faster.  This can be achieved by invoking the following command in the top-level directory:
```
make eval-in-parallel
```

### Component intelligence eval (standalone, optional sampling)

The component intelligence eval can be run on its own. To limit Gemini (or other LLM) API usage, you can pass a sample size so that only a random subset of qualifying osidb_cache CVEs is used:

```
pytest evals/features/component/test_component_intelligence.py --sample 25
```

Alternatively set `COMPONENT_INTEL_EVAL_SAMPLE=25` (and optionally `COMPONENT_INTEL_EVAL_SAMPLE_SEED=42` for reproducibility). When `--sample` or `COMPONENT_INTEL_EVAL_SAMPLE` is used, the sample is drawn **only** from the curated list in `evals/component_intel_cve_ids.txt` (ignoring `COMPONENT_INTEL_EVAL_CVE_IDS`). Without `--sample` / `COMPONENT_INTEL_EVAL_SAMPLE`, all qualifying cache entries in the active set are used. By default the active set is the curated list; set `COMPONENT_INTEL_EVAL_CVE_IDS` to override (e.g. kernel-only or a custom list).

To run only on a fixed list of CVE IDs (e.g. Linux kernel CVEs), set `COMPONENT_INTEL_EVAL_CVE_IDS` to a comma-separated list. Example for 10 Linux kernel CVEs (expected component `kernel`; useful to check if the model consistently returns e.g. "Linux kernel" in `components`):

```
COMPONENT_INTEL_EVAL_CVE_IDS=CVE-2022-48701,CVE-2022-49669,CVE-2022-49885,CVE-2022-50087,CVE-2022-50235,CVE-2022-50333,CVE-2022-50361,CVE-2022-50390,CVE-2022-50421,CVE-2022-50439 pytest evals/features/component/test_component_intelligence.py -v
```

## Results

If an assertion fails during the evaluation, the `make` command exits with a non-zero exit code and the failed assertions are printed for each test-case.  For example:
```
[...]
FAILED evals/features/cve/test_suggest_cwe.py::test_eval_suggest_cwe - AssertionError: Unsatisfied assertion(s):
suggest-cwe-for-CVE-2025-23395: SuggestCweEvaluator(): score below threshold: -0.95 < 0.1
```

In any case, a summary is printed for each test-case, where you can see:
- Case ID (a unique identifier of a test-case)
- Inputs (usually a CVE ID)
- Outputs (usually a structured object including an explanation, confidence, etc.)
- Scores provided by each evaluator
    - useful responses get a score in the range 0..1 (where 1 denotes the ideal response)
    - potentially dangerous responses get negative scores
- Assertions (a check-mark/cross for each)

For each Aegis feature, the average score and average assertion success rate is provided in the last row of the corresponding table.


## Tunables

| Name | Location | Description | Default |
| ---- | -------- | ----------- | ------- |
| `EXPLANATION_MIN_LEN` | [common.py](features/common.py) | minimal acceptable length of an explanation (where applicable) | 80 |
| `MIN_SCORE_THRESHOLD` | [common.py](features/common.py) | minimal acceptable score returned by an evaluator | 0.1 |
| `LOW_CONFIDENCE_PENALTY_DIVISOR` | [common.py](features/common.py) | penalize models providing correct results but low confidence (the difference between score and confidence is divided by this number and subtracted from the final score) | 4.0 |
| `COMPONENT_INTEL_EVAL_SAMPLE` | component eval | when set, use a random sample of N CVEs from component_intel_cve_ids.txt (reduces API usage; ignores COMPONENT_INTEL_EVAL_CVE_IDS) | (all qualifying) |
| `COMPONENT_INTEL_EVAL_SAMPLE_SEED` | component eval | random seed for sampling (reproducible runs) | 42 |
| `COMPONENT_INTEL_EVAL_CVE_IDS` | component eval | comma-separated CVE IDs to restrict cases to; overrides curated list | `evals/component_intel_cve_ids.txt` |
| `COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS` | component eval | cap description length (truncate with " […]"); 0 = no cap (reduces input tokens) | 0 |
| `COMPONENT_INTEL_EVAL_SKIP_DESCRIPTION_LONGER_THAN` | component eval | skip cases whose description is longer than N chars; 0 = don't skip | 0 |
| `AEGIS_LLM_INPUT_TOKENS_WARN_THR` | [features/__init__.py](../src/aegis_ai/features/__init__.py) | log a warning when LLM input tokens exceed this (component intel and other features) | 65536 |


## Too many input tokens (component intelligence)

The component intelligence eval often triggers a **"too many input tokens processed by LLM"** warning. The total input includes the initial prompt (title + description) **and** all tool outputs (Wikipedia, GitHub, kernel_cve_tool, CISA KEV, etc.) from the multi-turn run, so token count can exceed 100k even when the description is moderate.

**Ways to mitigate (besides truncating description):**

1. **Raise the warning threshold** – Set `AEGIS_LLM_INPUT_TOKENS_WARN_THR` to a higher value (e.g. `128000` or `200000`) so the warning is logged only for very large runs. Does not reduce tokens; only reduces log noise if your model supports large context.

2. **Cap description length in the eval** – Set `COMPONENT_INTEL_EVAL_MAX_DESCRIPTION_CHARS` (e.g. `2000` or `5000`). The eval will truncate the description when building cases and append " […]". Shorter context reduces initial prompt size.

3. **Skip very long descriptions** – Set `COMPONENT_INTEL_EVAL_SKIP_DESCRIPTION_LONGER_THAN` (e.g. `10000`). The eval will skip any CVE whose description is longer than that, so the heaviest cases are not run. Useful to avoid the worst token hogs.

4. **Truncate description (comment_zero)** – Same as (2); cap the text passed as context in the eval.

5. **Run with fewer/sampled cases** – Use `--sample N` or `COMPONENT_INTEL_EVAL_SAMPLE=N` so you run fewer cases; you’ll see the warning less often and still get a signal.

The main driver of very high token counts is **tool output** (e.g. full Wikipedia article for "Linux kernel"). Reducing description length in the eval helps the initial prompt; it does not limit how much the agent fetches via tools. Limiting or truncating tool responses would require changes in the agent or tools (e.g. an "eval mode" with smaller tool payloads).


## Common evaluators

These evaluators are used for **all** Aegis features:

| Name | Location | Score | Assertion | Description |
| ---- | -------- | ----- | --------- | ----------- |
| `FeatureMetricsEvaluator` | [common.py](features/common.py) | &check; | | summarization (multiplication) of all metrics provided by Aegis itself, including a check for `EXPLANATION_MIN_LEN` |
| `ToolsUsedEvaluator` | [common.py](features/common.py) | | &check; | check whether `osidb_tool` was used by the Aegis agent |


## Feature evaluators

| Name | Location | Score | Assertion | Description |
| ---- | -------- | ----- | --------- | ----------- |
| `CVSSDiffEvaluator` | [test_cvss_diff.py](features/cve/test_cvss_diff.py) | | &check; | check that explanation is provided if and only if CVSS scores differ |
| custom `LLMJudge` | [test_cvss_diff.py](features/cve/test_cvss_diff.py) | | &check; | "Unless the explanation field is empty, it elaborates on the reason why Red Hat assigned a different CVSS score." |
| `IdentifyPIIEvaluator` | [test_identify_pii.py](features/cve/test_identify_pii.py) | | &check; | check the `contains_PII` flag in the answer |
| custom `LLMJudge` | [test_identify_pii.py](features/cve/test_identify_pii.py) | | &check; | "If PII is found, the explanation contains a bulleted list." |
| `OriginalTitleEvaluator` | [test_suggest_description.py](features/cve/test_suggest_description.py) | | &check; | check whether original title is propagated by the model |
| `PromptLeakEvaluator` | [test_suggest_description.py](features/cve/test_suggest_description.py) | | &check; | check that text from the prompt template does not leak into the response |
| custom `LLMJudge` | [test_suggest_description.py](features/cve/test_suggest_description.py) | | &check; | "suggested_title and suggested_description do not contain any versioning info" |
| custom `LLMJudge` | [test_suggest_description.py](features/cve/test_suggest_description.py) | | &check; | "suggested_title briefly summarizes what is described in suggested_description" |
| custom `LLMJudge` | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | &check; | "The statement does not suggest to apply a patch or rebuild the software." |
| custom `LLMJudge` | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | &check; | "The statement does not describe the code change that was used to eliminate the flaw." |
| custom `LLMJudge` | [test_suggest_statement.py](features/cve/test_suggest_statement.py) | | &check; | "The statement does not duplicate the flaw description." |
| `SuggestCweEvaluator` | [test_suggest_cwe.py](features/cve/test_suggest_cwe.py) | &check; | | compare the provided list of CWEs with the expected one while taking length of the list and confidence into account |
| `SuggestImpactEvaluator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | &check; | | compare the provided impact and CVSS3 score with the expected values while taking the confidence into account |
| custom `LLMJudge` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | &check; | "explanation does not mention which Red Hat products are affected" |
| `ComponentsOverlapEvaluator` | [test_component_intelligence.py](features/component/test_component_intelligence.py) | &check; | | Jaccard + primary-component match between suggested and expected components (from osidb_cache) |
