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

The LLM used by Aegis during the evaluation as well as access to tools used by Aegis can be controlled by environment variables, as described in the top-level [README.md](../README.md#quick-start).  Some evaluators in the suite use an LLM to verify assertions on the output of Aegis features.  For this purpose, the suite currently uses the same LLM as Aegis itself but this may be extended in the future to use another LLM in order to make the evaluation independent of the implementation.

If you have sufficient system resources and LLM capacity, you can run the evaluation in parallel to get the evaluation results faster.  This can be achieved by invoking the following command in the top-level directory:
```
make eval-in-parallel
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
| `LOW_CONFIDENCE_PENALTY_DIVISOR` | [test_suggest_cwe.py](features/cve/test_suggest_cwe.py) | penalize models providing correct results but low confidence (the difference between score and confidence is divided by this number and subtracted from the final score) | 4.0 |


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
| `OriginalTitleEvaluator` | [test_rewrite_description.py](features/cve/test_rewrite_description.py) | | &check; | check whether original title is propagated by the model |
| `PromptLeakEvaluator` | [test_rewrite_description.py](features/cve/test_rewrite_description.py) | | &check; | check that text from the prompt template does not leak into the response |
| custom `LLMJudge` | [test_rewrite_description.py](features/cve/test_rewrite_description.py) | | &check; | "rewritten_title and rewritten_description do not contain any versioning info" |
| custom `LLMJudge` | [test_rewrite_description.py](features/cve/test_rewrite_description.py) | | &check; | "rewritten_title briefly summarizes what is described in rewritten_description" |
| custom `LLMJudge` | [test_rewrite_statement.py](features/cve/test_rewrite_statement.py) | | &check; | "The statement does not suggest to apply a patch or rebuild the software." |
| custom `LLMJudge` | [test_rewrite_statement.py](features/cve/test_rewrite_statement.py) | | &check; | "The statement does not describe the code change that was used to eliminate the flaw." |
| custom `LLMJudge` | [test_rewrite_statement.py](features/cve/test_rewrite_statement.py) | | &check; | "The statement does not duplicate the flaw description." |
| `SuggestCweEvaluator` | [test_suggest_cwe.py](features/cve/test_suggest_cwe.py) | &check; | | compare the provided list of CWEs with the expected one while taking length of the list and confidence into account |
| `SuggestImpactEvaluator` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | &check; | | compare the provided impact and CVSS3 score with the expected values while taking the confidence into account |
| custom `LLMJudge` | [test_suggest_impact.py](features/cve/test_suggest_impact.py) | | &check; | "explanation does not mention which Red Hat products are affected" |
