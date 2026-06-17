# Kernel Classifier Sample Set And Retraining

This is the maintainer runbook for curating the kernel classifier sample set
and retraining the XGBoost model.

---

## Regular Retraining Workflow

Follow these steps in order from the repository root.

### 1. Install dependencies

```bash
make fetch-deps
```

### 2. Authenticate and configure

```bash
kinit
export AEGIS_OSIDB_SERVER_URL=URL
```

### 3. Generate training inputs from OSIDB

```bash
uv run python src/aegis_ai_ml/src/osidb_retrieve.py
```

This fetches kernel flaws from OSIDB, normalizes them, auto-resolves
patch IDs via `linux-security-vulns`, and writes the git-tracked
sample-set files:

- `src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/data/train_kernel_cves.json`
- `src/aegis_ai_ml/src/classifier/kernel-cve-impact-classifier/data/test_kernel_cves.json`

The fetch filters server-side by OSIDB component (`kernel`,
`Linux kernel`) and deduplicates across component queries by UUID.
Only flaws in the `DONE` workflow state are fetched by default.

If the initial fetch does not fill every severity class, the script
retries up to 3 times, targeting only the under-represented classes.

The data selection uses **ratio-based capping** anchored to the minority
class (IMPORTANT). All IMPORTANT CVEs are kept uncapped; MODERATE and
LOW are each capped at `MAJORITY_RATIO` × the IMPORTANT count (default
3×). With ~112 IMPORTANT CVEs in OSIDB, this produces ~112 IMPORTANT /
~336 MODERATE / ~336 LOW ≈ 784 total. This reflects the real-world
severity distribution where IMPORTANT is ~3% of kernel CVEs while
preserving enough majority-class examples for the model to learn
decision boundaries. The cap keeps the newest CVEs by `created_date`
and runs before train/test splitting.

CRITICAL severity is excluded from the default fetch because too few
kernel CVEs carry that rating to form a useful training class; their
characteristics overlap with IMPORTANT in practice.

Review the generation report for duplicate CVEs, unsupported severities,
unresolved patch lists, train/test split balance, and CVEs flagged for
manual review before continuing.

### 4. Retrain the model

```bash
make retrain-kernel
```

### 5. Verify the retrain

After `make retrain-kernel`, check at least:

1. Scraper warnings — `skipped_no_strategy`, CVEs with no commits or HTML.
2. Split output from `split_datasets_for_train_test.py` — train/test
   overlap is a **fatal error** (the splitter raises `SystemExit` and
   the pipeline aborts; fix the overlap in the JSON files before
   re-running). CVEs absent from `cve_dataset.csv` are warnings only.
3. SMOTE output — class balancing looks sane.
4. `models/model_metadata.json` — feature count, training dataset path,
   class weights or tuned params.
5. `test-results/test_summary.json` — accuracy, underestimations,
   per-class recall.
6. `test-results/predictions.txt` — whether misses cluster around a
   specific pattern.
7. `models/feature_importance.csv` — whether the learned signal still
   looks plausible.

If the retrain passes only because there was no prior
`test-results/test_summary.json`, commit the new summary with the model
update so the next retrain has a regression baseline.

### 6. Commit

Review the diff on the sample-set JSON files, model artifacts, and test
results, then commit.

## Refreshing Specific CVEs

To refresh only a specific set of CVEs by ID, pass a file to `--cve-ids`.
The file may be either:

- `.txt` with one CVE ID per line; blank lines and `#` comments are ignored
- `.json` containing a JSON array of CVE ID strings

```bash
# Merge the fetched CVEs into the existing train/test JSON (typical usage)
uv run python src/aegis_ai_ml/src/osidb_retrieve.py --cve-ids cves.json --merge

# Replace train/test JSON with only the specified CVEs
uv run python src/aegis_ai_ml/src/osidb_retrieve.py --cve-ids cves.txt
```

**Without `--merge`**, the output files are **replaced entirely** with
the fetched CVEs — all existing CVEs not in the file are lost. The
script logs warnings for each CVE that will be removed, and refuses to
write if the result would be empty while the existing files are not.
This mode is rarely what you want with `--cve-ids`; prefer `--merge`.

**With `--merge`**, the fetched CVEs are folded into the existing
`train_kernel_cves.json` and `test_kernel_cves.json`, updating any CVE
that already exists and appending new ones. The combined result is
trimmed to stay within `--max-total` (default 720) by evicting the
oldest CVEs, stratified by severity, preferring to drop from the train
split so the test set stays stable.

Both modes write to the git-tracked sample-set files; review the diff
and commit the result.

## Hyperparameter Tuning

```bash
make retrain-kernel RETUNE=1
```

This runs the same 7-step pipeline as `make retrain-kernel`, but injects
`tune_hyperparameters.py` immediately before `xgboost_train.py`. The
tuner performs a grid search over XGBoost hyperparameters and class
weights using **3-fold stratified cross-validation**. SMOTE is applied
inside each fold so synthetic samples never leak into fold validation
sets. Each fold uses early stopping (20 rounds) with a 10% eval set
carved from the SMOTE'd training portion.

The tuner selects configs that meet **per-class recall floors**
(IMPORTANT ≥ 80%, MODERATE ≥ 50%, LOW ≥ 50%) first, then maximises
accuracy, breaking ties by fewest underestimations. Class weights
express the asymmetric misclassification cost — underestimating an
IMPORTANT CVE is worse than overestimating a LOW one. The grid includes
a neutral baseline (1.0) so CV can determine whether SMOTE alone is
sufficient without additional weighting.

The winning configuration is written to `models/tuned_params.json`
(creating or overwriting the file). `xgboost_train.py` checks for that
file at startup and uses it in place of its hardcoded defaults, so a
tuned-params file produced by `RETUNE=1` also affects every subsequent
retrain that does _not_ use `RETUNE=1`. The model artifacts, metadata,
and test results are overwritten as part of the normal pipeline — that
is not specific to `RETUNE=1`.

Only retune hyperparameters when the current classifier gate fails,
underestimations regress, or the sample set / feature space changed
enough that the existing model parameters are no longer a good fit. Do
not retune for routine sample refreshes that already pass
`test_cve_model.py`, because unnecessary tuning makes results harder to
compare across retrains.

---

## Reference

### `osidb_retrieve.py` CLI Flags

| Flag | Default | Description |
|------|---------|-------------|
| `--input-flaws-json` | — | Read flaws from a local JSON export instead of OSIDB |
| `--cve-ids` | — | Fetch specific CVEs by ID from a file (`.txt` or `.json`) |
| `--merge` | off | Merge fetched CVEs into existing output files instead of replacing them |
| `--train-output` | `data/train_kernel_cves.json` | Output path for training records |
| `--test-output` | `data/test_kernel_cves.json` | Output path for test records |
| `--report-output` | `data/generation_report.json` | Output path for the generation report |
| `--raw-output-json` | — | Write the raw flaw array (before normalization) to a JSON file |
| `--raw-output-dir` | — | Write one raw flaw JSON file per CVE to a directory |
| `--raw-only` | off | Fetch/load flaws and write raw output only; skip train/test generation |
| `--dry-run` | off | Generate and validate in memory, write only the report; skip train/test output |
| `--max-total` | `720` | Maximum combined train+test CVE count |
| `--max-per-impact` | `ceil(max_total / n_impacts)` | Maximum flaws to fetch per impact from OSIDB |
| `--impacts` | `IMPORTANT MODERATE LOW` | Impact values to fetch |
| `--states` | `DONE` | OSIDB workflow states to fetch |
| `--test-ratio` | `0.25` | Fraction of records placed in the test split |
| `--seed` | `42` | Deterministic seed for stratified splitting |
| `--osidb-url` | env `AEGIS_OSIDB_SERVER_URL` | OSIDB server URL |
| `--owners` | — | Comma-separated owner emails; only fetch flaws owned by these users |
| `--vulns-repo` | `data/linux_security_vulns` | Path to the `linux-security-vulns` checkout |
| `--skip-patch-resolution` | off | Skip automatic patch resolution from `linux-security-vulns` |

### Acceptance Gates

`test_cve_model.py` is the classifier gate. A retrain is not complete
until it passes.

It currently enforces:

- **per-class recall floors** (configurable via environment variables):
  - IMPORTANT ≥ 80% (`CVE_MODEL_MIN_RECALL_IMPORTANT`)
  - MODERATE ≥ 50% (`CVE_MODEL_MIN_RECALL_MODERATE`)
  - LOW ≥ 50% (`CVE_MODEL_MIN_RECALL_LOW`)
- maximum IMPORTANT underestimations via `CVE_MODEL_MAX_IMPORTANT_UNDERESTIMATIONS` (default `6`)
- maximum MODERATE underestimations via `CVE_MODEL_MAX_MODERATE_UNDERESTIMATIONS` (default `8`)
- no regression in IMPORTANT or MODERATE underestimation counts versus
  the previous `test-results/test_summary.json`, when one exists

The IMPORTANT floor is deliberately set below the tuner's CV target
because the held-out test set is small (~28 IMPORTANT CVEs); each miss
swings recall by ~3.6 pp, so a tighter floor would cause noisy failures.

Underestimation is the critical failure mode. Overestimation is tolerated
if it buys safety.

### Feature Set

The model uses **52 features**: 49 patch flags + 3 CVSS score features.

**Patch flags (49)** — binary indicators extracted from the commit diff
and HTML (e.g. `kernel_panic`, `netfilter`, `race`, `virt`). These are
produced by `cve_feature_extraction.py`.

**CVSS score features (3):**

| Feature | Type | Description |
|---------|------|-------------|
| `has_cvss` | binary | Whether a CVSS v3 score exists for the CVE |
| `cvss_score` | continuous | Raw CVSS v3 score (0.0–10.0) |
| `cvss_score_bucket` | ordinal | 0=low (<4.0), 1=medium (<7.0), 2=high (<9.0), 3=critical (≥9.0) |

**Excluded — decomposed CVSS vector components (22 one-hot features):**
`cvss_cwe_features.py` produces 22 one-hot features from the CVSS v3.1
vector string: 13 attack-surface components (AV, AC, PR, UI, S) and 9
impact-triad components (C, I, A). Both groups are excluded:

- *Attack-surface components* (AV, AC, PR, UI, S) are near-constant for
  kernel CVEs: 94% are AV:L (local), 90% are AC:L/PR:L, 100% are
  UI:N/S:U. Near-constant features add noise without discriminating
  signal.
- *Impact-triad components* (C, I, A — 9 one-hot features for
  Confidentiality, Integrity, Availability at None/Low/High) have real
  variance but were tested in isolation and hurt IMPORTANT recall:
  adding them dropped IMPORTANT recall from 87.5% to 78.1% and
  introduced 3 new IMPORTANT underestimations. The aggregate CVSS score
  already captures the severity signal without diluting it across
  correlated one-hot columns.

**Excluded — CWE category features** (`cwe_*`, `has_cwe`): kernel CWE
assignments are inconsistent and the categories are too coarse to
distinguish severity. These also hurt IMPORTANT recall in ablation
testing.

CVSS features are produced by `fetch_cvss_cwe.py` (step 3), which
fetches CVSS vectors from the cache (`data/cvss_cwe_cache.json`) and
merges the encoded columns into `cve_dataset.csv`. The encoding logic
lives in `cvss_cwe_features.py`.

#### Ablation History

This section records experiments that tested alternative feature sets so
future maintainers don't repeat them. Each entry notes the conditions
under which the test was run — results may change if the sample set,
pipeline, or model architecture changes significantly.

**Round 1 — original CVSS feature ablation (2026-03-30, commit
`9c052b77`).** Tested 8 feature combinations when CVSS features were
first added. The pipeline at the time used a single train/test split
(no cross-validation), no SMOTE isolation (SMOTE applied once before
splitting), an IMPORTANT-heavy dataset, and a 292-CVE held-out test set.

| Combination tried | Result |
|---|---|
| 49 patch flags only (baseline) | IMPORTANT recall 37.5%, accuracy 52.4% |
| + cvss_score, cvss_score_bucket, has_cvss | **IMPORTANT recall 43.8%, accuracy 54.1% — selected** |
| + decomposed CVSS vector (all 22 one-hot) | Hurt IMPORTANT recall vs score-only |
| + CWE category features (5 categories + has_cwe) | Hurt IMPORTANT recall vs score-only |
| + decomposed CVSS + CWE combined | Hurt IMPORTANT recall vs score-only |
| Various subsets of the above | None beat the 3-feature score-only set |

Conclusion: only the aggregate score features improved all metrics.
Decomposed CVSS components and CWE categories were excluded. Attack-
surface components (AV, AC, PR, UI, S) are additionally near-constant
for kernel CVEs (94% AV:L, 90% AC:L/PR:L, 100% UI:N/S:U) — there is
no variance to learn from.

**Round 2 — impact-triad retest under improved pipeline (2026-06-17).**
After the pipeline gained 3-fold stratified CV, SMOTE isolation (SMOTE
inside each fold), early stopping, per-class recall gates, and a
rebalanced dataset (ratio-based capping), the Round 1 findings were
potentially stale. Retested with just the 9 impact-triad features
(C/I/A one-hot), excluding the attack-surface components that have no
variance. Hypothesis: the triad would help distinguish availability-only
crashes (C:N/I:N/A:H, typically LOW/MODERATE) from bugs with
confidentiality or integrity impact (typically IMPORTANT).

| Metric | Score-only (3 features) | + Impact-triad (12 features) |
|---|---|---|
| Accuracy | 0.712 | 0.716 |
| IMPORTANT recall | **87.5%** | **78.1%** (fails 80% gate) |
| IMPORTANT underestimations | 4 | 6 (+3 new) |
| Total underestimations | 7 | 10 |
| Overestimations | 61 | 57 |

Conditions: 952 CVEs (136 IMP / 408 MOD / 408 LOW), 3-fold stratified
CV with SMOTE isolation, `RETUNE=1`, 236-CVE held-out test set (32 IMP /
102 MOD / 102 LOW).

**Why it failed — structural class overlap at the pattern level.**

The hypothesis assumed the C/I/A triad would cleanly partition severity:
availability-only (N/N/H) = LOW/MODERATE, confidentiality or integrity
impact = IMPORTANT. In practice the triad values are heavily confounded
with class labels in a way that hurts the minority class:

| C/I/A pattern | IMPORTANT | MODERATE | LOW | Problem |
|---|---|---|---|---|
| H/H/H | 108 (82%) | 45 | 13 | Majority IMPORTANT, but 35% are not — model must still rely on other features |
| H/N/H | 12 | **42** | 3 | 3.5× more MODERATE than IMPORTANT |
| N/N/H | 6 | **232** | **374** | 100× more non-IMPORTANT — signal is overwhelming |
| H/L/H | 3 | **12** | 0 | 4× more MODERATE |

82% of IMPORTANT CVEs have the H/H/H pattern, which does separate well.
But the remaining 18% (23 CVEs) share their triad pattern with a large
MODERATE majority — and **have identical CVSS scores**. For the H/N/H
pattern specifically, all 12 IMPORTANT CVEs score 7.1, and 36 of the 42
MODERATE CVEs also score 7.1. The triad + score features are identical
across classes; only patch flags distinguish them.

Without the triad features, the model's tree splits use patch flags and
the aggregate CVSS score, which carries the right gradient (IMPORTANT
averages 7.7, MODERATE averages 6.3). Adding triad features gives the
tree an early, high-gain split on `cvss_c_H` or `cvss_i_N` that routes
these borderline IMPORTANT CVEs into a MODERATE-dominated leaf. The
model over-indexes on the triad pattern because it explains more variance
in the training data (due to the class-imbalanced pattern distribution)
even though it destroys recall for the cases that matter most.

The three new misses illustrate this directly:
- CVE-2024-53155 and CVE-2022-49738: C:H/I:N/A:H, score 7.1 — routed
  with 42 MODERATEs that have the same triad + score
- CVE-2022-49278: C:N/I:H/A:H, score 7.1 — rare pattern (n=2), but
  missing C:H pushed it toward the MODERATE boundary

**Takeaway:** the triad features are not noisy — they have real variance
— but that variance is *confounded* with severity in the wrong
direction for minority-class recall. The aggregate score compresses the
triad into a single dimension that preserves the severity gradient
without exposing the tree to class-imbalanced pattern splits.

### Pipeline Steps

`make retrain-kernel` runs these steps in order:

1. `cve_data_scraper.py`
2. `cve_feature_extraction.py`
3. `fetch_cvss_cwe.py`
4. `split_datasets_for_train_test.py`
5. `cve_smote_balancer.py`
6. `xgboost_train.py`
7. `test_cve_model.py`

Each step reads only files produced by earlier steps in the same run
(or the curated JSON inputs). Intermediate CSVs from a previous run
must not affect the current pipeline — `cve_feature_extraction.py`
filters stale checkpoint rows against the current ground truth,
`fetch_cvss_cwe.py` reads `cve_dataset.csv` (step 2) rather than the
split CSVs (step 4), and `tune_hyperparameters.py` derives its feature
list from the freshly generated training data rather than from
`model_metadata.json` (step 6).

`osidb_retrieve.py` is the canonical entrypoint for generating
`train_kernel_cves.json` and `test_kernel_cves.json` from raw flaw data.
It runs before the Makefile pipeline and can fetch live flaws from OSIDB
(filtered server-side by component and impact), fetch individual CVEs by
ID, or read a local flaw export. It auto-resolves patch lists via
`linux-security-vulns`, retries to fill under-represented severity
classes, caps each class to a balanced target, and emits a generation
report.

### Data Flow

The curated JSON inputs define sample membership and labels. They are
inputs to the split step, not outputs from it.

Each curated record carries `patch_ids`, which represents the patch
evidence associated with the CVE. In the normal flow, those patch lists
are auto-resolved by `osidb_retrieve.py`; maintainers only need to
supply them manually when the resolver cannot find the right commits or
when a specific set of patches needs to be pinned.

The pipeline flow is:

1. `cve_feature_extraction.py` builds `data/cve_dataset.csv`
2. `split_datasets_for_train_test.py` reads `data/cve_dataset.csv`,
   `data/train_kernel_cves.json`, and `data/test_kernel_cves.json`
3. That step writes `data/cve_training_dataset.csv` and
   `data/cve_testing_dataset.csv`
4. `cve_smote_balancer.py` reads `data/cve_training_dataset.csv` and
   writes `data/balanced-training-dataset-through-smote.csv`
5. `xgboost_train.py` trains from
   `data/balanced-training-dataset-through-smote.csv`

Use `train_kernel_cves.json` for samples the model is allowed to learn
from. Use `test_kernel_cves.json` for held-out samples used to measure
classifier quality after retraining. Do not put the same CVE in both
files.

Do not hand-edit generated CSVs or model artifacts.

### What The Scraper Expects

`cve_data_scraper.py` currently supports two ways to reach patch content:

1. `direct_patch` — uses explicit `patch_ids` directly.
2. `json_references_filtered` — falls back to CVE JSON references in
   `linux-security-vulns` when no explicit patch list is present.

If neither path works, the scraper records the CVE as
`skipped_no_strategy`. Treat that as a curation problem to fix in the
sample set.

The scraper also updates or clones `linux_kernel_repo` and
`linux_security_vulns`, and fetches both raw patches and rendered commit
HTML so training sees the same HTML-derived signal as runtime inference.

### Curation Rules

When adding or updating a sample:

1. Choose high-quality CVEs analyzed by a subject matter expert (SME).
2. Confirm the Red Hat severity label you want the model to learn.
3. Decide whether the CVE belongs in train or test.
4. Run `osidb_retrieve.py` to auto-populate `patch_ids` from raw flaws
   and `linux-security-vulns`.
5. Otherwise make sure the CVE is resolvable through the local
   `linux-security-vulns` checkout so patch IDs can be auto-populated.
6. Keep enough metadata for future maintainers to understand why the
   sample is present and how old it is.

The current process is manual. Good candidates usually come from newly
labeled kernel CVEs, repeated classifier misses, or cases that exercise
newly added feature-extraction behavior.

The working policy is curated and reviewable, not mechanically
ever-growing: prefer recent, well-labeled samples, keep older ones only
when they still represent behavior the model must retain, and replace
outdated cases when analyst practice has changed.

### Generated Artifacts

#### Intermediate datasets

- `data/CVE-*/`
- `data/cve_dataset.csv`
- `data/cve_training_dataset.csv`
- `data/cve_testing_dataset.csv`
- `data/balanced-training-dataset-through-smote.csv`
- `data/cvss_cwe_cache.json`

#### Model artifacts

- `models/cve_severity_model.json`
- `models/model_metadata.json`
- `models/feature_importance.csv`
- optionally `models/tuned_params.json`

#### Review artifacts

- `test-results/test_results.png`
- `test-results/predictions.txt`
- `test-results/test_summary.json`

### When To Revisit The Sample Set

Revisit the curated JSON files when:

- a kernel eval exposes a repeated blind spot
- feature-extraction logic changes and the old set no longer covers the
  new signal
- OSIDB labeling practice shifts enough that older cases are misleading
- retraining starts producing `skipped_no_strategy` or missing-dataset
  warnings
- the held-out test set stops representing the cases you care about

If the sample set changes, rerun the full retrain pipeline. Do not patch
the derived CSVs or model files by hand.

### Related Docs

- `evals/README.md` covers the separate kernel `suggest-impact` eval
  corpus and cache-preparation flow
