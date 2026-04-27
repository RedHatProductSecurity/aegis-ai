"""Kernel-specific CVE impact classifier for the suggest-impact endpoint.

Uses an XGBoost model trained on kernel patch features plus CVSS score data,
with a post-prediction severity cascade ported from the al-kernel daemon.

At runtime, the classifier:
  1. Fetches raw git patches via kernel.org for the CVE's fix commits
  2. Extracts 49 binary feature flags from the patches
  3. Fetches commit HTML pages and extracts supplemental features
  4. Merges 3 CVSS score features (has_cvss, cvss_score, cvss_score_bucket)
  5. Runs the XGBoost model to predict severity (IMPORTANT/MODERATE/LOW)
  6. Applies severity cascade rules R6–R10 using CVSS vector components

Configuration (environment variables):
  AEGIS_KERNEL_CLASSIFIER_DIR  — path to the classifier directory containing
      models/ and cve_feature_extraction.py.  Defaults to the co-located
      aegis_ai_ml source tree for development.
  AEGIS_USE_KERNEL_CLASSIFIER  — set to "true" to enable (default: false)
"""

import importlib.util
import json
import logging
import os
from pathlib import Path
from typing import Optional

import httpx
import numpy as np

from aegis_ai.kernel_classifier.cascade import (
    SEVERITY_LABELS,
    apply_cascade,
    apply_flag_interactions,
)
from aegis_ai.kernel_classifier.html import extract_html_features

logger = logging.getLogger(__name__)

KERNEL_COMPONENTS = {"kernel", "kernel-rt", "linux kernel"}

CVSS_ISSUER_PRIORITY = ["NIST", "RH", "CVEORG", "OSV", "CISA"]

SCORE_BUCKET_BOUNDARIES = [4.0, 7.0, 9.0]

# URLs tried in order to fetch raw git patches for kernel commits.
# git.kernel.org's CGI only resolves commits on the default branch of each
# tree, so stable-backport hashes often fail there.  The GitHub fallback
# resolves any commit reachable from any branch in gregkh/linux (the
# stable mirror that al-kernel also uses as its primary source).
PATCH_URL_TEMPLATES = [
    "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={hash}",
    "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={hash}",
    "https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/patch/?id={hash}",
    # Stable-backport commits live on per-version branches (linux-X.Y.y) that
    # git.kernel.org's CGI cannot resolve.  gregkh/linux is the GitHub mirror
    # of the stable tree and resolves commits across all branches — the same
    # source al-kernel uses.  This is the last-resort fallback.
    "https://github.com/gregkh/linux/commit/{hash}.patch",
]

_GREGKH_FALLBACK_TEMPLATE = PATCH_URL_TEMPLATES[-1]

# URLs tried in order to fetch rendered commit HTML pages (for supplemental feature extraction).
# These may need updating if upstream hosting changes.
HTML_COMMIT_URL_TEMPLATES = [
    "https://github.com/gregkh/linux/commit/{hash}",
    "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/commit/?id={hash}",
]


def is_kernel_component(components: list) -> bool:
    """Check if any component in the list indicates a Linux kernel flaw."""
    return bool(
        {c.lower().strip() for c in components if isinstance(c, str)}
        & KERNEL_COMPONENTS
    )


def _score_to_bucket(score: float) -> int:
    for i, boundary in enumerate(SCORE_BUCKET_BOUNDARIES):
        if score < boundary:
            return i
    return len(SCORE_BUCKET_BOUNDARIES)


def _select_best_external_cvss3(cvss_scores: list[dict]) -> tuple[str, float]:
    """Select the best CVSS v3 vector and score from OSIDB-style cvss_scores.

    Checks issuers in priority order: NIST > RH > CVEORG > OSV > CISA.
    Returns (vector_string, score) or ("", 0.0) when unavailable.
    """
    best_vector = ""
    best_score = 0.0
    best_priority = len(CVSS_ISSUER_PRIORITY) + 1

    for entry in cvss_scores:
        vector = entry.get("vector", "")
        issuer = entry.get("issuer", "")
        if not vector or "CVSS:3" not in vector:
            continue
        try:
            priority = CVSS_ISSUER_PRIORITY.index(issuer)
        except ValueError:
            priority = len(CVSS_ISSUER_PRIORITY)
        if priority < best_priority:
            best_priority = priority
            best_vector = vector
            try:
                import cvss as cvss_lib

                best_score = cvss_lib.CVSS3(vector).scores()[0]
            except ImportError:
                raw = entry.get("score")
                if isinstance(raw, (int, float)) and raw > 0:
                    best_score = float(raw)
                    logger.warning(
                        "cvss library unavailable; using raw score %.1f from %s entry",
                        best_score,
                        issuer,
                    )
                else:
                    best_score = 0.0
                    logger.warning(
                        "cvss library unavailable and no raw score for %s entry; "
                        "CVSS-based cascade rules disabled",
                        issuer,
                    )
            except Exception:
                raw = entry.get("score")
                best_score = (
                    float(raw) if isinstance(raw, (int, float)) and raw > 0 else 0.0
                )

    return best_vector, best_score


_PATCH_SIZE_LIMIT = 1_000_000


def _collect_patches(patches: list[tuple[str, str]]) -> list[str]:
    """Return patch content strings, dropping any that exceed the size limit.

    Large non-fix commits exist (driver imports, treewide refactors) but
    CVE fix commits are targeted bug fixes that are well under 1 MB.
    The guard protects against accidental inclusion of a prohibitively
    large patch (e.g. the ~200 MB initial kernel commit).
    """
    out: list[str] = []
    for commit_hash, content in patches:
        if len(content) > _PATCH_SIZE_LIMIT:
            logger.warning(
                "Dropping oversized patch %s (%d chars)", commit_hash[:12], len(content)
            )
            continue
        out.append(content)
    return out


class KernelImpactClassifier:
    """Singleton classifier for kernel CVE impact assessment.

    Loads the XGBoost model and feature extraction code from the
    kernel-cve-impact-classifier directory (configurable via
    AEGIS_KERNEL_CLASSIFIER_DIR).
    """

    _instance: Optional["KernelImpactClassifier"] = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._initialized = False
        return cls._instance

    def __init__(self):
        if self._initialized:
            return
        self._initialized = True
        self.model = None
        self.feature_columns: list[str] = []
        self.label_mapping: dict[int, str] = {}
        self._feature_extractor = None
        self._load()

    @staticmethod
    def _resolve_classifier_dir() -> Path:
        configured = os.getenv("AEGIS_KERNEL_CLASSIFIER_DIR")
        if configured:
            clf_dir = Path(configured)
        else:
            clf_dir = (
                Path(__file__).resolve().parent.parent.parent
                / "aegis_ai_ml"
                / "src"
                / "classifier"
                / "kernel-cve-impact-classifier"
            )
        if not clf_dir.is_dir():
            raise FileNotFoundError(
                f"Kernel classifier directory not found: {clf_dir}. "
                "Set AEGIS_KERNEL_CLASSIFIER_DIR or install aegis_ai_ml."
            )
        model_json = clf_dir / "models" / "cve_severity_model.json"
        model_ubj = clf_dir / "models" / "cve_severity_model.ubj"
        if not model_json.is_file() and not model_ubj.is_file():
            raise FileNotFoundError(
                f"Kernel classifier model not found in {clf_dir / 'models'}. "
                "Expected cve_severity_model.json or .ubj"
            )
        return clf_dir

    def _load(self):
        classifier_dir = self._resolve_classifier_dir()
        self._load_model(classifier_dir)
        self._load_feature_extractor(classifier_dir)

    def _load_model(self, classifier_dir: Path):
        model_dir = classifier_dir / "models"
        try:
            import xgboost as xgb

            model = xgb.XGBClassifier()
            json_path = model_dir / "cve_severity_model.json"
            ubj_path = model_dir / "cve_severity_model.ubj"
            if json_path.is_file():
                model.load_model(str(json_path))
            elif ubj_path.is_file():
                model.load_model(str(ubj_path))
            else:
                raise FileNotFoundError(
                    f"No XGBoost native model found in {model_dir}. "
                    "Expected cve_severity_model.json or .ubj — "
                    "run xgboost_train.py to produce the model."
                )
            with open(model_dir / "model_metadata.json") as f:
                metadata = json.load(f)
            feature_columns = metadata["feature_columns"]
            label_mapping = {int(k): v for k, v in metadata["label_mapping"].items()}
            expected = getattr(model, "n_features_in_", None)
            if expected is not None and expected != len(feature_columns):
                raise ValueError(
                    f"Model expects {expected} features but metadata "
                    f"lists {len(feature_columns)}"
                )
            self.model = model
            self.feature_columns = feature_columns
            self.label_mapping = label_mapping
            logger.info(
                "Loaded kernel classifier model (%d features)",
                len(self.feature_columns),
            )
        except Exception as e:
            logger.error("Failed to load kernel classifier model: %s", e)

    def _load_feature_extractor(self, classifier_dir: Path):
        fe_path = classifier_dir / "cve_feature_extraction.py"
        if not fe_path.exists():
            logger.warning("Kernel feature extraction module not found: %s", fe_path)
            return
        try:
            spec = importlib.util.spec_from_file_location(
                "kernel_cve_feature_extraction", str(fe_path)
            )
            if spec is None or spec.loader is None:
                logger.warning("Could not create module spec for %s", fe_path)
                return
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self._feature_extractor = module.CVEFeatureExtractor(data_dir="/tmp")
            logger.info("Loaded kernel feature extractor from %s", fe_path)
        except Exception as e:
            logger.error("Failed to load kernel feature extractor: %s", e)

    @property
    def available(self) -> bool:
        return self.model is not None and self._feature_extractor is not None

    async def _fetch_patches(self, commit_hashes: list[str]) -> list[tuple[str, str]]:
        """Fetch raw patches from git.kernel.org for given commit hashes.

        Tries torvalds, stable, linux-next, and the gregkh/linux GitHub
        fallback in order.
        Returns list of (commit_hash, patch_content) tuples.
        """
        patches = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for commit_hash in commit_hashes:
                fetched = False
                used_template = None
                for tmpl in PATCH_URL_TEMPLATES:
                    url = tmpl.format(hash=commit_hash)
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        if resp.status_code == 200 and len(resp.text) > 100:
                            patches.append((commit_hash, resp.text))
                            logger.debug("Fetched patch for %s", commit_hash[:12])
                            fetched = True
                            used_template = tmpl
                            break
                    except Exception:
                        continue
                if not fetched:
                    logger.warning(
                        "Could not fetch patch %s from any source "
                        "(including gregkh/linux fallback for resolving "
                        "backport patches) — commit may not exist in "
                        "any known tree",
                        commit_hash[:12],
                    )
                elif used_template == _GREGKH_FALLBACK_TEMPLATE:
                    logger.debug(
                        "Patch %s resolved via gregkh/linux fallback "
                        "(stable-backport commit)",
                        commit_hash[:12],
                    )
        return patches

    async def _fetch_commit_html(
        self, commit_hashes: list[str]
    ) -> list[tuple[str, str]]:
        """Fetch rendered commit HTML pages for given commit hashes.

        The al-kernel daemon analyses GitHub commit pages which contain crash
        reports, call stacks, and rendered diffs that raw git patches lack.
        We replicate that by fetching from GitHub (primary) with a
        git.kernel.org fallback.

        Returns list of (commit_hash, html_content) tuples.
        """
        pages: list[tuple[str, str]] = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for commit_hash in commit_hashes:
                fetched = False
                for tmpl in HTML_COMMIT_URL_TEMPLATES:
                    url = tmpl.format(hash=commit_hash)
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        if resp.status_code == 200 and len(resp.text) > 200:
                            pages.append((commit_hash, resp.text))
                            logger.debug("Fetched commit HTML for %s", commit_hash[:12])
                            fetched = True
                            break
                    except Exception:
                        continue
                if not fetched:
                    logger.warning(
                        "Could not fetch commit HTML for %s", commit_hash[:12]
                    )
        return pages

    @staticmethod
    def _apply_flag_cascade(features: dict[str, bool]) -> None:
        """Re-apply derived-flag rules after cross-patch OR-merge and HTML supplement.

        Delegates to ``apply_flag_interactions`` in ``cascade.py`` so that
        training and runtime share the same canonical rule ordering.
        """
        apply_flag_interactions(features)

    def _extract_features(
        self, patches: list[tuple[str, str]], cve_id: str
    ) -> dict[str, bool]:
        """Extract and OR-combine features across all patches for a CVE."""
        assert self._feature_extractor is not None
        combined = {name: False for name in self._feature_extractor.feature_names}
        agg_total_lines = 0
        agg_src_lines = 0
        for commit_hash, content in patches:
            features = self._feature_extractor.extract_patch_features(
                content, patch_filename="", cve_id=cve_id
            )
            agg_total_lines += features.pop("_total_lines", 0)
            agg_src_lines += features.pop("_src_lines", 0)
            for key, val in features.items():
                if val:
                    combined[key] = True

        combined["simplefix"] = agg_total_lines < 21 and agg_src_lines < 15
        if combined.get("hardware") or combined.get("uaf"):
            combined["simplefix"] = False
        return combined

    def _predict(
        self,
        patch_features: dict[str, bool],
        cvss_score: float,
        cvss_vector: str,
    ) -> tuple[str, float, dict[str, float], int]:
        """Run XGBoost prediction + severity cascade.

        Returns (impact_label, confidence, class_probabilities, raw_pred_index).
        """
        continuous_cols = {"cvss_score", "cvss_score_bucket"}
        feature_vector = []
        for col in self.feature_columns:
            if col == "has_cvss":
                feature_vector.append(1.0 if (cvss_vector and cvss_score > 0) else 0.0)
            elif col == "cvss_score":
                feature_vector.append(float(cvss_score))
            elif col == "cvss_score_bucket":
                feature_vector.append(
                    float(_score_to_bucket(cvss_score)) if cvss_score > 0 else 0.0
                )
            elif col in continuous_cols:
                feature_vector.append(0.0)
            else:
                feature_vector.append(float(int(patch_features.get(col, False))))

        assert self.model is not None
        X = np.array(feature_vector).reshape(1, -1)
        raw_pred = int(self.model.predict(X)[0])
        proba = self.model.predict_proba(X)[0]

        # Build active flags set for the cascade
        active_flags = {k for k, v in patch_features.items() if v}

        adjusted = apply_cascade(raw_pred, cvss_score, cvss_vector, active_flags)

        label = SEVERITY_LABELS.get(adjusted, "MODERATE")
        confidence = float(proba[adjusted])
        probabilities = {SEVERITY_LABELS[i]: float(p) for i, p in enumerate(proba)}

        if adjusted != raw_pred:
            logger.info(
                "Cascade changed prediction %d -> %d (raw_confidence=%.3f, adjusted_confidence=%.3f)",
                raw_pred,
                adjusted,
                float(proba[raw_pred]),
                confidence,
            )

        return label, confidence, probabilities, raw_pred

    async def classify(
        self,
        cve_id: str,
        commit_hashes: list[str],
        cvss_scores: list[dict],
    ) -> Optional[dict]:
        """Run the full kernel classification pipeline.

        Args:
            cve_id: the CVE identifier
            commit_hashes: git commit hashes (40-char hex) fixing this CVE
            cvss_scores: OSIDB-style list of {issuer, vector} dicts

        Returns:
            dict with keys: impact, confidence, probabilities, active_features,
            cvss_vector, cvss_score — or None on failure.
        """
        if not self.available:
            logger.warning("Kernel classifier not available, skipping")
            return None

        if not commit_hashes:
            logger.info("No commit hashes for %s, skipping kernel classifier", cve_id)
            return None

        patches = await self._fetch_patches(commit_hashes)
        if not patches:
            logger.warning("No patches retrieved for %s", cve_id)
            return None

        patch_features = self._extract_features(patches, cve_id)

        html_supplemented_flags: list[str] = []
        html_pages = await self._fetch_commit_html(commit_hashes)
        if html_pages:
            html_features = extract_html_features(html_pages)
            for flag, val in html_features.items():
                if val and not patch_features.get(flag):
                    patch_features[flag] = True
                    html_supplemented_flags.append(flag)
            logger.info(
                "HTML supplement for %s: %d pages, %d new flags (%s)",
                cve_id,
                len(html_pages),
                len(html_supplemented_flags),
                ", ".join(html_supplemented_flags) or "none",
            )
        else:
            logger.warning("No commit HTML retrieved for %s", cve_id)

        self._apply_flag_cascade(patch_features)

        cvss_vector, cvss_score = _select_best_external_cvss3(cvss_scores)

        impact, confidence, probabilities, raw_pred = self._predict(
            patch_features, cvss_score, cvss_vector
        )

        assert self._feature_extractor is not None
        active = [
            k for k in self._feature_extractor.feature_names if patch_features.get(k)
        ]

        logger.info(
            "Kernel classifier for %s: %s (confidence=%.2f, patches=%d, features=%d)",
            cve_id,
            impact,
            confidence,
            len(patches),
            len(active),
        )

        raw_label = SEVERITY_LABELS.get(raw_pred, "MODERATE")
        result: dict = {
            "impact": impact,
            "confidence": confidence,
            "probabilities": probabilities,
            "raw_prediction": raw_label,
            "raw_confidence": probabilities.get(raw_label, 0.0),
            "active_features": active,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score,
            "patches_analyzed": len(patches),
            "patch_summaries": _collect_patches(patches),
        }
        if html_supplemented_flags:
            result["html_supplemented_flags"] = html_supplemented_flags
        return result
