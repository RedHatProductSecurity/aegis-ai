"""Kernel-specific CVE impact classifier for the suggest-impact endpoint.

Uses an XGBoost model trained on kernel patch features plus CVSS score data,
with a post-prediction severity cascade ported from the al-kernel daemon.

At runtime, the classifier:
  1. Fetches raw git patches via kernel.org for the CVE's fix commits
  2. Extracts 49 binary feature flags from the patches
  3. Merges 3 CVSS score features (has_cvss, cvss_score, cvss_score_bucket)
  4. Runs the XGBoost model to predict severity (IMPORTANT/MODERATE/LOW)
  5. Applies severity cascade rules R6–R10 using CVSS vector components

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
import pickle
from pathlib import Path
from typing import Optional

import httpx
import numpy as np

from aegis_ai.kernel_classifier.cascade import SEVERITY_LABELS, apply_cascade

logger = logging.getLogger(__name__)

KERNEL_COMPONENTS = {"kernel", "kernel-rt"}

CVSS_ISSUER_PRIORITY = ["NIST", "RH", "CVEORG", "OSV", "CISA"]

SCORE_BUCKET_BOUNDARIES = [4.0, 7.0, 9.0]


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


def _select_nist_cvss3(cvss_scores: list[dict]) -> tuple[str, float]:
    """Select the best CVSS v3 vector and score from OSIDB-style cvss_scores.

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
            # Compute score from the cvss library if available, else parse
            try:
                import cvss as cvss_lib

                best_score = cvss_lib.CVSS3(vector).scores()[0]
            except Exception:
                best_score = 0.0

    return best_vector, best_score


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
        configured = os.environ.get("AEGIS_KERNEL_CLASSIFIER_DIR")
        if configured:
            return Path(configured)
        return (
            Path(__file__).resolve().parent.parent.parent
            / "aegis_ai_ml"
            / "src"
            / "classifier"
            / "kernel-cve-impact-classifier"
        )

    def _load(self):
        classifier_dir = self._resolve_classifier_dir()
        self._load_model(classifier_dir)
        self._load_feature_extractor(classifier_dir)

    def _load_model(self, classifier_dir: Path):
        model_dir = classifier_dir / "models"
        try:
            with open(model_dir / "cve_severity_model.pkl", "rb") as f:
                self.model = pickle.load(f)
            with open(model_dir / "model_metadata.json") as f:
                metadata = json.load(f)
            self.feature_columns = metadata["feature_columns"]
            self.label_mapping = {
                int(k): v for k, v in metadata["label_mapping"].items()
            }
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

    _PATCH_URL_TEMPLATES = [
        "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/patch/?id={hash}",
        "https://git.kernel.org/pub/scm/linux/kernel/git/stable/linux.git/patch/?id={hash}",
        "https://git.kernel.org/pub/scm/linux/kernel/git/next/linux-next.git/patch/?id={hash}",
    ]

    async def _fetch_patches(self, commit_hashes: list[str]) -> list[tuple[str, str]]:
        """Fetch raw patches from git.kernel.org for given commit hashes.

        Tries torvalds, stable, and linux-next trees in order.
        Returns list of (commit_hash, patch_content) tuples.
        """
        patches = []
        async with httpx.AsyncClient(timeout=30.0) as client:
            for commit_hash in commit_hashes:
                fetched = False
                for tmpl in self._PATCH_URL_TEMPLATES:
                    url = tmpl.format(hash=commit_hash)
                    try:
                        resp = await client.get(url, follow_redirects=True)
                        if resp.status_code == 200 and len(resp.text) > 100:
                            patches.append((commit_hash, resp.text))
                            logger.debug("Fetched patch for %s", commit_hash[:12])
                            fetched = True
                            break
                    except Exception:
                        continue
                if not fetched:
                    logger.warning(
                        "Could not fetch patch %s from any tree", commit_hash[:12]
                    )
        return patches

    def _extract_features(
        self, patches: list[tuple[str, str]], cve_id: str
    ) -> dict[str, bool]:
        """Extract and OR-combine features across all patches for a CVE."""
        assert self._feature_extractor is not None
        combined = {name: False for name in self._feature_extractor.feature_names}
        for commit_hash, content in patches:
            features = self._feature_extractor.extract_patch_features(
                content, patch_filename="", cve_id=cve_id
            )
            for key, val in features.items():
                if val:
                    combined[key] = True
        return combined

    def _predict(
        self,
        patch_features: dict[str, bool],
        cvss_score: float,
        cvss_vector: str,
    ) -> tuple[str, float, dict[str, float]]:
        """Run XGBoost prediction + severity cascade.

        Returns (impact_label, confidence, class_probabilities).
        """
        continuous_cols = {"cvss_score", "cvss_score_bucket"}
        feature_vector = []
        for col in self.feature_columns:
            if col == "has_cvss":
                feature_vector.append(1.0 if cvss_vector else 0.0)
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
        confidence = float(proba[raw_pred])
        probabilities = {SEVERITY_LABELS[i]: float(p) for i, p in enumerate(proba)}

        return label, confidence, probabilities

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

        # Fetch patches
        patches = await self._fetch_patches(commit_hashes)
        if not patches:
            logger.warning("No patches retrieved for %s", cve_id)
            return None

        # Extract features
        patch_features = self._extract_features(patches, cve_id)

        # Get best CVSS v3 score
        cvss_vector, cvss_score = _select_nist_cvss3(cvss_scores)

        # Predict
        impact, confidence, probabilities = self._predict(
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

        return {
            "impact": impact,
            "confidence": confidence,
            "probabilities": probabilities,
            "active_features": active,
            "cvss_vector": cvss_vector,
            "cvss_score": cvss_score,
            "patches_analyzed": len(patches),
        }
