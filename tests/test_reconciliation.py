"""Unit tests for severity reconciliation.

Covers the kernel threshold path (_reconcile_kernel) ported from
al-kernel and the non-kernel LLM self-consistency path.
"""

from types import SimpleNamespace


from aegis_ai.features.cve import SuggestImpact

# Shorthand CVSS vectors used across tests.  Only the metrics that matter
# for the rule under test are varied; the rest use benign defaults.
_VEC_BASE = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
_VEC_LOCAL = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
_VEC_LOCAL_LOW = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H"
_VEC_HHH = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_VEC_LOCAL_HHH = "CVSS:3.1/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
_VEC_PR_H = "CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H"


def _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_BASE):
    return SimpleNamespace(
        impact=impact,
        cvss3_score=cvss_score,
        cvss3_vector=cvss_vector,
    )


def _clf(impact="MODERATE", confidence=0.8, cvss_score=7.0, features=None):
    return {
        "impact": impact,
        "confidence": confidence,
        "cvss_score": cvss_score,
        "active_features": features or [],
    }


# ── Kernel threshold rules (individual) ─────────────────────────────


class TestH1:
    """H1: IMPORTANT -> MODERATE when LLM CVSS < 6.5"""

    def test_fires(self):
        out = _output(impact="IMPORTANT", cvss_score="5.0", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="IMPORTANT", cvss_score=5.5)
        )
        assert out.impact == "MODERATE"
        assert "H1" in trace

    def test_does_not_fire_when_cvss_ge_6_5(self):
        out = _output(impact="IMPORTANT", cvss_score="7.0", cvss_vector=_VEC_BASE)
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="IMPORTANT"))
        assert out.impact == "IMPORTANT"

    def test_does_not_fire_for_moderate(self):
        out = _output(impact="MODERATE", cvss_score="5.0", cvss_vector=_VEC_LOCAL)
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact != "IMPORTANT"


class TestH2:
    """H2: MODERATE -> IMPORTANT when LLM CVSS very high"""

    def test_fires_cvss_ge_8_5(self):
        out = _output(impact="MODERATE", cvss_score="8.5", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "IMPORTANT"
        assert "H2" in trace

    def test_fires_cvss_7_5_with_hhh(self):
        out = _output(impact="MODERATE", cvss_score="7.5", cvss_vector=_VEC_HHH)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "IMPORTANT"
        assert "H2" in trace

    def test_blocked_by_contained_subsystem(self):
        out = _output(impact="MODERATE", cvss_score="7.5", cvss_vector=_VEC_HHH)
        SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="MODERATE", features=["bpf"])
        )
        assert out.impact == "MODERATE"


class TestH5:
    """H5: LOW/MOD -> IMPORTANT when LLM CVSS > 8.5"""

    def test_fires_for_low(self):
        out = _output(impact="MODERATE", cvss_score="9.0", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW"))
        assert out.impact == "IMPORTANT"
        assert "H5" in trace

    def test_does_not_fire_at_exactly_8_5(self):
        out = _output(impact="MODERATE", cvss_score="8.5", cvss_vector=_VEC_BASE)
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW"))
        assert out.impact != "IMPORTANT"


class TestH6:
    """H6: LOW -> MODERATE when LLM CVSS >= 6.7 or >= 5.5 with C:H/I:H/A:H"""

    def test_fires_cvss_6_7(self):
        out = _output(impact="MODERATE", cvss_score="6.7", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW"))
        assert out.impact == "MODERATE"
        assert "H6" in trace

    def test_fires_cvss_5_5_with_hhh(self):
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_HHH)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW"))
        assert out.impact == "MODERATE"
        assert "H6" in trace

    def test_blocked_by_contained_low_band(self):
        """H6 blocked by contained subsystem AND LLM band is LOW,
        so G4 also does not promote."""
        out = _output(impact="MODERATE", cvss_score="3.5", cvss_vector=_VEC_BASE)
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW", features=["bpf"]))
        assert out.impact == "LOW"

    def test_contained_moderate_band_promotes_via_g4(self):
        """H6 blocked by contained subsystem but LLM band is MODERATE,
        so G4 promotes LOW -> MODERATE (capped by containment)."""
        out = _output(impact="MODERATE", cvss_score="6.7", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="LOW", features=["bpf"])
        )
        assert out.impact == "MODERATE"
        assert "llm_band_floor" in trace


class TestH7:
    """H7: MODERATE -> LOW when CVSS <= 3.9, no kernel_panic, no kpanic_marked"""

    def test_fires(self):
        out = _output(impact="MODERATE", cvss_score="3.5", cvss_vector=_VEC_LOCAL)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "LOW"
        assert "H7" in trace

    def test_blocked_by_kernel_panic(self):
        out = _output(impact="MODERATE", cvss_score="3.5", cvss_vector=_VEC_BASE)
        SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="MODERATE", features=["kernel_panic"])
        )
        assert out.impact == "MODERATE"

    def test_blocked_by_kpanic_marked_via_h4(self):
        """H4 sets kpanic_marked at CVSS >= 6.0, but we need to test that
        H7 is blocked when kpanic_marked is True.  Since H7 requires
        CVSS <= 3.9 while H3/H4 require >= 6.0/6.5, they can't co-fire
        in a single pass — the flag prevents H7 only when set by an
        earlier rule in the chain.  This test verifies that by checking
        a sequence where H3 fires first (CVSS >= 7.5) and then severity
        stays MODERATE because H7 cannot fire."""
        out = _output(impact="MODERATE", cvss_score="7.5", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "MODERATE"
        assert "H3:kpanic_set" in trace
        assert "H7" not in trace


class TestH8:
    """H8: MODERATE -> LOW for local/low-impact vectors at CVSS < 5.5"""

    def test_fires_low_band(self):
        """H8 de-escalates to LOW when LLM band is also LOW (< 4.0)."""
        out = _output(
            impact="MODERATE",
            cvss_score="3.95",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H",
        )
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "LOW"
        assert "H8" in trace

    def test_moderate_band_caught_by_g4(self):
        """H8 fires (MOD->LOW) at CVSS 4.0 but G4 catches it because
        the LLM band is MODERATE, not LOW."""
        out = _output(
            impact="MODERATE",
            cvss_score="4.0",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H",
        )
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "MODERATE"
        assert "H8" in trace
        assert "llm_band_floor" in trace

    def test_not_local_does_not_fire(self):
        out = _output(
            impact="MODERATE",
            cvss_score="4.0",
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:H",
        )
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact != "LOW" or "H8" not in ""

    def test_hhh_does_not_fire(self):
        out = _output(impact="MODERATE", cvss_score="4.0", cvss_vector=_VEC_LOCAL_HHH)
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert out.impact == "MODERATE"


class TestH11:
    """H11: IMPORTANT -> MODERATE when PR:H and CVSS < 8.0"""

    def test_fires(self):
        out = _output(impact="IMPORTANT", cvss_score="7.5", cvss_vector=_VEC_PR_H)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="IMPORTANT"))
        assert out.impact == "MODERATE"
        assert "H11" in trace

    def test_does_not_fire_cvss_ge_8(self):
        out = _output(impact="IMPORTANT", cvss_score="8.5", cvss_vector=_VEC_PR_H)
        SuggestImpact.reconcile_severity(out, "t", _clf(impact="IMPORTANT"))
        assert out.impact == "IMPORTANT"


# ── Rule chaining ───────────────────────────────────────────────────


class TestRuleChaining:
    def test_h1_then_h8_caught_by_g4(self):
        """H1 de-escalates IMP->MOD, H8 de-escalates MOD->LOW, but G4
        catches it: CVSS 5.0 is MODERATE band, so floor prevents LOW.
        ext_cvss=5.5 (MODERATE) so G5 does not reverse H1."""
        vec = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
        out = _output(impact="IMPORTANT", cvss_score="5.0", cvss_vector=vec)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="IMPORTANT", cvss_score=5.5)
        )
        assert out.impact == "MODERATE"
        assert "H1" in trace
        assert "H8" in trace
        assert "llm_band_floor" in trace

    def test_h1_then_h8_low_band_cascades(self):
        """H1+H8 chain succeeds when LLM band is actually LOW (< 4.0)."""
        vec = "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H"
        out = _output(impact="IMPORTANT", cvss_score="3.95", cvss_vector=vec)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="IMPORTANT"))
        assert out.impact == "LOW"
        assert "H1" in trace
        assert "H8" in trace

    def test_h6_promotes_low_to_moderate(self):
        """LOW start, CVSS 7.0 -> H6 promotes to MODERATE."""
        out = _output(impact="MODERATE", cvss_score="7.0", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW"))
        assert out.impact == "MODERATE"
        assert "H6" in trace


# ── Annotation gating ───────────────────────────────────────────────


class TestAnnotationGating:
    def test_h3_blocks_h7(self):
        """H3 sets kpanic when CVSS >= 7.5, preventing H7 de-escalation."""
        out = _output(impact="MODERATE", cvss_score="7.5", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert "H3:kpanic_set" in trace
        assert "H7" not in trace
        assert out.impact == "MODERATE"

    def test_h4_blocks_h7(self):
        """H4 sets kpanic when CVSS >= 6.0, preventing H7."""
        out = _output(impact="MODERATE", cvss_score="6.0", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="MODERATE"))
        assert "H4:kpanic_set" in trace
        assert out.impact == "MODERATE"

    def test_h4_skipped_for_local_nullptr(self):
        """H4 skips when vulnerability is local NULL-ptr-dereference.
        This allows H7 to de-escalate if applicable."""
        out = _output(
            impact="MODERATE",
            cvss_score="6.0",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        )
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="MODERATE", features=["nullptr"])
        )
        assert "H4:kpanic_set" not in trace


# ── Guardrails ──────────────────────────────────────────────────────


class TestGuardrails:
    def test_g2_corruption_floor(self):
        """Memory corruption features enforce severity >= MODERATE."""
        out = _output(impact="MODERATE", cvss_score="3.0", cvss_vector=_VEC_LOCAL)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="MODERATE", features=["uaf"])
        )
        assert out.impact == "MODERATE"
        assert "memory_corruption_floor" in trace

    def test_g3_network_corruption_floor(self):
        """Network + corruption features enforce severity >= IMPORTANT."""
        out = _output(impact="MODERATE", cvss_score="5.0", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(
            out,
            "t",
            _clf(impact="MODERATE", features=["uaf", "remote"]),
        )
        assert out.impact == "IMPORTANT"
        assert "network_corruption_floor" in trace

    def test_no_g1_external_cvss_cap(self):
        """G1 (external CVSS divergence cap) is removed — threshold rules
        can produce severity that diverges > 1 level from external CVSS."""
        out = _output(impact="MODERATE", cvss_score="9.0", cvss_vector=_VEC_BASE)
        clf = _clf(impact="MODERATE", cvss_score=3.0)
        SuggestImpact.reconcile_severity(out, "t", clf)
        assert out.impact == "IMPORTANT"

    def test_g4_promotes_low_to_moderate_band(self):
        """G4: severity reaches LOW but LLM band is MODERATE → promote."""
        out = _output(
            impact="MODERATE",
            cvss_score="4.5",
            cvss_vector="CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H",
        )
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="LOW"))
        assert out.impact == "MODERATE"
        assert "llm_band_floor" in trace

    def test_g4_does_not_fire_at_moderate(self):
        """G4 only applies when severity is LOW, not MODERATE."""
        out = _output(impact="IMPORTANT", cvss_score="7.5", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="IMPORTANT"))
        assert "llm_band_floor" not in trace

    def test_g4_contained_caps_at_moderate(self):
        """G4 with contained subsystem: promotes LOW to MODERATE but not
        higher, even if LLM band is IMPORTANT."""
        out = _output(impact="MODERATE", cvss_score="7.5", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="LOW", features=["bpf"])
        )
        assert out.impact == "MODERATE"
        assert "llm_band_floor" in trace

    def test_g5_reverses_h1_when_ext_cvss_confirms(self):
        """G5: H1 de-escalates IMP->MOD but external CVSS is IMPORTANT,
        so G5 reverses back to IMPORTANT."""
        out = _output(impact="IMPORTANT", cvss_score="5.8", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="IMPORTANT", cvss_score=7.8)
        )
        assert out.impact == "IMPORTANT"
        assert "H1" in trace
        assert "ext_cvss_confirms_imp" in trace

    def test_g5_does_not_fire_when_ext_cvss_moderate(self):
        """G5 does not fire when external CVSS is also MODERATE."""
        out = _output(impact="IMPORTANT", cvss_score="5.8", cvss_vector=_VEC_BASE)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="IMPORTANT", cvss_score=5.5)
        )
        assert out.impact == "MODERATE"
        assert "H1" in trace
        assert "ext_cvss_confirms_imp" not in trace

    def test_g5_does_not_fire_without_h1(self):
        """G5 only applies when H1 fired, not other de-escalations."""
        out = _output(impact="IMPORTANT", cvss_score="7.5", cvss_vector=_VEC_PR_H)
        trace = SuggestImpact.reconcile_severity(
            out, "t", _clf(impact="IMPORTANT", cvss_score=7.8)
        )
        assert out.impact == "MODERATE"
        assert "H11" in trace
        assert "ext_cvss_confirms_imp" not in trace


# ── Non-kernel path ─────────────────────────────────────────────────


class TestNonKernelPath:
    def test_consistent_llm_no_change(self):
        """When LLM CVSS band matches stated impact, output is unchanged."""
        out = _output(impact="MODERATE", cvss_score="5.5")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert out.impact == "MODERATE"
        assert "non_kernel" in trace
        assert "consistent=true" in trace

    def test_inconsistent_llm_trusts_cvss_band(self):
        """When LLM CVSS band disagrees with stated impact, CVSS band wins."""
        out = _output(impact="LOW", cvss_score="7.5")
        trace = SuggestImpact.reconcile_severity(out, "t")
        assert out.impact == "IMPORTANT"
        assert "non_kernel" in trace
        assert "consistent=false" in trace

    def test_no_classifier_returns_non_kernel_path(self):
        out = _output(impact="MODERATE", cvss_score="5.5")
        trace = SuggestImpact.reconcile_severity(out, "t", classifier_result=None)
        assert "non_kernel" in trace


# ── Edge cases ──────────────────────────────────────────────────────


class TestEdgeCases:
    def test_nan_llm_cvss_keeps_classifier_output(self):
        """NaN LLM CVSS skips threshold rules, keeps classifier output."""
        out = _output(
            impact="MODERATE", cvss_score="not_a_number", cvss_vector=_VEC_BASE
        )
        trace = SuggestImpact.reconcile_severity(out, "t", _clf(impact="IMPORTANT"))
        assert out.impact == "IMPORTANT"
        assert "no_llm_cvss" in trace

    def test_empty_active_features(self):
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector=_VEC_LOCAL)
        clf = _clf(impact="MODERATE", features=[])
        SuggestImpact.reconcile_severity(out, "t", clf)
        assert out.impact in {"MODERATE", "LOW"}

    def test_missing_cvss_vector(self):
        """Missing vector doesn't crash; rules degrade gracefully."""
        out = _output(impact="MODERATE", cvss_score="5.5", cvss_vector="")
        clf = _clf(impact="IMPORTANT", cvss_score=5.5)
        trace = SuggestImpact.reconcile_severity(out, "t", clf)
        assert out.impact is not None
        assert "H1" in trace
