"""Tests for component feature data models (sync, no asyncio)."""

import pytest

from aegis_ai.features.component.data_models import ComponentFeatureInput


def test_component_feature_input_component_name_only():
    """ComponentFeatureInput accepts component_name only."""
    inp = ComponentFeatureInput(component_name="curl")
    assert inp.component_name == "curl"
    assert inp.title is None
    assert inp.description is None


def test_component_feature_input_title_and_description():
    """ComponentFeatureInput accepts title and description (no component_name)."""
    inp = ComponentFeatureInput(
        title="OpenSSL buffer overflow",
        description="A flaw in OpenSSL allows RCE.",
    )
    assert inp.component_name is None
    assert inp.title == "OpenSSL buffer overflow"
    assert inp.description == "A flaw in OpenSSL allows RCE."


def test_component_feature_input_rejects_both_modes():
    """ComponentFeatureInput rejects component_name together with title/description."""
    with pytest.raises(ValueError, match="not both"):
        ComponentFeatureInput(
            component_name="curl",
            title="Some CVE",
            description="Some description.",
        )


def test_component_feature_input_rejects_neither():
    """ComponentFeatureInput rejects missing component_name and missing title+description."""
    with pytest.raises(ValueError, match="either"):
        ComponentFeatureInput(component_name=None, title=None, description=None)
