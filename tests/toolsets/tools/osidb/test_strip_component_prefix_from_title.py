"""Unit tests for _strip_component_prefix_from_title helper."""

from aegis_ai.toolsets.tools.osidb import _strip_component_prefix_from_title


class TestStripComponentPrefixFromTitle:
    """Unit tests for _strip_component_prefix_from_title helper."""

    def test_strips_simple_component_prefix(self) -> None:
        """Title starting with 'Component: ' should strip to rest."""
        assert (
            _strip_component_prefix_from_title("kernel: buffer overflow")
            == "buffer overflow"
        )

    def test_does_not_strip_mid_sentence_colon(self) -> None:
        """Colon mid-sentence (e.g. 'Audio/Video: Playback') should not strip."""
        assert (
            _strip_component_prefix_from_title(
                "Use-after-free in the Audio/Video: Playback"
            )
            is None
        )

    def test_does_not_strip_dom_window_style(self) -> None:
        """'DOM: Window' style (colon after slash) - pattern not at start."""
        assert (
            _strip_component_prefix_from_title(
                "Use-after-free in the DOM: Window component"
            )
            is None
        )

    def test_empty_title_returns_none(self) -> None:
        assert _strip_component_prefix_from_title("") is None

    def test_no_colon_returns_none(self) -> None:
        assert _strip_component_prefix_from_title("No colon here") is None
