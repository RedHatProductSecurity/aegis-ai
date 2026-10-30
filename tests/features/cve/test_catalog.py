import json
from unittest.mock import MagicMock, patch

import pytest

from aegis_ai.features.cve.catalog import (
    _PROMISCUOUS_GLOB_LIMIT,
    _fetch_bomq_components,
    apply_bomq_aliases,
    catalog_alias_candidates,
    reconcile_ecosystems,
    reconcile_ecosystems_by_component,
)


def _json_response(payload: dict) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.read.return_value = json.dumps(payload).encode()
    mock_resp.__enter__ = lambda s: s
    mock_resp.__exit__ = MagicMock(return_value=False)
    return mock_resp


def _component_page(
    rows: list[dict], *, total: int | None = None, offset: int = 0
) -> dict:
    return {
        "data": rows,
        "count": len(rows),
        "total": total if total is not None else len(rows),
        "limit": 100,
        "offset": offset,
    }


class TestFetchBomqComponents:
    def test_query_includes_every_component_type(self):
        from urllib.parse import parse_qs, urlparse

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _json_response(
                _component_page([{"name": "hex", "type": "otp", "build_count": 2}])
            )
            rows = _fetch_bomq_components("https://bomq.example", "hex")

        url = mock_urlopen.call_args.args[0]
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        assert parsed.path == "/api/v0alpha/components"
        assert params["exclude_types"] == ['""']
        assert params["group_by"] == ["name"]
        assert params["strict"] == ["true"]
        assert params["exclude_dev"] == ["true"]
        assert params["name"] == ["hex"]
        assert rows == [{"name": "hex", "type": "otp", "build_count": 2}]

    def test_paginates_until_total(self):
        from urllib.parse import parse_qs, urlparse

        pages = [
            _component_page(
                [{"name": "hex", "type": "otp", "build_count": 1}],
                total=2,
            ),
            _component_page(
                [{"name": "hex", "type": "generic", "build_count": 1}],
                total=2,
                offset=1,
            ),
        ]
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = [_json_response(page) for page in pages]
            rows = _fetch_bomq_components("https://bomq.example", "hex")

        assert mock_urlopen.call_count == 2
        assert [row["type"] for row in rows] == ["otp", "generic"]
        offsets = [
            parse_qs(urlparse(call.args[0]).query)["offset"]
            for call in mock_urlopen.call_args_list
        ]
        assert offsets == [["0"], ["1"]]

    def test_glob_stops_once_distinct_names_exceed_the_limit(self):
        page = _component_page(
            [
                {"name": f"pkg{i}", "type": "rpm", "build_count": 1}
                for i in range(_PROMISCUOUS_GLOB_LIMIT + 1)
            ],
            total=200,
        )
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = [
                _json_response(page),
                _json_response(
                    _component_page(
                        [{"name": "later", "type": "rpm", "build_count": 1}],
                        total=200,
                        offset=_PROMISCUOUS_GLOB_LIMIT + 1,
                    )
                ),
            ]
            rows = _fetch_bomq_components("https://bomq.example", "libsoup*")

        assert mock_urlopen.call_count == 1
        assert len({row["name"].lower() for row in rows}) == _PROMISCUOUS_GLOB_LIMIT + 1

    def test_glob_keeps_paging_while_distinct_names_stay_within_the_limit(self):
        # Twenty-five names, each with case variants, fill a server page
        # without crossing the discard threshold. The next page can still
        # add a name that should be fetched.
        page_rows = []
        for i in range(_PROMISCUOUS_GLOB_LIMIT):
            folded = f"widget{i}"
            for variant in (folded, folded.upper(), folded.capitalize(), f"WiDgEt{i}"):
                page_rows.append({"name": variant, "type": "rpm", "build_count": 1})
        pages = [
            _component_page(page_rows, total=101),
            _component_page(
                [{"name": "libsoup3", "type": "rpm", "build_count": 1}],
                total=101,
                offset=100,
            ),
        ]
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = [_json_response(page) for page in pages]
            rows = _fetch_bomq_components("https://bomq.example", "libsoup*")

        assert mock_urlopen.call_count == 2
        assert "libsoup3" in {row["name"] for row in rows}
        assert len({row["name"].lower() for row in rows}) == _PROMISCUOUS_GLOB_LIMIT + 1

    def test_exact_lookup_paginates_past_the_glob_limit(self):
        pages = [
            _component_page(
                [
                    {"name": f"pkg{i}", "type": "rpm", "build_count": 1}
                    for i in range(_PROMISCUOUS_GLOB_LIMIT + 1)
                ],
                total=_PROMISCUOUS_GLOB_LIMIT + 2,
            ),
            _component_page(
                [{"name": "later", "type": "rpm", "build_count": 1}],
                total=_PROMISCUOUS_GLOB_LIMIT + 2,
                offset=_PROMISCUOUS_GLOB_LIMIT + 1,
            ),
        ]
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.side_effect = [_json_response(page) for page in pages]
            rows = _fetch_bomq_components("https://bomq.example", "pkg")

        assert mock_urlopen.call_count == 2
        assert rows[-1]["name"] == "later"

    def test_queries_the_given_base(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_urlopen.return_value = _json_response(_component_page([]))
            _fetch_bomq_components("https://bomq.example", "curl")
            _fetch_bomq_components("https://bomq-community.example", "curl")

        hosts = [call.args[0] for call in mock_urlopen.call_args_list]
        assert hosts[0].startswith("https://bomq.example/api/v0alpha/components?")
        assert hosts[1].startswith(
            "https://bomq-community.example/api/v0alpha/components?"
        )

    def test_url_error_is_an_empty_catalog(self):
        import urllib.error

        with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("down")):
            assert _fetch_bomq_components("https://bomq.example", "hex") == []


class TestCatalogAliases:
    def test_eval_pairs_and_rejections(self):
        cases = [
            ("libvips", [("exact", [{"name": "vips", "type": "generic"}])], ["vips"]),
            (
                "libsoup",
                [
                    (
                        "glob",
                        [
                            {"name": "libsoup", "type": "rpm"},
                            {"name": "libsoup3", "type": "rpm"},
                        ],
                    )
                ],
                ["libsoup3"],
            ),
            ("libgd", [("exact", [{"name": "gd", "type": "generic"}])], ["gd"]),
            (
                "gdk-pixbuf",
                [("glob", [{"name": "gdk-pixbuf2", "type": "rpm"}])],
                ["gdk-pixbuf2"],
            ),
            (
                "qtbase",
                [
                    (
                        "glob",
                        [
                            {"name": "qt5-qtbase", "type": "rpm"},
                            {"name": "qt6-qtbase", "type": "rpm"},
                        ],
                    )
                ],
                ["qt5-qtbase", "qt6-qtbase"],
            ),
            ("tftp-hpa", [("exact", [{"name": "tftp", "type": "rpm"}])], ["tftp"]),
            (
                "bind9",
                [("exact", [{"name": "bind", "type": "generic"}])],
                ["bind"],
            ),
            (
                "rabbitmq",
                [("glob", [{"name": "rabbitmq-server", "type": "rpm"}])],
                ["rabbitmq-server"],
            ),
            (
                "openssl",
                [
                    (
                        "glob",
                        [
                            {"name": "openssl3", "type": "generic"},
                            {"name": "openssl-pkcs11", "type": "rpm"},
                            {"name": "jbcs-httpd24-openssl", "type": "rpm"},
                            {"name": "mingw-openssl", "type": "rpm"},
                        ],
                    )
                ],
                ["openssl3"],
            ),
            (
                "keycloak-services",
                [
                    (
                        "glob",
                        [{"name": "org.keycloak/keycloak-services", "type": "maven"}],
                    )
                ],
                ["org.keycloak/keycloak-services"],
            ),
        ]
        for suggested, queries, expected in cases:
            assert catalog_alias_candidates(suggested, queries) == expected

    def test_promiscuous_glob_keeps_exact_hits(self):
        wide = [{"name": f"pkg{i}", "type": "rpm"} for i in range(26)]
        wide.append({"name": "libsoup3", "type": "rpm"})
        # libvips2 aliases libvips. It must stay out because the glob is too wide.
        wide.append({"name": "libvips2", "type": "rpm"})
        queries = [
            ("exact", [{"name": "vips", "type": "generic"}]),
            ("glob", wide),
        ]
        found = catalog_alias_candidates("libvips", queries)
        assert found == ["vips"]
        assert "libvips2" not in found


class TestReconcileEcosystems:
    def test_generic_plus_otp_becomes_otp(self):
        assert reconcile_ecosystems(["generic"], ["otp", "generic"]) == ["otp"]

    def test_pypi_stays_pypi(self):
        assert reconcile_ecosystems(["pypi"], ["otp", "pypi"]) == ["pypi"]

    def test_mixed_model_keeps_specific_and_replaces_fallback(self):
        assert reconcile_ecosystems(["npm", "generic"], ["otp"]) == ["npm", "otp"]

    def test_fallback_stays_when_catalog_type_does_not_replace(self):
        assert reconcile_ecosystems(["npm", "generic"], ["rpm"]) == ["npm", "generic"]

    @pytest.mark.parametrize("fallback", ["generic", "unknown"])
    def test_oci_stays_fallback(self, fallback):
        assert reconcile_ecosystems([fallback], ["oci"]) == [fallback]

    @pytest.mark.parametrize("distro", ["rpm", "apk", "deb"])
    def test_distribution_types_stay_generic(self, distro):
        assert reconcile_ecosystems(["generic"], [distro]) == ["generic"]

    def test_separate_components_keep_generic_and_otp(self):
        assert reconcile_ecosystems_by_component(
            ["generic"], [["otp"], ["generic"]]
        ) == ["otp", "generic"]

    def test_mixed_model_keeps_specific_across_components(self):
        assert reconcile_ecosystems_by_component(
            ["npm", "generic"], [["otp"], ["rpm"]]
        ) == ["npm", "otp", "generic"]

    def test_same_component_with_both_types_stays_otp(self):
        assert reconcile_ecosystems_by_component(["generic"], [["otp", "generic"]]) == [
            "otp"
        ]

    def test_unmatched_component_does_not_restore_a_replaced_fallback(self):
        assert reconcile_ecosystems_by_component(["generic"], [["otp"], []]) == ["otp"]

    def test_no_catalog_types_keeps_the_model_list(self):
        assert reconcile_ecosystems_by_component(["generic"], [[], []]) == ["generic"]


class TestApplyBomqAliases:
    def test_appends_only_confirmed_aliases(self):
        components, accepted = apply_bomq_aliases(
            ["libvips", "libsoup"],
            [("libvips", "vips"), ("libsoup", "libsoup3"), ("libvips", "vips")],
            lambda suggested, alias: alias != "libsoup3",
        )
        assert components == ["libvips", "libsoup", "vips"]
        assert accepted == [("libvips", "vips")]
