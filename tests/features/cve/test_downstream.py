"""Recorded-payload tests for same-project downstream name mapping."""

import json
import time
import urllib.parse
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from aegis_ai.features.cve.data_models import (
    ManifestComponentEntry,
    ManifestUsageAnalysis,
    SuggestManifestComponentAndStateModel,
)
from aegis_ai.features.cve.downstream import (
    CandidateHit,
    CatalogHit,
    DownstreamRow,
    _catalog_query_names,
    _glob_match,
    align_manifest_search_keys,
    apply_usage_policy,
    collect_downstream,
    collect_downstream_candidates,
    drop_short_segments_of_kept_modules,
    drop_soft_label_rejects,
    drop_suppressed_short_path_entries,
    ensure_soft_label_keeps,
    filter_anitya_response,
    filter_bomq_response,
    http_get_json,
    post_filter_manifest_entries,
    promote_reference_caller_modules,
    rejected_soft_label_names,
    suppressed_short_path_names,
)

PRIMARY = "https://bomq.example"
COMMUNITY = "https://community.example"
ANITYA = "https://anitya.example"


def _collect(
    flaw,
    *,
    components,
    projects=None,
    packages=None,
    builds=None,
    rhcos=None,
    component_versions=None,
    community=COMMUNITY,
    anitya=ANITYA,
):
    """Run collect_downstream against a stub bomq/Anitya catalog."""
    seen: list[str] = []
    projects = projects or {}
    packages = packages or {}
    builds = builds or {}
    rhcos = rhcos or {}
    component_versions = component_versions or {}

    def get_json(url: str):
        seen.append(url)
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        if path.startswith("/api/v0alpha/components"):
            requested = query["name"][0]
            data = []
            for name, types in components.items():
                matched = (
                    _glob_match(requested, name)
                    if "*" in requested
                    else name.casefold() == requested.casefold()
                )
                if matched:
                    data.extend({"name": name, "type": item} for item in types)
            return {"data": data, "total": len(data)}
        if path.startswith("/api/v2/projects"):
            requested = query["name"][0].casefold()
            items = projects.get(requested, [])
            return {"items": items, "total_items": len(items)}
        if path.startswith("/api/project/"):
            project_id = int(path.rstrip("/").rsplit("/", 1)[-1])
            return {"packages": packages.get(project_id, [])}
        if path.startswith("/api/v0/search/builds"):
            requested = query["name"][0].casefold()
            return {"data": builds.get(requested, [])}
        if path.startswith("/api/v0/search/components"):
            requested = query["name"][0].casefold()
            if query.get("build_name"):
                return {"data": rhcos.get(requested, [])}
            return {"data": component_versions.get(requested, [])}
        raise AssertionError(url)

    result = collect_downstream(
        flaw,
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=community,
        anitya_url=anitya,
    )
    return result, seen


def _names(result):
    """Return non-RHCOS downstream row names from a collect result."""
    return [row.name for row in result.rows if row.rhcos is None]


def _by_name(result):
    """Map non-RHCOS downstream rows by package name."""
    return {row.name: row for row in result.rows if row.rhcos is None}


def test_openssl_keeps_github_project_and_nulls_compat_affectedness():
    """Openssl keeps github project and nulls compat affectedness."""
    result, _urls = _collect(
        {
            "components": ["openssl"],
            "title": "openssl vulnerability",
            "upstream_data": {
                "affected": [{"ranges": [{"events": [{"introduced": "3.0.0"}]}]}]
            },
        },
        components={
            "openssl": ["rpm", "generic"],
            "rust-openssl": ["rpm"],
            "golang-github-spacemonkeygo-openssl": ["rpm"],
            "compat-openssl11": ["rpm"],
        },
        projects={
            "openssl": [
                {
                    "id": 15451,
                    "name": "openssl",
                    "backend": "crates.io",
                    "homepage": "https://crates.io/crates/openssl",
                },
                {
                    "id": 2566,
                    "name": "openssl",
                    "backend": "GitHub",
                    "homepage": "https://www.openssl.org",
                },
            ]
        },
        packages={
            15451: [{"distro": "Fedora", "package_name": "rust-openssl"}],
            2566: [
                {"distro": "Fedora", "package_name": "openssl"},
                {
                    "distro": "Fedora",
                    "package_name": "golang-github-spacemonkeygo-openssl",
                },
                {"distro": "Debian", "package_name": "openssl"},
            ],
        },
        builds={
            "openssl": [{"build_version": "3.0.7-1.el9"}],
            "compat-openssl11": [{"build_version": "3.0.1-21.el7"}],
        },
    )
    assert _names(result) == ["openssl", "compat-openssl11"]
    assert _by_name(result)["openssl"].build_type == "rpm"
    assert _by_name(result)["openssl"].ecosystem is None
    assert any(
        "exclude_subcomponents=true" in url and "/api/v0alpha/components" in url
        for url in _urls
    )
    assert _by_name(result)["openssl"].affectedness == "AFFECTED"
    assert _by_name(result)["compat-openssl11"].affectedness is None
    assert len(result.explanation) >= 80


def test_libsoup_version_package_uses_upstream_ranges():
    """Libsoup version package uses upstream ranges."""
    result, _urls = _collect(
        {
            "components": ["libsoup"],
            "comment_zero": "libsoup before 3 is a different soname",
            "upstream_data": {
                "affected": [{"ranges": [{"events": [{"introduced": "3.0.0"}]}]}]
            },
        },
        components={"libsoup": ["rpm"], "libsoup3": ["rpm"]},
        projects={
            "libsoup": [
                {
                    "id": 11483,
                    "name": "libsoup",
                    "backend": "GNOME",
                    "homepage": "https://libsoup.org",
                }
            ]
        },
        packages={
            11483: [
                {"distro": "Fedora", "package_name": "libsoup3"},
                {"distro": "Fedora", "package_name": "mingw-libsoup"},
            ]
        },
        builds={
            "libsoup": [{"build_version": "2.74.3-1.el9"}],
            "libsoup3": [{"build_version": "3.4.4-1.el9"}],
        },
    )
    assert _names(result) == ["libsoup", "libsoup3"]
    assert _by_name(result)["libsoup"].affectedness == "NOTAFFECTED"
    assert _by_name(result)["libsoup3"].affectedness == "AFFECTED"
    assert _by_name(result)["libsoup3"].build_type == "rpm"


def test_gdk_pixbuf_uses_the_non_registry_project():
    """Gdk pixbuf uses the non registry project."""
    result, _urls = _collect(
        {"components": ["gdk-pixbuf"], "title": "gdk-pixbuf"},
        components={
            "gdk-pixbuf2": ["rpm"],
            "gdk-pixbuf2-modules-extra": ["rpm"],
            "rust-gdk-pixbuf": ["rpm"],
        },
        projects={
            "gdk-pixbuf": [
                {
                    "id": 9533,
                    "name": "gdk-pixbuf",
                    "backend": "GitLab",
                    "homepage": "https://gitlab.gnome.org/GNOME/gdk-pixbuf",
                },
                {
                    "id": 16745,
                    "name": "gdk-pixbuf",
                    "backend": "crates.io",
                    "homepage": "https://crates.io/crates/gdk-pixbuf",
                },
            ]
        },
        packages={
            9533: [
                {"distro": "Fedora", "package_name": "gdk-pixbuf2"},
                {"distro": "Fedora", "package_name": "gdk-pixbuf2-modules-extra"},
            ],
            16745: [{"distro": "Fedora", "package_name": "rust-gdk-pixbuf"}],
        },
    )
    assert _names(result) == ["gdk-pixbuf2"]
    assert _by_name(result)["gdk-pixbuf2"].build_type == "rpm"


def test_net_oauth_fedora_rename():
    """Net oauth fedora rename."""
    result, _urls = _collect(
        {"components": ["Net-OAuth"], "title": "Net-OAuth"},
        components={"perl-Net-OAuth": ["rpm"]},
        projects={
            "net-oauth": [
                {
                    "id": 10352,
                    "name": "Net-OAuth",
                    "backend": "CPAN (perl)",
                    "homepage": "https://metacpan.org/release/Net-OAuth",
                }
            ]
        },
        packages={
            10352: [{"distro": "Fedora", "package_name": "perl-Net-OAuth"}],
        },
    )
    assert _names(result) == ["perl-Net-OAuth"]
    assert _by_name(result)["perl-Net-OAuth"].build_type == "rpm"


def test_tomcat_keeps_version_rebuilds_and_drops_neighbors():
    """Tomcat keeps version rebuilds and drops neighbors."""
    result, urls = _collect(
        {"components": ["tomcat"], "title": "tomcat"},
        components={
            "tomcat": ["rpm", "generic", "oci"],
            "jws5-tomcat": ["rpm"],
            "jws6-tomcat": ["rpm"],
            "jws7-tomcat": ["rpm"],
            "idm-jss-tomcat": ["rpm"],
            "mod_cluster-tomcat": ["rpm"],
            "tomcatx": ["rpm"],
            "python3-tomcat": ["rpm"],
        },
        projects={
            "tomcat": [
                {
                    "id": 148939,
                    "name": "tomcat",
                    "backend": "GitHub",
                    "homepage": "https://tomcat.apache.org",
                }
            ]
        },
        packages={
            148939: [{"distro": "Fedora", "package_name": "tomcatx"}],
        },
    )
    assert _names(result) == [
        "tomcat",
        "tomcatx",
        "jws5-tomcat",
        "jws6-tomcat",
        "jws7-tomcat",
    ]
    assert _by_name(result)["tomcat"].build_type == "rpm"
    assert _by_name(result)["tomcat"].ecosystem is None
    glob_urls = [
        url
        for url in urls
        if "*" in urllib.parse.unquote(url) and "/api/v0alpha/components" in url
    ]
    assert glob_urls
    assert all(url.startswith((PRIMARY, COMMUNITY)) for url in glob_urls)


def test_rclone_full_path_does_not_add_the_short_name():
    """Rclone full path does not add the short name."""
    result, urls = _collect(
        {"components": ["github.com/rclone/rclone"], "title": "rclone"},
        components={
            "github.com/rclone/rclone": ["golang", "generic"],
            "rclone": ["rpm"],
        },
        projects={
            "rclone": [
                {
                    "id": 1,
                    "name": "rclone",
                    "backend": "GitHub",
                    "homepage": "https://github.com/rclone/rclone",
                }
            ]
        },
        packages={1: [{"distro": "Fedora", "package_name": "rclone"}]},
    )
    assert _names(result) == ["github.com/rclone/rclone"]
    assert _by_name(result)["github.com/rclone/rclone"].ecosystem == "golang"
    anitya_urls = [url for url in urls if "/api/v2/projects/" in url]
    assert anitya_urls == []


def test_nuclei_short_rpm_when_the_module_path_is_absent():
    """Nuclei short rpm when the module path is absent."""
    result, _urls = _collect(
        {
            "components": ["github.com/projectdiscovery/nuclei"],
            "title": "nuclei",
        },
        components={"nuclei": ["rpm"], "rust-nuclei": ["rpm"]},
        projects={
            "nuclei": [
                {
                    "id": 9,
                    "name": "nuclei",
                    "backend": "GitHub",
                    "homepage": "https://github.com/projectdiscovery/nuclei",
                },
                {
                    "id": 10,
                    "name": "nuclei",
                    "backend": "crates.io",
                    "homepage": "https://github.com/projectdiscovery/nuclei",
                },
                {
                    "id": 11,
                    "name": "nuclei",
                    "backend": "GitHub",
                    "homepage": "https://example.com/other-nuclei",
                },
            ]
        },
        packages={
            9: [{"distro": "Fedora", "package_name": "nuclei"}],
            10: [{"distro": "Fedora", "package_name": "rust-nuclei"}],
            11: [{"distro": "Fedora", "package_name": "nuclei-other"}],
        },
    )
    assert _names(result) == ["nuclei"]
    assert _by_name(result)["nuclei"].build_type == "rpm"


def test_ion_java_is_empty():
    """Ion java is empty."""
    result, _urls = _collect(
        {
            "components": ["software.amazon.ion/ion-java"],
            "title": "ion-java",
            "description": "No downstream package is known for this coordinate.",
        },
        components={},
    )
    assert result.rows == []
    assert len(result.explanation) >= 80


def test_scoped_npm_drops_the_bare_final_segment():
    """Scoped npm drops the bare final segment."""
    result, urls = _collect(
        {"components": ["xmldom", "@xmldom/xmldom"], "title": "xmldom"},
        components={
            "xmldom": ["npm"],
            "@xmldom/xmldom": ["npm"],
            "nodejs-xmldom": ["npm"],
        },
        projects={
            "xmldom": [
                {
                    "id": 4,
                    "name": "xmldom",
                    "backend": "npm",
                    "homepage": "https://github.com/xmldom/xmldom",
                }
            ]
        },
        packages={4: [{"distro": "Fedora", "package_name": "nodejs-xmldom"}]},
    )
    assert _names(result) == ["@xmldom/xmldom"]
    assert _by_name(result)["@xmldom/xmldom"].ecosystem == "npm"
    assert [url for url in urls if "/api/v2/projects/" in url] == []


def test_queries_use_example_hosts_and_skip_an_empty_community_catalog():
    """Queries use example hosts and skip an empty community catalog."""
    _result, urls = _collect(
        {"components": ["nginx"], "title": "nginx"},
        components={"nginx": ["rpm"]},
        community="",
    )
    assert urls
    assert all(url.startswith((PRIMARY, ANITYA)) for url in urls)
    assert not any(url.startswith(COMMUNITY) for url in urls)

    _result, urls = _collect(
        {"components": ["nginx"], "title": "nginx"},
        components={"nginx": ["rpm"]},
    )
    assert any(url.startswith(PRIMARY) for url in urls)
    assert any(url.startswith(COMMUNITY) for url in urls)


def test_catalog_connection_errors_mark_catalog_unavailable():
    """Catalog connection errors mark catalog unavailable."""

    def get_json(_url):
        return None

    gathered = collect_downstream_candidates(
        {"components": ["nginx"], "title": "nginx"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
    )
    assert gathered.catalog_unavailable is True
    assert gathered.candidates == []
    assert "lookups failed" in gathered.explanation

    result = collect_downstream(
        {"components": ["nginx"], "title": "nginx"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
    )
    assert result.rows == []
    assert "lookups failed" in result.explanation


def test_successful_empty_catalog_is_not_unavailable():
    """Successful empty catalog is not unavailable."""

    def get_json(_url):
        if "/api/v2/projects/" in _url:
            return {"items": [], "total_items": 0}
        return {"data": [], "total": 0}

    gathered = collect_downstream_candidates(
        {"components": ["nginx"], "title": "nginx"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
    )
    assert gathered.catalog_unavailable is False
    assert gathered.candidates == []


def test_prefetch_stops_when_overall_deadline_expires():
    """Prefetch stops when overall deadline expires."""
    calls: list[str] = []

    def get_json(url: str):
        calls.append(url)
        time.sleep(0.03)

    gathered = collect_downstream_candidates(
        {"components": ["nginx", "httpd", "openssl"], "title": "slow catalog"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
        prefetch_timeout_secs=0.05,
    )
    # Without a budget this seed×host catalog walk issues many requests; the
    # overall deadline must cut that short so one slow catalog cannot stall.
    assert 1 <= len(calls) <= 3
    assert gathered.catalog_unavailable is True


@pytest.mark.asyncio
async def test_feature_returns_zero_confidence_when_catalog_unavailable(monkeypatch):
    """Feature returns zero confidence when catalog unavailable."""
    monkeypatch.setattr(
        "aegis_ai.features.cve.downstream.http_get_json",
        lambda _url, *, timeout=None, deadline=None: None,
    )
    monkeypatch.setattr(
        "aegis_ai.features.cve.downstream.get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "bomq_url": PRIMARY,
                "bomq_community_url": COMMUNITY,
                "anitya_url": ANITYA,
            },
        )(),
    )

    from aegis_ai.features.cve import SuggestManifestComponentAndState

    class _Agent:
        name = "RHFeatureAgent"

    feature = SuggestManifestComponentAndState(agent=_Agent())
    result = await feature.exec(
        "CVE-2026-90439",
        static_context={
            "components": ["nginx"],
            "title": "nginx",
            "description": "A flaw in nginx.",
            "comment_zero": "A flaw in nginx.",
            "cve_description": "",
            "statement": "",
            "references": [],
            "upstream_data": None,
        },
    )
    assert result.output.manifest_components == []
    assert result.output.confidence == 0.0
    assert result.output._catalog_outage is True
    assert "lookups failed" in result.output.explanation


def test_kernel_does_not_query_catalogs():
    """Kernel does not query catalogs."""

    def get_json(_url):
        raise AssertionError("kernel flaws do not query catalogs")

    result = collect_downstream(
        {"components": ["kernel"], "title": "kernel"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
    )
    assert result.rows == []
    assert len(result.explanation) >= 80


def test_rhcos_hit_adds_a_companion_row():
    """Rhcos hit adds a companion row."""
    result, _urls = _collect(
        {"components": ["nginx"], "title": "nginx"},
        components={"nginx": ["rpm"]},
        rhcos={
            "nginx": [
                {
                    "build_name": "rhcos-4.16",
                    "sources": [
                        {"components": [{"name": "nginx", "version": "1.26.1-1.el9"}]}
                    ],
                }
            ]
        },
        builds={"nginx": [{"build_version": "1.26.1-1.el9"}]},
    )
    companions = [row for row in result.rows if row.rhcos == "rpm"]
    assert len(companions) == 1
    assert companions[0].name == "nginx"
    assert companions[0].build_type is None
    assert "bomq_rhcos" in result.tools_used


def test_entry_requires_exactly_one_search_key():
    """Entry requires exactly one search key."""
    ManifestComponentEntry(name="nginx", build_type="rpm")
    with pytest.raises(ValidationError):
        ManifestComponentEntry(name="nginx", build_type="rpm", ecosystem="generic")
    with pytest.raises(ValidationError):
        ManifestComponentEntry(name="nginx")


@pytest.mark.asyncio
async def test_feature_records_the_osidb_flaw_as_a_tool(monkeypatch):
    """Exercise OSIDB retrieval (no flaw-body static_context) and assert it is used."""

    def get_json(url: str, *, timeout: float | None = None, deadline=None):
        del timeout, deadline
        if "/api/v0alpha/components" in url and "nginx" in urllib.parse.unquote(url):
            if "*" in urllib.parse.unquote(url):
                return {"data": [], "total": 0}
            return {
                "data": [{"name": "nginx", "type": "rpm"}],
                "total": 1,
            }
        if "/api/v2/projects/" in url:
            return {"items": [], "total_items": 0}
        return {"data": []}

    retrieved: list[str] = []

    class _RetrievedFlaw:
        def model_dump(self):
            return {
                "components": ["nginx"],
                "title": "nginx",
                "description": "A flaw in nginx.",
                "comment_zero": "A flaw in nginx.",
                "cve_description": "",
                "statement": "",
                "references": [],
                "upstream_data": None,
            }

    async def cve_retrieve(cve_id):
        retrieved.append(cve_id)
        return _RetrievedFlaw()

    monkeypatch.setattr(
        "aegis_ai.features.cve.downstream.http_get_json",
        get_json,
    )
    monkeypatch.setattr(
        "aegis_ai.features.cve.osidb_tool.cve_retrieve",
        cve_retrieve,
    )
    monkeypatch.setattr(
        "aegis_ai.features.cve.downstream.get_settings",
        lambda: type(
            "Settings",
            (),
            {
                "bomq_url": PRIMARY,
                "bomq_community_url": "",
                "anitya_url": ANITYA,
            },
        )(),
    )

    from aegis_ai.features.cve import SuggestManifestComponentAndState

    class _Agent:
        name = "RHFeatureAgent"

    feature = SuggestManifestComponentAndState(agent=_Agent())

    async def fake_guarded_run(prompt, **kwargs):
        baseline = prompt.context.soft_label_baseline
        output = SuggestManifestComponentAndStateModel(
            cve_id="CVE-2026-90439",
            manifest_components=[
                ManifestComponentEntry(
                    name=row["name"],
                    build_type=row.get("build_type"),
                    ecosystem=row.get("ecosystem"),
                    rhcos=row.get("rhcos"),
                    affectedness=row.get("affectedness"),
                    evidence=row.get("evidence"),
                )
                for row in baseline
            ],
            usage=ManifestUsageAnalysis(
                vulnerable_unit="nginx",
                caller_role="every_importer",
                runs_vulnerable_code=["nginx"],
                importer_only=[],
            ),
            explanation=(
                "Prefetched catalog soft-label baseline kept nginx as an RPM "
                "build from the flaw components seed."
            ),
            confidence=0.9,
            data_quality=0.9,
            tools_used=[],
            disclaimer=(
                "This response was generated by Aegis AI "
                "(https://github.com/RedHatProductSecurity/aegis-ai) using "
                "generative AI for informational purposes. All findings should "
                "be validated by a human expert."
            ),
        )
        return type("Result", (), {"output": output})()

    monkeypatch.setattr(feature, "guarded_run", fake_guarded_run)
    result = await feature.exec("CVE-2026-90439")
    output = result.output
    assert retrieved == ["CVE-2026-90439"]
    assert [row.name for row in output.manifest_components] == ["nginx"]
    assert output.manifest_components[0].build_type == "rpm"
    assert "osidb_tool" in output.tools_used
    assert output.confidence == 0.9
    assert len(output.explanation) >= 80


def test_catalog_query_names_add_reference_caller_token():
    """Catalog query names add reference caller token."""
    flaw = {
        "components": ["github.com/prometheus/common"],
        "references": [
            {"url": "https://github.com/prometheus/common/pull/901"},
            {
                "url": (
                    "https://github.com/prometheus/prometheus/blob/"
                    "v3.15.1/storage/remote/client.go"
                )
            },
        ],
    }
    seeds = ["github.com/prometheus/common"]
    assert _catalog_query_names(seeds, flaw) == [
        "github.com/prometheus/common",
        "github.com/prometheus/prometheus",
        "prometheus",
    ]


def test_prometheus_reference_token_keeps_openshift_priv_and_rpms():
    """Prometheus reference token keeps openshift priv and rpms."""
    result, urls = _collect(
        {
            "components": ["github.com/prometheus/common"],
            "title": "Prometheus remote_write credential leak",
            "comment_zero": "Prometheus through 3.15.1 contains a credential leak.",
            "references": [
                {"url": "https://github.com/prometheus/common/pull/901"},
                {
                    "url": (
                        "https://github.com/prometheus/prometheus/blob/"
                        "v3.15.1/storage/remote/client.go"
                    )
                },
            ],
        },
        components={
            "github.com/prometheus/common": ["golang"],
            "github.com/prometheus/prometheus": ["golang"],
            "github.com/openshift-priv/prometheus": ["golang"],
            "prometheus": ["rpm"],
            "prometheus3.13": ["rpm"],
            "prometheus3.5": ["rpm"],
            "github.com/prometheus/client_golang": ["golang"],
        },
        builds={
            "prometheus": [{"build_version": "3.14.0-1.fc42"}],
            "prometheus3.13": [{"build_version": "3.13.5-1.hum1"}],
            "prometheus3.5": [{"build_version": "3.5.0-1.hum1"}],
        },
        component_versions={
            "github.com/openshift-priv/prometheus": [
                {
                    "build_name": "ose-prometheus",
                    "sources": [
                        {
                            "components": [
                                {
                                    "name": "github.com/openshift-priv/prometheus",
                                    "type": "golang",
                                    "version": "v3.14.0",
                                }
                            ]
                        }
                    ],
                }
            ],
            "github.com/prometheus/prometheus": [
                {
                    "build_name": "prometheus",
                    "sources": [
                        {
                            "components": [
                                {
                                    "name": "github.com/prometheus/prometheus",
                                    "type": "golang",
                                    "version": "v3.14.0",
                                }
                            ]
                        }
                    ],
                }
            ],
            "github.com/prometheus/common": [
                {
                    "build_name": "importer",
                    "sources": [
                        {
                            "components": [
                                {
                                    "name": "github.com/prometheus/common",
                                    "type": "golang",
                                    "version": "v0.60.0",
                                }
                            ]
                        }
                    ],
                }
            ],
        },
        anitya="",
    )
    names = _names(result)
    assert "github.com/openshift-priv/prometheus" in names
    # Bare reference token stays a candidate, not an automatic soft-label keep.
    assert "prometheus" not in names
    assert "prometheus3.13" in names
    assert "prometheus3.5" in names
    assert "github.com/prometheus/client_golang" not in names
    assert _by_name(result)["github.com/openshift-priv/prometheus"].affectedness == (
        "AFFECTED"
    )
    assert _by_name(result)["prometheus3.13"].affectedness == "AFFECTED"
    assert any("name=prometheus" in url for url in urls)
    assert any("exclude_subcomponents=true" in url for url in urls)
    assert any(
        "include_types=golang" in url and "/api/v0/search/components" in url
        for url in urls
    )


def test_ecosystem_component_versions_outside_range_are_notaffected():
    """Ecosystem component versions outside range are notaffected."""
    result, _urls = _collect(
        {
            "components": ["github.com/prometheus/common"],
            "comment_zero": "Prometheus through 3.15.1 contains a credential leak.",
            "references": [
                {
                    "url": (
                        "https://github.com/prometheus/prometheus/blob/"
                        "v3.16.0/storage/remote/client.go"
                    )
                },
            ],
        },
        components={
            "github.com/prometheus/common": ["golang"],
            "github.com/prometheus/prometheus": ["golang"],
            "github.com/openshift-priv/prometheus": ["golang"],
            "prometheus": ["rpm"],
        },
        builds={"prometheus": [{"build_version": "3.16.0-1.fc42"}]},
        component_versions={
            "github.com/openshift-priv/prometheus": [
                {
                    "build_name": "ose-prometheus",
                    "sources": [
                        {
                            "components": [
                                {
                                    "name": "github.com/openshift-priv/prometheus",
                                    "type": "golang",
                                    "version": "v3.16.0",
                                }
                            ]
                        }
                    ],
                }
            ],
            "github.com/prometheus/prometheus": [
                {
                    "build_name": "prometheus",
                    "sources": [
                        {
                            "components": [
                                {
                                    "name": "github.com/prometheus/prometheus",
                                    "type": "golang",
                                    "version": "v3.16.0",
                                }
                            ]
                        }
                    ],
                }
            ],
            "github.com/prometheus/common": [
                {
                    "build_name": "importer",
                    "sources": [
                        {
                            "components": [
                                {
                                    "name": "github.com/prometheus/common",
                                    "type": "golang",
                                    "version": "v0.62.0",
                                }
                            ]
                        }
                    ],
                }
            ],
        },
        anitya="",
    )
    by_name = _by_name(result)
    assert by_name["github.com/openshift-priv/prometheus"].affectedness == (
        "NOTAFFECTED"
    )
    # Reference exact hits are candidates, not soft-label keepers.
    assert "github.com/prometheus/prometheus" not in by_name
    assert "prometheus" not in by_name


def test_bare_through_advisory_parses_last_affected():
    """Bare through advisory parses last affected."""
    from aegis_ai.features.cve.downstream import _advisory_bounds, _upstream_version

    bounds = _advisory_bounds("Prometheus through 3.15.1 contains a credential leak.")
    assert any(b.last_affected == "3.15.1" and b.introduced is None for b in bounds)
    assert _upstream_version("v3.15.1") == "3.15.1"
    assert _upstream_version("3.15.1-1.el9") == "3.15.1"


def test_jbcs_multi_token_rebuild_is_a_clear_rebuild_keeper():
    """Jbcs multi token rebuild is a clear rebuild keeper."""
    result, _urls = _collect(
        {"components": ["openssl"], "title": "openssl"},
        components={
            "openssl": ["rpm"],
            "jbcs-httpd24-openssl": ["rpm"],
            "idm-jss-openssl": ["rpm"],
        },
    )
    names = _names(result)
    assert "openssl" in names
    assert "jbcs-httpd24-openssl" in names
    assert "idm-jss-openssl" not in names


def test_openshift_priv_fork_rebuild_matches_upstream_repo_seed():
    """openshift-priv/<project> maps to openshift/<project>; keep when repo matches."""
    from aegis_ai.features.cve.downstream import _label_candidates

    patched = (
        "github.com/openshift-priv/prometheus/patches/"
        "github.com/prometheus/common/config"
    )
    catalog = {
        "github.com/prometheus/prometheus": [
            CatalogHit("github.com/prometheus/prometheus", "golang", 10),
        ],
        "github.com/openshift-priv/prometheus": [
            CatalogHit("github.com/openshift-priv/prometheus", "golang", 4),
        ],
        patched: [CatalogHit(patched, "golang", 1)],
    }
    labeled = _label_candidates(
        ["github.com/prometheus/prometheus"], catalog, {}, set()
    )
    by_name = {hit.name: hit for hit in labeled}
    assert by_name["github.com/openshift-priv/prometheus"].soft_label == "fork_rebuild"
    assert by_name[patched].soft_label == "fork_rebuild"

    result, _ = _collect(
        {"components": ["prometheus"], "title": "Prometheus"},
        components={
            "prometheus": ["rpm"],
            "github.com/openshift-priv/prometheus": ["golang"],
        },
        anitya="",
    )
    assert "github.com/openshift-priv/prometheus" in _names(result)

    labeled_common = _label_candidates(
        ["github.com/prometheus/common"],
        {
            "github.com/prometheus/common": [
                CatalogHit("github.com/prometheus/common", "golang", 100),
            ],
            "github.com/openshift-priv/prometheus": [
                CatalogHit("github.com/openshift-priv/prometheus", "golang", 4),
            ],
        },
        {},
        set(),
    )
    by_rejected = {hit.name: hit for hit in labeled_common}
    assert by_rejected["github.com/openshift-priv/prometheus"].soft_label == "drop_hint"
    assert (
        by_rejected["github.com/openshift-priv/prometheus"].drop_reason
        == "unrelated_to_seed"
    )

    # Reference-caller packaging token keeps the openshift-priv rebuild.
    labeled_with_token = _label_candidates(
        ["github.com/prometheus/common", "prometheus"],
        {
            "github.com/prometheus/common": [
                CatalogHit("github.com/prometheus/common", "golang", 100),
            ],
            "github.com/openshift-priv/prometheus": [
                CatalogHit("github.com/openshift-priv/prometheus", "golang", 4),
            ],
            "prometheus": [CatalogHit("prometheus", "rpm", 40)],
            "prometheus3.13": [CatalogHit("prometheus3.13", "rpm", 2)],
        },
        {},
        set(),
        seed_names=["github.com/prometheus/common"],
    )
    by_token = {hit.name: hit for hit in labeled_with_token}
    assert by_token["github.com/openshift-priv/prometheus"].soft_label == "fork_rebuild"
    # Reference packaging token is visible but not a soft-label keeper.
    assert by_token["prometheus"].soft_label == "reference"
    assert by_token["prometheus3.13"].soft_label == "version_package"


def test_binutils_anitya_cross_toolchains_are_keepers():
    """Anitya Fedora packages under GNU binutils stay soft-label keepers.

    avr-binutils and arm-none-eabi-binutils-cs share the upstream tarball but
    fail _is_clear_rebuild (target triple / -cs suffix). Without Anitya they
    are packaging drops; with Anitya they are keepers.
    """
    from aegis_ai.features.cve.downstream import _label_candidates

    catalog = {
        "binutils": [CatalogHit("binutils", "rpm", 100)],
        "mingw-binutils": [CatalogHit("mingw-binutils", "rpm", 10)],
        "avr-binutils": [CatalogHit("avr-binutils", "rpm", 5)],
        "arm-none-eabi-binutils-cs": [
            CatalogHit("arm-none-eabi-binutils-cs", "rpm", 3)
        ],
    }
    structural = _label_candidates(["binutils"], catalog, {}, set())
    by_structural = {hit.name: hit for hit in structural}
    assert by_structural["avr-binutils"].soft_label == "drop_hint"
    assert by_structural["avr-binutils"].drop_reason == "neighbor_rebuild"
    assert by_structural["arm-none-eabi-binutils-cs"].soft_label == "drop_hint"
    assert by_structural["arm-none-eabi-binutils-cs"].drop_reason in {
        "lookalike",
        "unrelated_to_seed",
    }
    assert "avr-binutils" in rejected_soft_label_names(structural)
    assert "arm-none-eabi-binutils-cs" in rejected_soft_label_names(structural)

    anitya_names = {
        "avr-binutils": "binutils",
        "arm-none-eabi-binutils-cs": "binutils",
        "mingw-binutils": "binutils",
    }
    labeled = _label_candidates(["binutils"], catalog, anitya_names, set())
    by_name = {hit.name: hit for hit in labeled}
    assert by_name["binutils"].soft_label == "seed"
    assert by_name["avr-binutils"].soft_label == "anitya"
    assert by_name["arm-none-eabi-binutils-cs"].soft_label == "anitya"
    assert by_name["mingw-binutils"].soft_label == "anitya"
    rejected = rejected_soft_label_names(labeled)
    assert "avr-binutils" not in rejected
    assert "arm-none-eabi-binutils-cs" not in rejected


def test_fluidsynth_plugins_are_neighbor_rebuild_rejects():
    """Wide *fluidsynth* hits that end in -fluidsynth are packaging drops."""
    gathered, _urls = _collect_candidates(
        {"components": ["FluidSynth"], "title": "FluidSynth: DoS via crafted DLS"},
        components={
            "fluidsynth": ["rpm", "generic"],
            "fluidsynth-devel": ["rpm"],
            "fluidsynth-libs": ["rpm"],
            "gstreamer1-plugins-bad-free-fluidsynth": ["rpm"],
            "vlc-plugin-fluidsynth": ["rpm"],
        },
        anitya="",
    )
    by_name = {hit.name: hit for hit in gathered.candidates}
    assert by_name["fluidsynth"].soft_label == "seed"
    assert by_name["fluidsynth-devel"].drop_reason == "subpackage"
    assert by_name["fluidsynth-libs"].drop_reason == "subpackage"
    assert by_name["gstreamer1-plugins-bad-free-fluidsynth"].drop_reason == (
        "neighbor_rebuild"
    )
    assert by_name["vlc-plugin-fluidsynth"].drop_reason == "neighbor_rebuild"

    rejected = rejected_soft_label_names(gathered.candidates)
    assert "gstreamer1-plugins-bad-free-fluidsynth" in rejected
    assert "vlc-plugin-fluidsynth" in rejected
    assert "fluidsynth-devel" in rejected
    assert "fluidsynth-libs" in rejected
    assert "fluidsynth" not in rejected

    result, _ = _collect(
        {"components": ["FluidSynth"], "title": "FluidSynth"},
        components={
            "fluidsynth": ["rpm"],
            "fluidsynth-devel": ["rpm"],
            "gstreamer1-plugins-bad-free-fluidsynth": ["rpm"],
            "vlc-plugin-fluidsynth": ["rpm"],
        },
        anitya="",
    )
    assert _names(result) == ["fluidsynth"]


def test_drop_soft_label_rejects_removes_fluidsynth_plugins():
    """Drop soft label rejects removes fluidsynth plugins."""
    candidates = [
        CandidateHit("fluidsynth", "rpm", "seed", "FluidSynth", None, 1),
        CandidateHit(
            "gstreamer1-plugins-bad-free-fluidsynth",
            "rpm",
            "drop_hint",
            "FluidSynth",
            "neighbor_rebuild",
            1,
        ),
        CandidateHit(
            "vlc-plugin-fluidsynth",
            "rpm",
            "drop_hint",
            "FluidSynth",
            "neighbor_rebuild",
            1,
        ),
    ]
    entries = [
        ManifestComponentEntry(name="fluidsynth", build_type="rpm"),
        ManifestComponentEntry(
            name="gstreamer1-plugins-bad-free-fluidsynth", build_type="rpm"
        ),
        ManifestComponentEntry(name="vlc-plugin-fluidsynth", build_type="rpm"),
    ]
    filtered = drop_soft_label_rejects(entries, candidates)
    assert [entry.name for entry in filtered] == ["fluidsynth"]


def test_ensure_soft_label_keeps_restores_prometheus_version_packages():
    """Agent-omitted version_package rows are hard-restored from baseline."""
    candidates = [
        CandidateHit("prometheus", "rpm", "seed", "prometheus", None, 40),
        CandidateHit("prometheus3.13", "rpm", "version_package", "prometheus", None, 2),
        CandidateHit("prometheus3.5", "rpm", "version_package", "prometheus", None, 1),
        CandidateHit(
            "github.com/prometheus/common",
            "golang",
            "seed",
            "github.com/prometheus/common",
            None,
            1700,
        ),
    ]
    baseline = [
        DownstreamRow(name="prometheus", build_type="rpm", affectedness="AFFECTED"),
        DownstreamRow(name="prometheus3.13", build_type="rpm", affectedness="AFFECTED"),
        DownstreamRow(name="prometheus3.5", build_type="rpm", affectedness="AFFECTED"),
        DownstreamRow(
            name="github.com/prometheus/common",
            ecosystem="golang",
            affectedness="NOTAFFECTED",
        ),
    ]
    entries = [
        ManifestComponentEntry(
            name="prometheus", build_type="rpm", affectedness="AFFECTED"
        ),
    ]
    restored = ensure_soft_label_keeps(entries, baseline, candidates)
    assert [entry.name for entry in restored] == [
        "prometheus",
        "prometheus3.13",
        "prometheus3.5",
    ]
    assert restored[1].build_type == "rpm"
    assert restored[1].affectedness == "AFFECTED"
    assert restored[2].affectedness == "AFFECTED"


def test_ensure_soft_label_keeps_does_not_duplicate_present_rows():
    """Ensure soft label keeps does not duplicate present rows."""
    candidates = [
        CandidateHit("prometheus3.13", "rpm", "version_package", "prometheus", None, 2),
    ]
    baseline = [
        DownstreamRow(name="prometheus3.13", build_type="rpm", affectedness="AFFECTED"),
    ]
    entries = [
        ManifestComponentEntry(
            name="prometheus3.13", build_type="rpm", affectedness="AFFECTED"
        ),
    ]
    restored = ensure_soft_label_keeps(entries, baseline, candidates)
    assert [entry.name for entry in restored] == ["prometheus3.13"]


def test_ensure_soft_label_keeps_restores_compat_with_null_affect():
    """Ensure soft label keeps restores compat with null affect."""
    candidates = [
        CandidateHit("openssl", "rpm", "seed", "openssl", None, 10),
        CandidateHit("compat-openssl11", "rpm", "compat", "openssl", None, 3),
    ]
    baseline = [
        DownstreamRow(name="openssl", build_type="rpm", affectedness="AFFECTED"),
        DownstreamRow(name="compat-openssl11", build_type="rpm", affectedness=None),
    ]
    entries = [
        ManifestComponentEntry(
            name="openssl", build_type="rpm", affectedness="AFFECTED"
        ),
    ]
    restored = ensure_soft_label_keeps(entries, baseline, candidates)
    assert [entry.name for entry in restored] == ["openssl", "compat-openssl11"]
    assert restored[1].affectedness is None
    assert restored[1].build_type == "rpm"


def test_ensure_soft_label_keeps_does_not_restore_omitted_seed():
    """Usage remains authoritative for seed soft-labels."""
    candidates = [
        CandidateHit(
            "github.com/prometheus/common",
            "golang",
            "seed",
            "github.com/prometheus/common",
            None,
            1700,
        ),
        CandidateHit("prometheus", "rpm", "seed", "prometheus", None, 40),
    ]
    baseline = [
        DownstreamRow(
            name="github.com/prometheus/common",
            ecosystem="golang",
            affectedness="NOTAFFECTED",
        ),
        DownstreamRow(name="prometheus", build_type="rpm", affectedness="AFFECTED"),
    ]
    entries = [
        ManifestComponentEntry(
            name="prometheus", build_type="rpm", affectedness="AFFECTED"
        ),
    ]
    restored = ensure_soft_label_keeps(entries, baseline, candidates)
    assert [entry.name for entry in restored] == ["prometheus"]


def test_drop_soft_label_rejects_after_usage_policy_readd():
    """Plugins stripped by post-filter must stay out even if usage re-adds them."""
    candidates = [
        CandidateHit("fluidsynth", "rpm", "seed", "FluidSynth", None, 1),
        CandidateHit(
            "vlc-plugin-fluidsynth",
            "rpm",
            "drop_hint",
            "FluidSynth",
            "neighbor_rebuild",
            1,
        ),
    ]
    rejected = rejected_soft_label_names(candidates)
    allowed = {hit.name.casefold() for hit in candidates} - rejected
    agent_entries = [
        ManifestComponentEntry(name="fluidsynth", build_type="rpm"),
        ManifestComponentEntry(name="vlc-plugin-fluidsynth", build_type="rpm"),
    ]
    post_filtered = post_filter_manifest_entries(agent_entries, allowed)
    assert [entry.name for entry in post_filtered] == ["fluidsynth"]

    # product_feature re-adds names listed in runs_vulnerable_code.
    readded, _explanation = apply_usage_policy(
        post_filtered,
        vulnerable_unit="fluidsynth",
        caller_role="product_feature",
        runs_vulnerable_code=["fluidsynth", "vlc-plugin-fluidsynth"],
        importer_only=[],
        candidates=candidates,
        explanation="Agent kept fluidsynth and the vlc plugin.",
    )
    assert "vlc-plugin-fluidsynth" in [entry.name for entry in readded]

    final = drop_soft_label_rejects(readded, candidates)
    assert [entry.name for entry in final] == ["fluidsynth"]


def test_rejected_soft_label_names_skips_drop_hint_without_reason():
    """Usage-policy drop_hints with drop_reason=None are not hard-rejected."""
    candidates = [
        CandidateHit(
            "github.com/prometheus/common/config",
            "golang",
            "drop_hint",
            "github.com/prometheus/common",
            None,
            12,
        ),
        CandidateHit(
            "prometheus",
            "rpm",
            "drop_hint",
            "github.com/prometheus/common",
            None,
            40,
        ),
    ]
    assert rejected_soft_label_names(candidates) == set()


def test_version_suffixed_catalog_name_is_kept():
    """Version suffixed catalog name is kept."""
    result, _urls = _collect(
        {
            "components": ["openssl"],
            "upstream_data": {
                "affected": [{"ranges": [{"events": [{"introduced": "3.0.0"}]}]}]
            },
        },
        components={"openssl": ["rpm"], "openssl3": ["rpm"]},
        builds={
            "openssl": [{"build_version": "1.1.1k-1.el8"}],
            "openssl3": [{"build_version": "3.0.7-1.el9"}],
        },
    )
    assert "openssl3" in _names(result)
    assert _by_name(result)["openssl"].affectedness == "NOTAFFECTED"
    assert _by_name(result)["openssl3"].affectedness == "AFFECTED"


def test_dotted_version_packages_are_kept():
    """Fedora-style majors such as zabbix6.0 / OpenImageIO2.5 are version packages."""
    result, _urls = _collect(
        {
            "components": ["zabbix"],
            "comment_zero": (
                "Affected from 6.0.0 through 6.0.46, from 7.0.0 through 7.0.27, "
                "and from 7.4.0 through 7.4.11."
            ),
        },
        components={
            "zabbix": ["rpm"],
            "zabbix6.0": ["rpm"],
            "zabbix7.0": ["rpm"],
            "zabbix-agent": ["rpm"],
            "uwsgi-stats-pusher-zabbix": ["rpm"],
        },
        builds={
            "zabbix": [
                {"build_version": "6.0.48-1.el9"},
                {"build_version": "7.4.16-1.fc43"},
            ],
            "zabbix6.0": [{"build_version": "6.0.48-1.el8"}],
            "zabbix7.0": [{"build_version": "7.0.32-1.el9"}],
        },
    )
    names = _names(result)
    assert names == ["zabbix", "zabbix6.0", "zabbix7.0"]
    assert _by_name(result)["zabbix"].affectedness == "NOTAFFECTED"
    assert _by_name(result)["zabbix6.0"].affectedness == "NOTAFFECTED"
    assert _by_name(result)["zabbix7.0"].affectedness == "NOTAFFECTED"


def test_openimageio_dotted_version_package_notaffected_outside_introduced():
    """Openimageio dotted version package notaffected outside introduced."""
    result, _urls = _collect(
        {
            "components": ["OpenImageIO"],
            "comment_zero": (
                "Affected from 3.0.0 through 3.0.15.0 and from 3.1.0 through 3.1.10.0."
            ),
        },
        components={
            "OpenImageIO": ["rpm"],
            "OpenImageIO2.5": ["rpm"],
            "OpenImageIO-devel": ["rpm"],
            "python3-openimageio": ["rpm"],
        },
        builds={
            "openimageio": [
                {"build_version": "3.1.18.1-1.fc44"},
                {"build_version": "3.2.1.1-1.fc45"},
            ],
            "openimageio2.5": [{"build_version": "2.5.19.1-1.fc43"}],
        },
    )
    names = _names(result)
    assert "OpenImageIO" in names
    assert "OpenImageIO2.5" in names
    assert "OpenImageIO-devel" not in names
    assert "python3-openimageio" not in names
    # Soft-label: 2.5 is below introduced 3.0 → NOTAFFECTED.
    assert _by_name(result)["OpenImageIO"].affectedness == "NOTAFFECTED"
    assert _by_name(result)["OpenImageIO2.5"].affectedness == "NOTAFFECTED"


def test_advisory_through_without_from_and_mixed_samples_are_affected():
    """'X through Y' (no leading 'from') must bound; any overlap is AFFECTED."""
    from aegis_ai.features.cve.downstream import (
        VersionBound,
        _advisory_bounds,
        _decide_affectedness,
    )

    text = "In versions before 3.2.11, 3.3.0 through 3.3.12, and 3.4.0 through 3.4.13"
    bounds = _advisory_bounds(text)
    assert any(b.last_affected == "3.3.12" for b in bounds)
    assert any(b.last_affected == "3.4.13" for b in bounds)
    assert any(b.fixed == "3.2.11" for b in bounds)
    assert (
        _decide_affectedness(["1.6.1", "3.4.14"], [VersionBound(None, "3.2.11", None)])
        == "AFFECTED"
    )
    assert (
        _decide_affectedness(["3.4.14", "3.4.15"], [VersionBound(None, "3.2.11", None)])
        == "NOTAFFECTED"
    )

    result, _urls = _collect(
        {
            "components": ["OpenEXR"],
            "comment_zero": text,
        },
        components={
            "OpenEXR": ["rpm"],
            "openexr": ["rpm"],
            "openexr2": ["rpm"],
            "mingw-OpenEXR": ["rpm"],
            "openexr-devel": ["rpm"],
        },
        builds={
            "openexr": [
                {"build_version": "1.7.1-8.el7"},
                {"build_version": "2.2.0-12.el8"},
                {"build_version": "3.1.10-8.el10"},
                {"build_version": "3.4.13-2.fc45"},
            ],
            "openexr2": [{"build_version": "2.5.10-1.fc43"}],
            "mingw-openexr": [{"build_version": "2.2.1-3.el8"}],
        },
    )
    names = _names(result)
    assert "openexr2" in names
    assert "mingw-OpenEXR" in names
    assert "openexr-devel" not in names
    by_name = {name.casefold(): row for name, row in _by_name(result).items()}
    assert by_name["openexr"].affectedness == "AFFECTED"
    assert by_name["openexr2"].affectedness == "AFFECTED"
    assert by_name["mingw-openexr"].affectedness == "AFFECTED"


def test_promiscuous_wide_catalog_narrows_to_prefix_suffix_and_compat():
    """Promiscuous wide catalog narrows to prefix suffix and compat."""
    components = {f"noise-{i}-openssl-middle": ["rpm"] for i in range(60)}
    components.update(
        {
            "openssl": ["rpm"],
            "jbcs-httpd24-openssl": ["rpm"],
            "openssl3": ["rpm"],
            "compat-openssl11": ["rpm"],
            "middle-openssl-extra": ["rpm"],
        }
    )
    gathered, urls = _collect_candidates(
        {"components": ["openssl"], "title": "openssl"},
        components=components,
    )
    assert gathered.promiscuous_hosts
    names = {hit.name for hit in gathered.candidates}
    assert "openssl" in names
    assert "jbcs-httpd24-openssl" in names
    assert "openssl3" in names
    assert "compat-openssl11" in names
    assert "middle-openssl-extra" not in names
    assert any("compat-openssl" in urllib.parse.unquote(url) for url in urls)


def test_post_filter_rejects_invented_names_and_keeps_rhcos_companion():
    """Post filter rejects invented names and keeps rhcos companion."""
    allowed = {"openssl"}
    entries = [
        ManifestComponentEntry(name="openssl", build_type="rpm"),
        ManifestComponentEntry(name="invented-openssl", build_type="rpm"),
        ManifestComponentEntry(name="openssl", rhcos="rpm"),
    ]
    filtered = post_filter_manifest_entries(entries, allowed)
    assert [entry.name for entry in filtered] == ["openssl", "openssl"]
    assert filtered[1].rhcos == "rpm"


def test_post_filter_drops_rhcos_without_kept_rpm():
    """Ecosystem-only names must not admit an rhcos companion."""
    allowed = {"prometheus"}
    entries = [
        ManifestComponentEntry(name="prometheus", ecosystem="golang"),
        ManifestComponentEntry(name="prometheus", rhcos="rpm"),
    ]
    filtered = post_filter_manifest_entries(entries, allowed)
    assert [entry.name for entry in filtered] == ["prometheus"]
    assert filtered[0].ecosystem == "golang"


def test_suppressed_short_path_names_rclone_when_full_path_is_catalog_hit():
    """Suppressed short path names rclone when full path is catalog hit."""
    seeds = ["github.com/rclone/rclone"]
    candidates = {"github.com/rclone/rclone", "rclone"}
    short = suppressed_short_path_names(seeds, candidates)
    assert short == {"rclone"}

    entries = [
        ManifestComponentEntry(name="github.com/rclone/rclone", ecosystem="golang"),
        ManifestComponentEntry(name="rclone", ecosystem="golang"),
    ]
    allowed = candidates - short
    filtered = post_filter_manifest_entries(entries, allowed)
    assert [entry.name for entry in filtered] == ["github.com/rclone/rclone"]


def test_suppressed_short_path_names_keeps_nuclei_when_path_absent():
    """Suppressed short path names keeps nuclei when path absent."""
    seeds = ["github.com/projectdiscovery/nuclei"]
    candidates = {"nuclei", "rust-nuclei"}
    short = suppressed_short_path_names(seeds, candidates)
    assert short == set()

    entries = [ManifestComponentEntry(name="nuclei", build_type="rpm")]
    filtered = post_filter_manifest_entries(entries, candidates - short)
    assert [entry.name for entry in filtered] == ["nuclei"]


def test_drop_suppressed_short_path_after_usage_policy_confirm():
    """confirm_name can re-add bare rclone; drop it when the full path is a hit."""
    entries = [
        ManifestComponentEntry(
            name="github.com/rclone/rclone",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
    ]
    candidates = _usage_candidates(
        (
            "github.com/rclone/rclone",
            "golang",
            "seed",
            "github.com/rclone/rclone",
            12,
        ),
    )

    def confirm(name: str):
        from aegis_ai.features.cve.downstream import CatalogHit

        if name == "rclone":
            return [CatalogHit("rclone", "rpm", 8)]
        return []

    kept, _explanation = apply_usage_policy(
        entries,
        vulnerable_unit="github.com/rclone/rclone",
        caller_role="product_feature",
        runs_vulnerable_code=["github.com/rclone/rclone", "rclone"],
        importer_only=[],
        candidates=candidates,
        explanation="Kept the rclone module.",
        confirm_name=confirm,
    )
    assert "rclone" in [row.name for row in kept]

    short = suppressed_short_path_names(
        ["github.com/rclone/rclone"],
        {"github.com/rclone/rclone", "rclone"},
    )
    final = drop_suppressed_short_path_entries(kept, short)
    assert [row.name for row in final] == ["github.com/rclone/rclone"]


def test_align_manifest_search_keys_restores_maven_ecosystem():
    """LLM often emits build_type:maven; soft-label marks bundled GAVs as ecosystem."""
    entries = [
        ManifestComponentEntry(name="io.netty/netty-codec-http", build_type="maven"),
        ManifestComponentEntry(
            name="org.bouncycastle/bcprov-jdk15on", build_type="maven"
        ),
        ManifestComponentEntry(name="nginx", build_type="rpm"),
        ManifestComponentEntry(name="nginx", rhcos="rpm"),
    ]
    baseline = [
        DownstreamRow(name="io.netty/netty-codec-http", ecosystem="maven"),
        DownstreamRow(name="org.bouncycastle/bcprov-jdk15on", ecosystem="maven"),
        DownstreamRow(name="nginx", build_type="rpm"),
        DownstreamRow(name="nginx", rhcos="rpm"),
    ]
    aligned = align_manifest_search_keys(entries, baseline)
    assert aligned[0].ecosystem == "maven"
    assert aligned[0].build_type is None
    assert aligned[1].ecosystem == "maven"
    assert aligned[1].build_type is None
    assert aligned[2].build_type == "rpm"
    assert aligned[2].ecosystem is None
    assert aligned[3].rhcos == "rpm"
    assert aligned[3].build_type is None
    assert aligned[3].ecosystem is None


def test_align_manifest_copies_baseline_affectedness_over_unknown():
    """Align manifest copies baseline affectedness over unknown."""
    entries = [
        ManifestComponentEntry(
            name="github.com/openshift-priv/prometheus",
            ecosystem="golang",
            affectedness="UNKNOWN",
        ),
        ManifestComponentEntry(
            name="prometheus",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
    ]
    baseline = [
        DownstreamRow(
            name="github.com/openshift-priv/prometheus",
            ecosystem="golang",
            affectedness="AFFECTED",
            evidence="3.14.0",
        ),
        DownstreamRow(
            name="prometheus",
            build_type="rpm",
            affectedness="AFFECTED",
            evidence="3.14.0",
        ),
    ]
    aligned = align_manifest_search_keys(entries, baseline)
    assert aligned[0].affectedness == "AFFECTED"
    assert aligned[0].evidence == "3.14.0"
    assert aligned[1].affectedness == "AFFECTED"


def test_unknown_affectedness_when_range_is_missing():
    """Unknown affectedness when range is missing."""
    result, _urls = _collect(
        {"components": ["nginx"], "title": "nginx"},
        components={"nginx": ["rpm"]},
        builds={"nginx": [{"build_version": "1.26.1-1.el9"}]},
    )
    assert _by_name(result)["nginx"].affectedness == "UNKNOWN"


def _collect_candidates(flaw, *, components, community=COMMUNITY, anitya=ANITYA):
    """Run collect_downstream_candidates against a stub bomq catalog."""
    seen: list[str] = []

    def get_json(url: str):
        seen.append(url)
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        path = parsed.path
        if path.startswith("/api/v0alpha/components"):
            requested = query["name"][0]
            data = []
            for name, types in components.items():
                matched = (
                    _glob_match(requested, name)
                    if "*" in requested
                    else name.casefold() == requested.casefold()
                )
                if matched:
                    data.extend({"name": name, "type": item} for item in types)
            return {"data": data, "total": len(data)}
        if path.startswith("/api/v2/projects"):
            return {"items": [], "total_items": 0}
        return {"data": []}

    result = collect_downstream_candidates(
        flaw,
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=community,
        anitya_url=anitya,
    )
    return result, seen


def _usage_candidates(*rows):
    """Build CandidateHit rows for usage-policy unit tests."""
    return [
        CandidateHit(
            name=name,
            type=comp_type,
            soft_label=label,
            seed=seed,
            build_count=count,
        )
        for name, comp_type, label, seed, count in rows
    ]


def test_usage_policy_omits_high_build_count_importer():
    """Usage policy omits high build count importer."""
    entries = [
        ManifestComponentEntry(
            name="github.com/prometheus/common",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
        ManifestComponentEntry(
            name="github.com/prometheus/common/config",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
        ManifestComponentEntry(
            name="prometheus",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
    ]
    candidates = _usage_candidates(
        (
            "github.com/prometheus/common",
            "golang",
            "seed",
            "github.com/prometheus/common",
            5000,
        ),
        (
            "github.com/prometheus/common/config",
            "golang",
            "drop_hint",
            "github.com/prometheus/common",
            12,
        ),
        ("prometheus", "rpm", "drop_hint", "github.com/prometheus/common", 40),
    )
    kept, explanation = apply_usage_policy(
        entries,
        vulnerable_unit="github.com/prometheus/common/config",
        caller_role="product_feature",
        runs_vulnerable_code=[
            "github.com/prometheus/common/config",
            "prometheus",
        ],
        importer_only=["github.com/prometheus/common"],
        candidates=candidates,
        explanation="Catalog soft-label baseline for prometheus common.",
    )
    names = [row.name for row in kept]
    assert "github.com/prometheus/common" not in names
    assert "github.com/prometheus/common/config" in names
    assert "prometheus" in names
    assert "5000 builds" in explanation
    assert "do not run" in explanation.casefold() or "omitted" in explanation.casefold()


def test_usage_policy_keeps_small_importer_as_notaffected():
    """Usage policy keeps small importer as notaffected."""
    entries = [
        ManifestComponentEntry(
            name="github.com/prometheus/common/config",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
    ]
    candidates = _usage_candidates(
        (
            "github.com/prometheus/common/config",
            "golang",
            "seed",
            "github.com/prometheus/common/config",
            12,
        ),
        ("small-metrics-importer", "golang", "drop_hint", None, 40),
    )
    kept, explanation = apply_usage_policy(
        entries,
        vulnerable_unit="github.com/prometheus/common/config",
        caller_role="product_feature",
        runs_vulnerable_code=["github.com/prometheus/common/config"],
        importer_only=["small-metrics-importer"],
        candidates=candidates,
        explanation="Kept the patched config submodule.",
    )
    by_name = {row.name: row for row in kept}
    assert "github.com/prometheus/common/config" in by_name
    assert by_name["small-metrics-importer"].affectedness == "NOTAFFECTED"
    assert by_name["small-metrics-importer"].ecosystem == "golang"
    assert "NOTAFFECTED" in explanation
    assert "40 builds" in explanation


def test_usage_policy_confirms_server_build_missing_from_prefetch():
    """Usage policy confirms server build missing from prefetch."""
    entries = [
        ManifestComponentEntry(
            name="github.com/prometheus/common/config",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
    ]
    candidates = _usage_candidates(
        (
            "github.com/prometheus/common/config",
            "golang",
            "seed",
            "github.com/prometheus/common/config",
            12,
        ),
    )

    def confirm(name: str):
        from aegis_ai.features.cve.downstream import CatalogHit

        if name == "prometheus":
            return [CatalogHit("prometheus", "rpm", 40)]
        return []

    kept, _explanation = apply_usage_policy(
        entries,
        vulnerable_unit="github.com/prometheus/common/config",
        caller_role="product_feature",
        runs_vulnerable_code=[
            "github.com/prometheus/common/config",
            "prometheus",
            "invented-server",
        ],
        importer_only=[],
        candidates=candidates,
        explanation="Usage kept the config submodule and prometheus server.",
        confirm_name=confirm,
    )
    names = [row.name for row in kept]
    assert "github.com/prometheus/common/config" in names
    assert "prometheus" in names
    assert "invented-server" not in names


def test_promote_reference_caller_leaves_rpm_prometheus():
    """Promote reference caller leaves rpm prometheus."""
    entries = [
        ManifestComponentEntry(
            name="github.com/openshift-priv/prometheus",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
        ManifestComponentEntry(
            name="prometheus",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
        ManifestComponentEntry(
            name="prometheus3.13",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
        ManifestComponentEntry(
            name="prometheus3.5",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
    ]
    flaw = {
        "components": ["github.com/prometheus/common"],
        "references": [
            {"url": "https://github.com/prometheus/common/pull/901"},
            {
                "url": (
                    "https://github.com/prometheus/prometheus/blob/"
                    "v3.15.1/storage/remote/client.go#L205-L216"
                )
            },
        ],
    }

    def confirm(name: str):
        if name == "github.com/prometheus/prometheus":
            return [CatalogHit(name, "golang", 30)]
        return []

    promoted, note = promote_reference_caller_modules(
        entries,
        flaw,
        ["github.com/prometheus/common"],
        confirm,
    )
    promoted = drop_short_segments_of_kept_modules(promoted)
    names = [row.name for row in promoted]
    assert names == [
        "github.com/openshift-priv/prometheus",
        "prometheus",
        "prometheus3.13",
        "prometheus3.5",
    ]
    assert note == ""


def test_promote_reference_caller_replaces_ecosystem_shorthand():
    """Promote reference caller replaces ecosystem shorthand."""
    entries = [
        ManifestComponentEntry(
            name="rclone",
            ecosystem="golang",
            affectedness="AFFECTED",
        ),
    ]
    flaw = {
        "components": ["some-other-seed"],
        "references": [{"url": "https://github.com/rclone/rclone"}],
    }

    def confirm(name: str):
        if name == "github.com/rclone/rclone":
            return [CatalogHit(name, "golang", 10)]
        return []

    promoted, note = promote_reference_caller_modules(
        entries,
        flaw,
        ["some-other-seed"],
        confirm,
    )
    assert [row.name for row in promoted] == ["github.com/rclone/rclone"]
    assert promoted[0].ecosystem == "golang"
    assert "github.com/rclone/rclone" in note


def test_promote_reference_caller_keeps_short_name_when_module_is_absent():
    """Promote reference caller keeps short name when module is absent."""
    entries = [
        ManifestComponentEntry(
            name="prometheus",
            build_type="rpm",
            affectedness="AFFECTED",
        )
    ]
    flaw = {
        "references": [{"url": "https://github.com/prometheus/prometheus"}],
    }
    promoted, note = promote_reference_caller_modules(
        entries,
        flaw,
        ["github.com/prometheus/common"],
        lambda _name: [],
    )
    assert [row.name for row in promoted] == ["prometheus"]
    assert note == ""


def test_promote_reference_caller_ignores_seed_module():
    """Promote reference caller ignores seed module."""
    entries = [
        ManifestComponentEntry(
            name="common",
            build_type="rpm",
            affectedness="AFFECTED",
        )
    ]
    flaw = {
        "references": [{"url": "https://github.com/prometheus/common/pull/901"}],
    }
    promoted, note = promote_reference_caller_modules(
        entries,
        flaw,
        ["github.com/prometheus/common"],
        lambda name: [CatalogHit(name, "golang", 10)],
    )
    assert [row.name for row in promoted] == ["common"]
    assert note == ""


def test_drop_short_segment_when_full_module_is_kept():
    """Drop short segment when full module is kept."""
    entries = [
        ManifestComponentEntry(
            name="github.com/rclone/rclone",
            ecosystem="golang",
        ),
        ManifestComponentEntry(name="rclone", ecosystem="golang"),
        ManifestComponentEntry(name="prometheus", build_type="rpm"),
        ManifestComponentEntry(
            name="github.com/openshift-priv/prometheus",
            ecosystem="golang",
        ),
        ManifestComponentEntry(name="prometheus3.13", build_type="rpm"),
    ]
    kept = drop_short_segments_of_kept_modules(entries)
    assert [row.name for row in kept] == [
        "github.com/rclone/rclone",
        "prometheus",
        "github.com/openshift-priv/prometheus",
        "prometheus3.13",
    ]


def test_usage_policy_every_importer_keeps_high_build_count_unit():
    """Usage policy every importer keeps high build count unit."""
    entries = [
        ManifestComponentEntry(
            name="openssl",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
    ]
    candidates = _usage_candidates(
        ("openssl", "rpm", "seed", "openssl", 7000),
    )
    kept, explanation = apply_usage_policy(
        entries,
        vulnerable_unit="openssl",
        caller_role="every_importer",
        runs_vulnerable_code=["openssl"],
        importer_only=[],
        candidates=candidates,
        explanation="OpenSSL API is the vulnerable unit for every importer.",
    )
    assert [row.name for row in kept] == ["openssl"]
    assert kept[0].affectedness == "AFFECTED"
    assert explanation == "OpenSSL API is the vulnerable unit for every importer."


def test_check_output_retries_high_count_name_off_runs_list():
    """Check output retries high count name off runs list."""
    from aegis_ai.features.cve import SuggestManifestComponentAndState
    from aegis_ai.features.cve.downstream import DownstreamCandidates

    class _Agent:
        name = "RHFeatureAgent"

    feature = SuggestManifestComponentAndState(agent=_Agent())
    feature._downstream_candidates = DownstreamCandidates(
        candidates=_usage_candidates(
            ("github.com/prometheus/common", "golang", "seed", None, 5000),
            (
                "github.com/prometheus/common/config",
                "golang",
                "drop_hint",
                None,
                12,
            ),
        )
    )
    output = SuggestManifestComponentAndStateModel(
        cve_id="CVE-2026-119566",
        manifest_components=[
            ManifestComponentEntry(
                name="github.com/prometheus/common",
                ecosystem="golang",
                affectedness="AFFECTED",
            ),
            ManifestComponentEntry(
                name="github.com/prometheus/common/config",
                ecosystem="golang",
                affectedness="AFFECTED",
            ),
        ],
        usage=ManifestUsageAnalysis(
            vulnerable_unit="github.com/prometheus/common/config",
            caller_role="product_feature",
            runs_vulnerable_code=["github.com/prometheus/common/config"],
            importer_only=[],
        ),
        explanation="Incomplete usage classification.",
        confidence=0.8,
        data_quality=0.9,
        tools_used=[],
        disclaimer=(
            "This response was generated by Aegis AI "
            "(https://github.com/RedHatProductSecurity/aegis-ai) using "
            "generative AI for informational purposes. All findings should "
            "be validated by a human expert."
        ),
    )
    retry = feature._check_output(type("Result", (), {"output": output})(), deps=None)
    assert retry is not None
    assert "github.com/prometheus/common" in retry
    assert "runs_vulnerable_code" in retry


def test_build_count_is_carried_on_candidates():
    """Build count is carried on candidates."""
    gathered, _seen = _collect_candidates(
        {"components": ["openssl"], "title": "openssl"},
        components={"openssl": ["rpm"]},
    )
    # Mock without build_count leaves None; exercise the field presence.
    assert gathered.candidates
    assert all(hasattr(hit, "build_count") for hit in gathered.candidates)

    def get_json(url: str):
        parsed = urllib.parse.urlsplit(url)
        query = urllib.parse.parse_qs(parsed.query)
        if parsed.path.startswith("/api/v0alpha/components"):
            requested = query["name"][0]
            if requested.casefold() == "openssl" or _glob_match(requested, "openssl"):
                return {
                    "data": [
                        {"name": "openssl", "type": "rpm", "build_count": 4200},
                    ],
                    "total": 1,
                }
            return {"data": [], "total": 0}
        if parsed.path.startswith("/api/v2/projects"):
            return {"items": [], "total_items": 0}
        return {"data": []}

    gathered = collect_downstream_candidates(
        {"components": ["openssl"], "title": "openssl"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url="",
        anitya_url=ANITYA,
    )
    assert gathered.build_counts()["openssl"] == 4200


def test_downstream_feature_context_str_includes_candidates():
    """Downstream feature context str includes candidates."""
    from aegis_ai.features.cve.data_models import DownstreamFeatureContext
    from aegis_ai.prompt import AegisPrompt

    context = DownstreamFeatureContext(
        cve_id="CVE-2026-90439",
        flaw_components=["nginx"],
        advisory_text="nginx before 1.26",
        downstream_candidates={
            "candidates": [
                {"name": "nginx", "type": "rpm", "soft_label": "seed"},
            ],
        },
        soft_label_baseline=[{"name": "nginx", "build_type": "rpm"}],
    )
    assert "nginx" in str(context)
    assert "DownstreamFeatureContext(cve_id=" in repr(context)
    prompt = AegisPrompt(
        user_instruction="Map seeds.",
        goals="Keep same-project names.",
        rules="Do not invent names.",
        context=context,
    )
    assert "nginx" in prompt.to_string()
    assert "advisory_text" in prompt.to_string()


def test_prerelease_orders_before_final_release():
    """Prerelease orders before final release."""
    from aegis_ai.features.cve.downstream import (
        VersionBound,
        _decide_affectedness,
        _version_compare,
        _version_key,
    )

    assert _version_compare(_version_key("1.2.0rc1"), _version_key("1.2.0")) < 0
    assert _version_compare(_version_key("1.2.0"), _version_key("1.2.0.1")) < 0
    assert _version_compare(_version_key("1.2.0"), _version_key("1.2.0")) == 0
    # Prerelease below a final-release last_affected stays AFFECTED.
    assert (
        _decide_affectedness(["1.2.0rc1"], [VersionBound(None, None, "1.2.0")])
        == "AFFECTED"
    )
    assert (
        _decide_affectedness(["1.2.0"], [VersionBound(None, "1.2.0", None)])
        == "NOTAFFECTED"
    )


def test_leading_v_is_stripped_in_version_compare():
    """Leading v is stripped in version compare."""
    from aegis_ai.features.cve.downstream import VersionBound, _decide_affectedness

    assert (
        _decide_affectedness(["1.2.0"], [VersionBound("v1.0.0", "v2.0.0", None)])
        == "AFFECTED"
    )


def test_not_affected_through_is_ignored():
    """Not affected through is ignored."""
    from aegis_ai.features.cve.downstream import (
        VersionBound,
        _advisory_bounds,
        _decide_affectedness,
    )

    bounds = _advisory_bounds("nginx is not affected through 3.15.1.")
    assert bounds == []
    assert (
        _decide_affectedness(
            ["3.14.0"],
            _advisory_bounds("Prometheus through 3.15.1 contains a credential leak."),
        )
        == "AFFECTED"
    )
    # Sanity: an explicit bound still works when not negated.
    assert any(
        isinstance(bound, VersionBound) and bound.last_affected == "3.15.1"
        for bound in _advisory_bounds(
            "Prometheus through 3.15.1 contains a credential leak."
        )
    )


def test_osv_skips_git_ranges_and_scopes_packages():
    """Osv skips git ranges and scopes packages."""
    from aegis_ai.features.cve.downstream import _osv_bounds

    upstream = {
        "affected": [
            {
                "package": {"name": "github.com/foo/bar", "ecosystem": "Go"},
                "ranges": [
                    {
                        "type": "GIT",
                        "events": [
                            {"introduced": "abc123"},
                            {"fixed": "def456"},
                        ],
                    },
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "1.0.0"},
                            {"fixed": "1.2.0"},
                        ],
                    },
                ],
            },
            {
                "package": {"name": "other", "ecosystem": "Go"},
                "ranges": [
                    {
                        "type": "SEMVER",
                        "events": [
                            {"introduced": "9.0.0"},
                            {"fixed": "9.9.9"},
                        ],
                    },
                ],
            },
        ]
    }
    assert _osv_bounds(upstream)  # global merge still sees SEMVER
    scoped = _osv_bounds(upstream, package_name="github.com/foo/bar")
    assert len(scoped) == 1
    assert scoped[0].introduced == "1.0.0"
    assert scoped[0].fixed == "1.2.0"
    assert _osv_bounds(upstream, package_name="missing") == []


def test_error_json_bomq_payload_marks_catalog_unavailable():
    """Error json bomq payload marks catalog unavailable."""

    def get_json(_url):
        return {"error": "unavailable"}

    gathered = collect_downstream_candidates(
        {"components": ["nginx"], "title": "nginx"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
    )
    assert gathered.catalog_unavailable is True
    assert gathered.candidates == []


def test_primary_fail_empty_community_marks_catalog_unavailable():
    """Primary fail empty community marks catalog unavailable."""

    def get_json(url: str):
        if url.startswith(PRIMARY):
            return None
        if "/api/v2/projects/" in url:
            return {"items": [], "total_items": 0}
        return {"data": [], "total": 0}

    gathered = collect_downstream_candidates(
        {"components": ["nginx"], "title": "nginx"},
        get_json=get_json,
        bomq_url=PRIMARY,
        bomq_community_url=COMMUNITY,
        anitya_url=ANITYA,
    )
    assert gathered.catalog_unavailable is True
    assert gathered.candidates == []


def test_usage_policy_restores_confirmed_name_for_every_importer():
    """Usage policy restores confirmed name for every importer."""
    from aegis_ai.features.cve.downstream import CatalogHit

    entries = [
        ManifestComponentEntry(
            name="prometheus",
            build_type="rpm",
            affectedness="AFFECTED",
        ),
    ]
    candidates = _usage_candidates(("prometheus", "rpm", "seed", "prometheus", 40))

    def confirm(name: str):
        if name == "github.com/openshift-priv/prometheus":
            return [CatalogHit(name, "golang", 4)]
        return []

    kept, _ = apply_usage_policy(
        entries,
        vulnerable_unit="prometheus",
        caller_role="every_importer",
        runs_vulnerable_code=[
            "prometheus",
            "github.com/openshift-priv/prometheus",
        ],
        importer_only=[],
        candidates=candidates,
        explanation="Server packaging runs the bug.",
        confirm_name=confirm,
    )
    assert [row.name for row in kept] == [
        "prometheus",
        "github.com/openshift-priv/prometheus",
    ]


def test_usage_policy_keeps_rpm_when_rhcos_companion_present():
    """Usage policy keeps rpm when rhcos companion present."""
    entries = [
        ManifestComponentEntry(name="nginx", build_type="rpm", affectedness="AFFECTED"),
        ManifestComponentEntry(name="nginx", rhcos="rpm", affectedness="AFFECTED"),
    ]
    candidates = _usage_candidates(("nginx", "rpm", "seed", "nginx", 10))
    kept, _ = apply_usage_policy(
        entries,
        vulnerable_unit="nginx",
        caller_role="product_feature",
        runs_vulnerable_code=["nginx"],
        importer_only=[],
        candidates=candidates,
        explanation="nginx RPM runs the bug.",
    )
    assert len(kept) == 2
    assert kept[0].build_type == "rpm"
    assert kept[1].rhcos == "rpm"


def test_promote_reference_does_not_copy_short_row_verdict():
    """Promote reference does not copy short row verdict."""
    entries = [
        ManifestComponentEntry(
            name="rclone",
            ecosystem="golang",
            affectedness="AFFECTED",
            evidence="1.2.0",
        ),
    ]
    flaw = {
        "components": ["other"],
        "references": [{"url": "https://github.com/rclone/rclone"}],
    }

    def confirm(name: str):
        if name == "github.com/rclone/rclone":
            return [CatalogHit(name, "golang", 10)]
        return []

    promoted, _note = promote_reference_caller_modules(
        entries,
        flaw,
        ["other"],
        confirm,
    )
    assert [row.name for row in promoted] == ["github.com/rclone/rclone"]
    assert promoted[0].affectedness == "UNKNOWN"
    assert promoted[0].evidence is None


@pytest.mark.asyncio
async def test_downstream_flaw_merges_partial_static_context(monkeypatch):
    """Downstream flaw merges partial static context."""
    from aegis_ai.features.cve import _downstream_flaw

    class _Flaw:
        def model_dump(self):
            return {
                "cve_id": "CVE-2026-90439",
                "components": ["nginx"],
                "title": "full title",
                "comment_zero": "full comment",
                "description": "full description",
                "cve_description": "",
                "statement": "",
                "references": [{"url": "https://example.com"}],
                "upstream_data": {"affected": []},
            }

    async def fake_retrieve(cve_id):
        return _Flaw()

    monkeypatch.setattr(
        "aegis_ai.features.cve.osidb_tool.cve_retrieve",
        fake_retrieve,
    )
    merged = await _downstream_flaw(
        "CVE-2026-90439",
        {"title": "caller title"},
    )
    assert merged["title"] == "caller title"
    assert merged["components"] == ["nginx"]
    assert merged["references"] == [{"url": "https://example.com"}]
    assert merged["upstream_data"] == {"affected": []}


def test_filter_bomq_v0alpha_components_keeps_catalog_fields():
    """Filter bomq v0alpha components keeps catalog fields."""
    url = f"{PRIMARY}/api/v0alpha/components?name=openssl&group_by=name"
    payload = {
        "data": [
            {
                "name": "openssl",
                "type": "rpm",
                "build_count": 12,
                "purl": "pkg:rpm/openssl",
                "version": "1.0",
                "arch": "x86_64",
            }
        ],
        "total": 1,
        "count": 1,
        "limit": 100,
        "offset": 0,
    }
    filtered = filter_bomq_response(url, payload)
    assert filtered == {
        "data": [{"name": "openssl", "type": "rpm", "build_count": 12}],
        "total": 1,
    }


def test_filter_bomq_search_builds_keeps_version_fields():
    """Filter bomq search builds keeps version fields."""
    url = f"{PRIMARY}/api/v0/search/builds?name=curl&strict=true"
    payload = {
        "data": [
            {
                "stream_name": "rhel-9.4.0",
                "module": "rhel",
                "build_name": "curl",
                "build_version": "8.0.1",
                "build_nvr": "curl-8.0.1-1.el9",
                "build_type": "rpm",
                "purl": "pkg:rpm/curl",
            },
            {"version": "7.9.0", "build_nvr": "curl-7.9.0-1"},
        ],
        "count": 2,
    }
    filtered = filter_bomq_response(url, payload)
    assert filtered == {
        "data": [{"build_version": "8.0.1"}, {"version": "7.9.0"}],
    }


def test_filter_bomq_search_components_keeps_nested_version_fields():
    """Filter bomq search components keeps nested version fields."""
    url = (
        f"{PRIMARY}/api/v0/search/components"
        "?name=github.com%2Fprometheus%2Fcommon&strict=true&include_types=golang"
    )
    payload = {
        "data": [
            {
                "stream_name": "openshift-4.16",
                "module": "ocp",
                "build_name": "prometheus",
                "build_version": "2.0",
                "build_nvr": "prometheus-2.0-1",
                "build_type": "container",
                "purl": "pkg:oci/prometheus",
                "sources": [
                    {
                        "source": "git",
                        "hash": "abc",
                        "components": [
                            {
                                "name": "github.com/prometheus/common",
                                "type": "golang",
                                "version": "0.45.0",
                                "nvr": "unused",
                                "dev": False,
                                "origin": "bundled",
                            }
                        ],
                    }
                ],
            }
        ],
        "count": 1,
    }
    filtered = filter_bomq_response(url, payload)
    assert filtered == {
        "data": [
            {
                "build_name": "prometheus",
                "sources": [
                    {
                        "components": [
                            {
                                "name": "github.com/prometheus/common",
                                "type": "golang",
                                "version": "0.45.0",
                            }
                        ]
                    }
                ],
            }
        ]
    }


def test_filter_bomq_leaves_anitya_and_errors_unchanged():
    """Filter bomq leaves anitya and errors unchanged."""
    anitya = {"items": [{"id": 1, "name": "vim"}], "total_items": 1}
    assert filter_bomq_response(f"{ANITYA}/api/v2/projects/?name=vim", anitya) is anitya
    error = {"error": "boom"}
    assert (
        filter_bomq_response(f"{PRIMARY}/api/v0/search/components?name=x", error)
        is error
    )


def test_filter_anitya_projects_keeps_mapping_fields():
    """Filter anitya projects keeps mapping fields."""
    url = f"{ANITYA}/api/v2/projects/?name=vim&page=1&items_per_page=100"
    payload = {
        "items": [
            {
                "name": "vim",
                "id": 5092,
                "backend": "GitHub",
                "homepage": "https://www.vim.org",
                "ecosystem": "https://www.vim.org",
                "versions": ["9.1.0000", "9.0.0000"],
                "stable_versions": ["9.1.0000"],
                "regex": None,
            }
        ],
        "total_items": 1,
        "page": 1,
        "items_per_page": 100,
    }
    filtered = filter_anitya_response(url, payload)
    assert filtered == {
        "items": [
            {
                "name": "vim",
                "id": 5092,
                "backend": "GitHub",
                "homepage": "https://www.vim.org",
                "ecosystem": "https://www.vim.org",
            }
        ],
        "total_items": 1,
    }


def test_filter_anitya_project_keeps_package_fields():
    """Filter anitya project keeps package fields."""
    url = f"{ANITYA}/api/project/5413"
    payload = {
        "id": 5413,
        "name": "nginx",
        "backend": "GitHub",
        "homepage": "https://nginx.org",
        "ecosystem": "https://nginx.org",
        "versions": ["1.25.0", "1.24.0"],
        "stable_versions": ["1.24.0"],
        "packages": [
            {
                "distro": "Fedora",
                "package_name": "nginx",
                "extra": "drop-me",
            },
            {
                "distro": "Debian",
                "package_name": "nginx",
            },
        ],
    }
    filtered = filter_anitya_response(url, payload)
    assert filtered == {
        "packages": [
            {"distro": "Fedora", "package_name": "nginx"},
            {"distro": "Debian", "package_name": "nginx"},
        ]
    }


def test_filter_anitya_leaves_bomq_and_errors_unchanged():
    """Filter anitya leaves bomq and errors unchanged."""
    bomq = {"data": [{"name": "openssl", "type": "rpm"}], "total": 1}
    assert (
        filter_anitya_response(f"{PRIMARY}/api/v0alpha/components?name=openssl", bomq)
        is bomq
    )
    error = {"error": "boom"}
    assert filter_anitya_response(f"{ANITYA}/api/v2/projects/?name=x", error) is error


def test_http_get_json_filters_bomq_search_components():
    """Http get json filters bomq search components."""
    body = {
        "data": [
            {
                "build_name": "pkg",
                "stream_name": "rhel-9",
                "sources": [
                    {
                        "hash": "deadbeef",
                        "components": [
                            {
                                "name": "libx",
                                "type": "rpm",
                                "version": "1.2.3",
                                "nvr": "libx-1.2.3-1",
                            }
                        ],
                    }
                ],
            }
        ],
        "count": 1,
    }
    response = MagicMock()
    response.read.return_value = json.dumps(body).encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = False

    with patch(
        "aegis_ai.features.cve.downstream.urllib.request.urlopen",
        return_value=response,
    ):
        result = http_get_json(
            f"{PRIMARY}/api/v0/search/components?name=libx&strict=true&include_types=rpm"
        )

    assert result == {
        "data": [
            {
                "build_name": "pkg",
                "sources": [
                    {
                        "components": [
                            {"name": "libx", "type": "rpm", "version": "1.2.3"}
                        ]
                    }
                ],
            }
        ]
    }


def test_http_get_json_filters_anitya_projects():
    """Http get json filters anitya projects."""
    body = {
        "items": [
            {
                "name": "vim",
                "id": 5092,
                "backend": "GitHub",
                "homepage": "https://www.vim.org",
                "ecosystem": "https://www.vim.org",
                "versions": ["9.1.0000"],
                "stable_versions": ["9.1.0000"],
            }
        ],
        "total_items": 1,
        "page": 1,
        "items_per_page": 100,
    }
    response = MagicMock()
    response.read.return_value = json.dumps(body).encode("utf-8")
    response.__enter__.return_value = response
    response.__exit__.return_value = False

    with patch(
        "aegis_ai.features.cve.downstream.urllib.request.urlopen",
        return_value=response,
    ):
        result = http_get_json(
            "https://release-monitoring.org/api/v2/projects/?name=vim&page=1&items_per_page=100"
        )

    assert result == {
        "items": [
            {
                "name": "vim",
                "id": 5092,
                "backend": "GitHub",
                "homepage": "https://www.vim.org",
                "ecosystem": "https://www.vim.org",
            }
        ],
        "total_items": 1,
    }
