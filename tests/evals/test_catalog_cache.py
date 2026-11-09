"""Unit tests for the evals catalog HTTP cache."""

from __future__ import annotations

import base64
import json
from pathlib import Path

import pytest

from evals.utils import catalog_cache


@pytest.fixture(autouse=True)
def _isolate_catalog_cache(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point the cache at a temp dir and reset miss / inflight state."""
    monkeypatch.setattr(catalog_cache, "CACHE_DIR", str(tmp_path))
    monkeypatch.delenv("AEGIS_EVALS_CATALOG_LIVE", raising=False)
    catalog_cache.cache_misses.clear()
    with catalog_cache._cache_lock:
        catalog_cache._inflight.clear()
    yield
    catalog_cache.cache_misses.clear()
    with catalog_cache._cache_lock:
        catalog_cache._inflight.clear()


def test_hit_returns_cached_body(tmp_path: Path):
    url = "https://bomq.example/api/v0alpha/components?name=openssl"
    body = {"data": [{"name": "openssl", "type": "rpm", "build_count": 3}]}
    catalog_cache.write_cache_entry(url, body)

    result = catalog_cache.catalog_cache_retrieve(url)

    assert result == body
    assert catalog_cache.cache_misses == []
    assert (tmp_path / catalog_cache._cache_filename(url)).is_file()


def test_prefetch_miss_raises_when_live_disabled():
    url = "https://bomq.example/api/v0alpha/components?name=missing"

    with pytest.raises(catalog_cache.CatalogCacheMiss) as exc_info:
        catalog_cache.catalog_cache_retrieve(url, deadline=1.0)

    assert exc_info.value.url == url
    assert catalog_cache.cache_misses == []


def test_private_miss_without_deadline_returns_none():
    url = "https://bomq.example/api/v0alpha/components?name=invented"

    result = catalog_cache.catalog_cache_retrieve(
        url, live_fetch=lambda *a, **k: {"data": [{"name": "should-not-run"}]}
    )

    assert result is None
    assert catalog_cache.cache_misses == []


def test_anitya_miss_fetches_when_live_disabled(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("AEGIS_ANITYA_URL", "https://release-monitoring.org")
    url = "https://release-monitoring.org/api/v2/projects/?name=rclone&page=1"
    body = {"items": [{"name": "rclone", "id": 1}], "total_items": 1}
    normalized = "{anitya}/api/v2/projects/?name=rclone&page=1"
    fetches: list[str] = []

    def fake_fetch(fetched_url: str, *, timeout: float = 30.0, deadline=None):
        fetches.append(fetched_url)
        return body

    result = catalog_cache.catalog_cache_retrieve(url, live_fetch=fake_fetch)

    assert result == body
    assert fetches == [url]
    assert catalog_cache.cache_misses == [normalized]
    cached = json.loads(
        (tmp_path / catalog_cache._cache_filename(url)).read_text(encoding="utf-8")
    )
    assert cached == {"url": normalized, "body": body}


def test_live_mode_writes_on_miss(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    monkeypatch.setenv("AEGIS_EVALS_CATALOG_LIVE", "1")
    monkeypatch.setenv("AEGIS_BOMQ_URL", "https://bomq.example")
    url = "https://bomq.example/api/v0alpha/components?name=nginx"
    body = {"data": [{"name": "nginx", "type": "rpm", "build_count": 10}]}
    normalized = "{bomq_primary}/api/v0alpha/components?name=nginx"

    def fake_fetch(fetched_url: str, *, timeout: float = 30.0, deadline=None):
        assert fetched_url == url
        return body

    result = catalog_cache.catalog_cache_retrieve(url, live_fetch=fake_fetch)

    assert result == body
    assert catalog_cache.cache_misses == [normalized]
    cached = json.loads(
        (tmp_path / catalog_cache._cache_filename(url)).read_text(encoding="utf-8")
    )
    assert cached == {"url": normalized, "body": body}


def test_write_cache_entry_stores_role_token_url(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("AEGIS_BOMQ_URL", "https://bomq.example")
    url = "https://bomq.example/api/v0alpha/components?name=openssl"
    body = {"data": []}

    catalog_cache.write_cache_entry(url, body)

    cached = json.loads(
        (tmp_path / catalog_cache._cache_filename(url)).read_text(encoding="utf-8")
    )
    assert cached["url"] == "{bomq_primary}/api/v0alpha/components?name=openssl"
    assert cached["body"] == body


def test_write_misses_report_uses_role_tokens(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("AEGIS_BOMQ_URL", "https://bomq.example")
    catalog_cache.cache_misses.append(
        "https://bomq.example/api/v0alpha/components?name=nginx"
    )

    report = catalog_cache.write_misses_report()

    assert report is not None
    assert report.read_text(encoding="utf-8") == (
        "{bomq_primary}/api/v0alpha/components?name=nginx\n"
    )


def test_live_mode_refuses_localhost(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AEGIS_EVALS_CATALOG_LIVE", "1")
    url = "https://localhost:8080/api/v0alpha/components?name=openssl"

    with pytest.raises(ValueError, match="refusing to record localhost"):
        catalog_cache.catalog_cache_retrieve(
            url, live_fetch=lambda *a, **k: {"data": []}
        )

    assert catalog_cache.cache_misses == []


def test_live_mode_none_body_does_not_write(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("AEGIS_EVALS_CATALOG_LIVE", "1")
    url = "https://bomq.example/api/v0alpha/components?name=gone"

    result = catalog_cache.catalog_cache_retrieve(url, live_fetch=lambda *a, **k: None)

    assert result is None
    assert catalog_cache.cache_misses == []
    assert not (tmp_path / catalog_cache._cache_filename(url)).exists()


def test_get_public_miss_files_filters_anitya(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
):
    monkeypatch.setenv("AEGIS_BOMQ_URL", "https://bomq.example")
    monkeypatch.setenv("AEGIS_ANITYA_URL", "https://release-monitoring.org")
    anitya_url = "https://release-monitoring.org/api/v2/projects/?name=vim"
    bomq_url = "https://bomq.example/api/v0alpha/components?name=openssl"
    catalog_cache.write_cache_entry(anitya_url, {"items": []})
    catalog_cache.write_cache_entry(bomq_url, {"data": []})
    catalog_cache.cache_misses.extend(
        [catalog_cache.normalize_cache_url(anitya_url), bomq_url]
    )

    paths = catalog_cache.get_public_miss_files()

    assert paths == [tmp_path / catalog_cache._cache_filename(anitya_url)]


def test_normalize_maps_configured_hosts(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("AEGIS_BOMQ_URL", "https://bomq.example")
    monkeypatch.setenv("AEGIS_BOMQ_COMMUNITY_URL", "https://community.example")
    monkeypatch.setenv("AEGIS_ANITYA_URL", "https://anitya.example")
    assert (
        catalog_cache.normalize_cache_url(
            "https://bomq.example/api/v0alpha/components?name=x"
        )
        == "{bomq_primary}/api/v0alpha/components?name=x"
    )
    assert (
        catalog_cache.normalize_cache_url(
            "https://community.example/api/v0alpha/components?name=x"
        )
        == "{bomq_community}/api/v0alpha/components?name=x"
    )
    assert (
        catalog_cache.normalize_cache_url("https://anitya.example/api/v2/projects/")
        == "{anitya}/api/v2/projects/"
    )
    # Prod and CI localhost hosts share a key when each matches its configured host.
    prod_key = catalog_cache._cache_filename(
        "https://bomq.example/api/v0alpha/components?name=x"
    )
    monkeypatch.setenv("AEGIS_BOMQ_URL", "https://localhost:8080")
    local_key = catalog_cache._cache_filename(
        "https://localhost:8080/api/v0alpha/components?name=x"
    )
    assert prod_key == local_key


def test_import_evals_cache_accepts_catalog(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    import scripts.import_evals_cache as import_mod

    cache_dir = tmp_path / "catalog_cache"
    monkeypatch.setattr(
        import_mod,
        "CACHE_DIRS",
        {"catalog": cache_dir},
    )
    monkeypatch.setattr(import_mod, "REPO_ROOT", tmp_path)
    body = {
        "url": "{anitya}/api/v2/projects/?name=rclone&page=1",
        "body": {"items": [], "total_items": 0},
    }
    payload = json.dumps(body, indent=4) + "\n"
    filename = "abc123.json"
    log_line = (
        f"[cache-dump] type=catalog file={filename} "
        f"base64={base64.b64encode(payload.encode()).decode()}\n"
    )
    log_path = tmp_path / "ci.log"
    log_path.write_text(log_line, encoding="utf-8")
    monkeypatch.setattr(
        import_mod.sys,
        "argv",
        ["import_evals_cache.py", str(log_path)],
    )

    import_mod.main()

    written = cache_dir / filename
    assert written.is_file()
    assert json.loads(written.read_text(encoding="utf-8")) == body
