import pytest

from aegis_ai.toolsets.tools.external_references import (
    ALLOWED_HOSTS,
    MAX_CONTENT_LENGTH,
    MAX_READ_BYTES,
    ExternalReferenceResult,
    _filter_cve_org_json,
    _normalize_cve_org_url,
    _sanitize_pii,
    _strip_github_chrome,
    _truncate,
    cache_key_for_url,
    extract_text_from_html,
    fetch_reference,
    validate_url,
)


class TestValidateUrl:
    def test_allowed_host(self):
        assert validate_url("https://www.cve.org/CVERecord?id=CVE-2025-0725")

    def test_allowed_github(self):
        assert validate_url("https://github.com/tektoncd/pipeline/security/advisories/GHSA-94jr-7pqp-xhcq")

    def test_blocked_host(self):
        assert not validate_url("https://evil.example.com/malware")

    def test_http_rejected(self):
        assert not validate_url("http://www.cve.org/CVERecord?id=CVE-2025-0725")

    def test_no_scheme(self):
        assert not validate_url("www.cve.org/CVERecord?id=CVE-2025-0725")

    def test_empty_string(self):
        assert not validate_url("")

    def test_all_allowed_hosts_are_lowercase(self):
        for host in ALLOWED_HOSTS:
            assert host == host.lower(), f"Host {host} should be lowercase"


class TestNormalizeCveOrgUrl:
    def test_standard_url(self):
        url = "https://www.cve.org/CVERecord?id=CVE-2025-0725"
        assert _normalize_cve_org_url(url) == "https://cveawg.mitre.org/api/cve/CVE-2025-0725"

    def test_non_cve_org(self):
        assert _normalize_cve_org_url("https://github.com/foo/bar") is None

    def test_wrong_path(self):
        assert _normalize_cve_org_url("https://www.cve.org/OtherPage?id=CVE-2025-0725") is None

    def test_missing_id_param(self):
        assert _normalize_cve_org_url("https://www.cve.org/CVERecord") is None


class TestFilterCveOrgJson:
    def test_extracts_descriptions(self):
        data = {
            "containers": {
                "cna": {
                    "descriptions": [{"lang": "en", "value": "A flaw was found..."}],
                }
            }
        }
        result = _filter_cve_org_json(data)
        assert result["descriptions"] == [{"lang": "en", "value": "A flaw was found..."}]

    def test_extracts_metrics(self):
        metrics = [{"cvssV3_1": {"vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}}]
        data = {"containers": {"cna": {"metrics": metrics}}}
        result = _filter_cve_org_json(data)
        assert result["metrics"] == metrics

    def test_extracts_affected_products(self):
        data = {
            "containers": {
                "cna": {
                    "affected": [
                        {
                            "vendor": "curl",
                            "product": "curl",
                            "versions": [{"version": "8.0"}],
                            "defaultStatus": "unaffected",
                            "extra_field": "should be dropped",
                        }
                    ]
                }
            }
        }
        result = _filter_cve_org_json(data)
        assert len(result["affected"]) == 1
        assert "extra_field" not in result["affected"][0]
        assert result["affected"][0]["vendor"] == "curl"

    def test_empty_cna(self):
        assert _filter_cve_org_json({"containers": {"cna": {}}}) == {}

    def test_no_containers(self):
        assert _filter_cve_org_json({}) == {}


class TestExtractTextFromHtml:
    def test_simple_html(self):
        html = "<html><body><p>Hello world</p></body></html>"
        assert "Hello world" in extract_text_from_html(html)

    def test_strips_script_and_style(self):
        html = "<script>alert('xss')</script><style>.foo{}</style><p>Content</p>"
        text = extract_text_from_html(html)
        assert "alert" not in text
        assert ".foo" not in text
        assert "Content" in text

    def test_preserves_line_breaks(self):
        html = "<p>First</p><p>Second</p>"
        text = extract_text_from_html(html)
        assert "First" in text
        assert "Second" in text

    def test_empty_html(self):
        assert extract_text_from_html("") == ""


class TestTruncate:
    def test_short_text_unchanged(self):
        assert _truncate("hello") == "hello"

    def test_long_text_truncated(self):
        text = "x" * (MAX_CONTENT_LENGTH + 100)
        result = _truncate(text)
        assert len(result) <= MAX_CONTENT_LENGTH
        assert result.endswith("[... truncated]")

    def test_exact_limit_unchanged(self):
        text = "x" * MAX_CONTENT_LENGTH
        assert _truncate(text) == text


class TestStripGithubChrome:
    def test_strips_session_notices(self):
        text = (
            "Skip to content\n\n"
            "You signed in with another tab or window. Reload to refresh your session.\n"
            "You signed out in another tab or window. Reload to refresh your session.\n"
            "Dismiss alert\n\n"
            "{{ message }}\n\n"
            "Actual content here"
        )
        assert _strip_github_chrome(text) == "Actual content here"

    def test_strips_file_tree_chrome(self):
        text = (
            "Expand file treeCollapse file tree\n"
            "Open diff view settings\n"
            "Filter options\n"
            "Collapse file\n"
            "Copy file name to clipboardExpand all lines: foo.py\n"
            "Original file line numberDiff line numberDiff line change\n"
            "@@ -1,3 +1,4 @@ def main():"
        )
        assert "@@ -1,3 +1,4 @@ def main():" in _strip_github_chrome(text)
        assert "Expand file tree" not in _strip_github_chrome(text)

    def test_preserves_real_content(self):
        text = "Fix buffer overflow in parse_header\n\nSigned-off-by: Dev"
        assert _strip_github_chrome(text) == text

    def test_empty_string(self):
        assert _strip_github_chrome("") == ""


class TestSanitizePii:
    def test_replaces_email(self):
        assert _sanitize_pii("Contact user@example.com for info") == (
            "Contact [email] for info"
        )

    def test_replaces_multiple_emails(self):
        text = "Signed-off-by: A <a@x.org>\nReviewed-by: B <b@y.com>"
        result = _sanitize_pii(text)
        assert "@" not in result
        assert result.count("[email]") == 2

    def test_no_email_unchanged(self):
        assert _sanitize_pii("no emails here") == "no emails here"

    def test_empty_string(self):
        assert _sanitize_pii("") == ""


class TestReadLimits:
    def test_read_bytes_exceeds_content_length(self):
        assert MAX_READ_BYTES > MAX_CONTENT_LENGTH


class TestCacheKeyForUrl:
    def test_deterministic(self):
        url = "https://www.cve.org/CVERecord?id=CVE-2025-0725"
        assert cache_key_for_url(url) == cache_key_for_url(url)

    def test_different_urls_differ(self):
        assert cache_key_for_url("https://a.com") != cache_key_for_url("https://b.com")

    def test_safe_for_filenames(self):
        key = cache_key_for_url("https://www.cve.org/CVERecord?id=CVE-2025-0725&foo=bar")
        assert all(c.isalnum() for c in key)


class TestFetchReference:
    @pytest.mark.asyncio
    async def test_blocked_url(self):
        result = await fetch_reference("https://evil.example.com/malware")
        assert result.status == "blocked"
        assert result.extracted_text is None

    @pytest.mark.asyncio
    async def test_http_url_blocked(self):
        result = await fetch_reference("http://www.cve.org/CVERecord?id=CVE-2025-0725")
        assert result.status == "blocked"

    @pytest.mark.asyncio
    async def test_returns_result_type(self):
        result = await fetch_reference("https://evil.example.com/foo")
        assert isinstance(result, ExternalReferenceResult)
