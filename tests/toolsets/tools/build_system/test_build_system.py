import json
from unittest.mock import MagicMock, patch

import koji
import pytest

from aegis_ai.toolsets.tools.build_system import (
    _create_brew_session,
    _fetch_deptopia_builds,
    _list_binary_rpms,
    _lookup_binary_rpms,
    _lookup_binary_rpms_batch,
    _resolve_build_from_stream,
    _resolve_build_id,
)


@pytest.fixture
def mock_koji_session():
    return MagicMock()


@pytest.fixture
def deptopia_response():
    """Deptopia API response with one matching build."""
    return {
        "Builds": [
            {
                "build_nvr": "curl-8.6.0-3.el9",
                "ps_update_stream": "rhel-9.6.0.z",
            },
            {
                "build_nvr": "curl-7.76.1-29.el8_10",
                "ps_update_stream": "rhel-8.10.0.z",
            },
        ]
    }


@pytest.fixture
def koji_rpms():
    """Koji listRPMs response with source and binary RPMs."""
    return [
        {"name": "curl", "arch": "x86_64"},
        {"name": "curl-minimal", "arch": "x86_64"},
        {"name": "libcurl", "arch": "x86_64"},
        {"name": "libcurl-devel", "arch": "x86_64"},
        {"name": "curl", "arch": "aarch64"},
        {"name": "libcurl", "arch": "aarch64"},
        {"name": "curl", "arch": "src"},
        {"name": "curl-debuginfo", "arch": "x86_64"},
        {"name": "curl-debugsource", "arch": "x86_64"},
        {"name": "glibc-all-langpacks", "arch": "x86_64"},
        {"name": "glibc-langpack-en", "arch": "x86_64"},
        {"name": "glibc-langpack-de", "arch": "x86_64"},
        {"name": "glibc-debuginfo-common", "arch": "x86_64"},
        {"name": "glibc-minimal-langpack", "arch": "x86_64"},
    ]


class TestCreateBrewSession:
    @patch("aegis_ai.toolsets.tools.build_system.koji")
    def test_creates_session(self, mock_koji_mod):
        mock_koji_mod.read_config.return_value = {"server": "https://brew.example.com"}
        mock_koji_mod.grab_session_options.return_value = {}
        mock_koji_mod.ClientSession.return_value = MagicMock()

        session = _create_brew_session()

        mock_koji_mod.read_config.assert_called_once_with("brew")
        mock_koji_mod.ClientSession.assert_called_once()
        assert session is not None

    @patch("aegis_ai.toolsets.tools.build_system.koji")
    def test_config_error_propagates(self, mock_koji_mod):
        mock_koji_mod.read_config.side_effect = koji.ConfigurationError("no profile")
        mock_koji_mod.ConfigurationError = koji.ConfigurationError

        with pytest.raises(koji.ConfigurationError):
            _create_brew_session()


class TestResolveBuildFromStream:
    def test_happy_path(self, mock_koji_session, deptopia_response):
        mock_koji_session.getBuild.return_value = {"id": 12345}

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(deptopia_response).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _resolve_build_from_stream(
                mock_koji_session, "curl", "rhel-9.6.0.z"
            )

        assert result == (12345, "curl-8.6.0-3.el9")
        mock_koji_session.getBuild.assert_called_once_with("curl-8.6.0-3.el9")

    def test_no_matching_stream(self, mock_koji_session, deptopia_response):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(deptopia_response).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _resolve_build_from_stream(mock_koji_session, "curl", "rhel-7.9.z")

        assert result is None

    def test_nvr_not_found_in_koji(self, mock_koji_session, deptopia_response):
        mock_koji_session.getBuild.return_value = None

        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(deptopia_response).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _resolve_build_from_stream(
                mock_koji_session, "curl", "rhel-9.6.0.z"
            )

        assert result is None

    def test_empty_builds(self, mock_koji_session):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"Builds": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            result = _resolve_build_from_stream(
                mock_koji_session, "curl", "rhel-9.6.0.z"
            )

        assert result is None


class TestFetchDeptopiaBuilds:
    def test_returns_builds(self, deptopia_response):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps(deptopia_response).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            builds = _fetch_deptopia_builds("curl")

        assert len(builds) == 2
        assert builds[0]["build_nvr"] == "curl-8.6.0-3.el9"

    def test_empty_response(self):
        with patch("urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.read.return_value = json.dumps({"Builds": []}).encode()
            mock_resp.__enter__ = lambda s: s
            mock_resp.__exit__ = MagicMock(return_value=False)
            mock_urlopen.return_value = mock_resp

            builds = _fetch_deptopia_builds("curl")

        assert builds == []


class TestResolveBuildId:
    def test_happy_path(self, mock_koji_session, deptopia_response):
        mock_koji_session.getBuild.return_value = {"id": 12345}

        result = _resolve_build_id(
            mock_koji_session, deptopia_response["Builds"], "rhel-9.6.0.z"
        )

        assert result == (12345, "curl-8.6.0-3.el9")

    def test_no_matching_stream(self, mock_koji_session, deptopia_response):
        result = _resolve_build_id(
            mock_koji_session, deptopia_response["Builds"], "rhel-7.9.z"
        )

        assert result is None

    def test_nvr_not_found_in_koji(self, mock_koji_session, deptopia_response):
        mock_koji_session.getBuild.return_value = None

        result = _resolve_build_id(
            mock_koji_session, deptopia_response["Builds"], "rhel-9.6.0.z"
        )

        assert result is None


class TestListBinaryRPMs:
    def test_filters_source_rpms(self, mock_koji_session, koji_rpms):
        mock_koji_session.listRPMs.return_value = koji_rpms

        result = _list_binary_rpms(mock_koji_session, 12345)

        assert "curl" in result
        assert "libcurl" in result
        assert "libcurl-devel" in result
        assert "curl-minimal" in result
        assert result == sorted(result)
        mock_koji_session.listRPMs.assert_called_once_with(buildID=12345)

    def test_deduplicates_across_arches(self, mock_koji_session, koji_rpms):
        mock_koji_session.listRPMs.return_value = koji_rpms

        result = _list_binary_rpms(mock_koji_session, 12345)

        assert result.count("curl") == 1
        assert result.count("libcurl") == 1

    def test_filters_noisy_rpms(self, mock_koji_session, koji_rpms):
        mock_koji_session.listRPMs.return_value = koji_rpms

        result = _list_binary_rpms(mock_koji_session, 12345)

        assert "curl-debuginfo" not in result
        assert "curl-debugsource" not in result
        assert "glibc-all-langpacks" not in result
        assert "glibc-debuginfo-common" not in result
        assert "glibc-langpack-en" not in result
        assert "glibc-langpack-de" not in result
        assert "glibc-minimal-langpack" not in result
        assert "curl" in result
        assert "libcurl" in result

    def test_empty_rpms(self, mock_koji_session):
        mock_koji_session.listRPMs.return_value = []

        result = _list_binary_rpms(mock_koji_session, 12345)

        assert result == []


class TestLookupBinaryRPMs:
    @patch("aegis_ai.toolsets.tools.build_system._list_binary_rpms")
    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_happy_path(self, mock_session, mock_fetch, mock_list):
        mock_session.return_value = MagicMock()
        mock_session.return_value.getBuild.return_value = {"id": 12345}
        mock_fetch.return_value = [
            {"build_nvr": "curl-8.6.0-3.el9", "ps_update_stream": "rhel-9.6.0.z"},
        ]
        mock_list.return_value = ["curl", "curl-minimal", "libcurl", "libcurl-devel"]

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "success"
        assert result.package == "curl"
        assert result.ps_update_stream == "rhel-9.6.0.z"
        assert result.build_nvr == "curl-8.6.0-3.el9"
        assert result.binary_rpms == [
            "curl",
            "curl-minimal",
            "libcurl",
            "libcurl-devel",
        ]

    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_koji_profile_missing(self, mock_session):
        mock_session.side_effect = koji.ConfigurationError("no profile")

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "error"
        assert result.error_message is not None
        assert "not configured" in result.error_message

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_not_found(self, mock_session, mock_fetch):
        mock_session.return_value = MagicMock()
        mock_fetch.return_value = []

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "not_found"
        assert result.error_message is not None
        assert "No builds found" in result.error_message

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_deptopia_http_error(self, mock_session, mock_fetch):
        import urllib.error
        from email.message import Message

        mock_session.return_value = MagicMock()
        mock_fetch.side_effect = urllib.error.HTTPError(
            url="", code=500, msg="Internal Server Error", hdrs=Message(), fp=None
        )

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "error"
        assert result.error_message is not None
        assert "Deptopia API error" in result.error_message

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_deptopia_url_error(self, mock_session, mock_fetch):
        import urllib.error

        mock_session.return_value = MagicMock()
        mock_fetch.side_effect = urllib.error.URLError("connection refused")

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "error"
        assert result.error_message is not None
        assert "Deptopia API error" in result.error_message

    @patch("aegis_ai.toolsets.tools.build_system._list_binary_rpms")
    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_koji_error_listing_rpms(self, mock_session, mock_fetch, mock_list):
        mock_session.return_value = MagicMock()
        mock_session.return_value.getBuild.return_value = {"id": 12345}
        mock_fetch.return_value = [
            {"build_nvr": "curl-8.6.0-3.el9", "ps_update_stream": "rhel-9.6.0.z"},
        ]
        mock_list.side_effect = koji.GenericError("XML-RPC fault")

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "error"
        assert result.build_nvr == "curl-8.6.0-3.el9"
        assert result.error_message is not None
        assert "listing RPMs" in result.error_message

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_deptopia_malformed_json(self, mock_session, mock_fetch):
        mock_session.return_value = MagicMock()
        mock_fetch.side_effect = json.JSONDecodeError("Expecting value", "", 0)

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "error"
        assert result.error_message is not None
        assert "Deptopia response error" in result.error_message

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_deptopia_missing_key(self, mock_session, mock_fetch):
        mock_session.return_value = MagicMock()
        mock_fetch.side_effect = KeyError("build_nvr")

        result = _lookup_binary_rpms("curl", "rhel-9.6.0.z")

        assert result.status == "error"
        assert result.error_message is not None
        assert "Deptopia response error" in result.error_message


class TestLookupBinaryRPMsBatch:
    @patch("aegis_ai.toolsets.tools.build_system._list_binary_rpms")
    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_deduplicates_deptopia(self, mock_session, mock_fetch, mock_list):
        mock_session.return_value = MagicMock()
        mock_session.return_value.getBuild.return_value = {"id": 111}
        mock_fetch.return_value = [
            {"build_nvr": "curl-8.6.0-3.el9", "ps_update_stream": "rhel-9.6.0.z"},
            {"build_nvr": "curl-7.76.1-29.el8_10", "ps_update_stream": "rhel-8.10.0.z"},
        ]
        mock_list.return_value = ["curl", "libcurl"]

        results = _lookup_binary_rpms_batch("curl", ["rhel-9.6.0.z", "rhel-8.10.0.z"])

        mock_fetch.assert_called_once_with("curl")
        assert len(results) == 2
        assert all(r.status == "success" for r in results)

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_mixed_found_and_not_found(self, mock_session, mock_fetch):
        mock_session.return_value = MagicMock()
        mock_session.return_value.getBuild.return_value = None
        mock_fetch.return_value = [
            {"build_nvr": "curl-8.6.0-3.el9", "ps_update_stream": "rhel-9.6.0.z"},
        ]

        results = _lookup_binary_rpms_batch("curl", ["rhel-9.6.0.z", "rhel-7.9.z"])

        assert len(results) == 2
        assert results[0].ps_update_stream == "rhel-9.6.0.z"
        assert results[1].status == "not_found"
        assert results[1].ps_update_stream == "rhel-7.9.z"

    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_koji_profile_missing(self, mock_session):
        mock_session.side_effect = koji.ConfigurationError("no profile")

        results = _lookup_binary_rpms_batch("curl", ["rhel-9.6.0.z", "rhel-8.10.0.z"])

        assert len(results) == 2
        assert all(r.status == "error" for r in results)
        for r in results:
            assert r.error_message is not None
            assert "not configured" in r.error_message

    @patch("aegis_ai.toolsets.tools.build_system._fetch_deptopia_builds")
    @patch("aegis_ai.toolsets.tools.build_system._create_brew_session")
    def test_deptopia_http_error(self, mock_session, mock_fetch):
        import urllib.error
        from email.message import Message

        mock_session.return_value = MagicMock()
        mock_fetch.side_effect = urllib.error.HTTPError(
            url="", code=500, msg="Internal Server Error", hdrs=Message(), fp=None
        )

        results = _lookup_binary_rpms_batch("curl", ["rhel-9.6.0.z", "rhel-8.10.0.z"])

        assert len(results) == 2
        assert all(r.status == "error" for r in results)
        for r in results:
            assert r.error_message is not None
            assert "Deptopia API error" in r.error_message
