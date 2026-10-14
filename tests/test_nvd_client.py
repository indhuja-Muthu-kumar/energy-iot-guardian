from unittest.mock import Mock

import requests
import pytest

from app.services.nvd_client import NVDClient


def test_nvd_client_returns_successful_response_and_sends_expected_request():
    client = NVDClient(base_url="https://example.test/cves/2.0", api_key="test-key")
    payload = {
        "totalResults": 1,
        "vulnerabilities": [{"cve": {"id": "CVE-2025-1234"}}],
    }
    response = Mock()
    response.json.return_value = payload
    client.session.get = Mock(return_value=response)

    result = client.fetch_cves("SMA Sunny Boy", page_size=5, start_index=10)

    assert result == payload
    client.session.get.assert_called_once_with(
        "https://example.test/cves/2.0",
        params={
            "keywordSearch": "SMA Sunny Boy",
            "resultsPerPage": 5,
            "startIndex": 10,
        },
        headers={
            "User-Agent": "Energy-IoT-CVE-Monitor/1.0",
            "apiKey": "test-key",
        },
        timeout=15,
    )


def test_nvd_client_respects_numeric_retry_after_on_rate_limit(monkeypatch):
    client = NVDClient(base_url="https://example.test")
    response = requests.Response()
    response.status_code = 429
    response.headers["Retry-After"] = "3"
    response.url = "https://example.test"
    error = requests.HTTPError(response=response)
    successful_response = Mock()
    successful_response.json.return_value = {"vulnerabilities": []}
    client.session.get = Mock(side_effect=[error, successful_response])
    sleep = Mock()
    monkeypatch.setattr("app.services.nvd_client.time.sleep", sleep)

    result = client.fetch_cves("SMA Sunny Boy")

    assert result == {"vulnerabilities": []}
    sleep.assert_called_once_with(3.0)


def test_nvd_client_does_not_retry_permanent_client_errors(monkeypatch):
    client = NVDClient(base_url="https://example.test")
    response = requests.Response()
    response.status_code = 400
    response.url = "https://example.test"
    error = requests.HTTPError(response=response)
    client.session.get = Mock(side_effect=error)
    sleep = Mock()
    monkeypatch.setattr("app.services.nvd_client.time.sleep", sleep)

    with pytest.raises(requests.HTTPError):
        client.fetch_cves("SMA Sunny Boy")

    client.session.get.assert_called_once()
    sleep.assert_not_called()


def test_nvd_client_retries_timeouts(monkeypatch):
    client = NVDClient(base_url="https://example.test")
    successful_response = Mock()
    successful_response.json.return_value = {
        "totalResults": 0,
        "vulnerabilities": [],
    }
    client.session.get = Mock(
        side_effect=[
            requests.Timeout("temporary timeout"),
            successful_response,
        ]
    )
    sleep = Mock()
    monkeypatch.setattr("app.services.nvd_client.time.sleep", sleep)

    result = client.fetch_cves("SMA Sunny Boy")

    assert result == {"totalResults": 0, "vulnerabilities": []}
    assert client.session.get.call_count == 2
    sleep.assert_called_once_with(1)


def test_nvd_cpe_lookup_uses_cpe_endpoint_without_network_access(monkeypatch):
    client = NVDClient()
    response = Mock()
    response.json.return_value = {"products": []}
    client.session.get = Mock(return_value=response)

    result = client.fetch_cpe("SMA", "Sunny Boy")

    assert result == {"products": []}
    args, kwargs = client.session.get.call_args
    assert args[0] == "https://services.nvd.nist.gov/rest/json/cpes/2.0"
    assert kwargs["params"] == {
        "keywordSearch": "SMA Sunny Boy",
        "resultsPerPage": 10,
        "startIndex": 0,
    }


def test_nvd_cve_by_cpe_uses_exact_cpe_name_without_network_access(monkeypatch):
    client = NVDClient(base_url="https://example.test")
    response = Mock()
    response.json.return_value = {"totalResults": 0, "vulnerabilities": []}
    client.session.get = Mock(return_value=response)

    result = client.fetch_cves_by_cpe(
        "cpe:2.3:a:espressif:esp_idf:5.5.2:*:*:*:*:*:*:*",
        page_size=100,
        start_index=0,
    )

    assert result == {"totalResults": 0, "vulnerabilities": []}
    assert client.session.get.call_args.kwargs["params"] == {
        "cpeName": "cpe:2.3:a:espressif:esp_idf:5.5.2:*:*:*:*:*:*:*",
        "resultsPerPage": 100,
        "startIndex": 0,
    }
