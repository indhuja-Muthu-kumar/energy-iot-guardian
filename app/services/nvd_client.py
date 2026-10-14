from __future__ import annotations

import time
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import Any

import requests

from app.config import Config


class NVDClient:
    def __init__(self, base_url: str | None = None, api_key: str | None = None):
        self.base_url = base_url or Config.NVD_API_BASE
        self.api_key = Config.NVD_API_KEY if api_key is None else api_key
        self.session = requests.Session()

    def _request(
        self,
        endpoint: str,
        params: dict[str, Any] | None = None,
        base_url: str | None = None,
    ):
        url = f"{(base_url or self.base_url).rstrip('/')}{endpoint}"
        headers = {"User-Agent": "Energy-IoT-CVE-Monitor/1.0"}
        if self.api_key:
            headers["apiKey"] = self.api_key
        for attempt in range(3):
            try:
                response = self.session.get(url, params=params, headers=headers, timeout=15)
                response.raise_for_status()
                return response.json()
            except requests.RequestException as error:
                if attempt == 2 or not _should_retry(error):
                    raise
                time.sleep(_retry_delay(error, attempt))

    def fetch_cves(self, keyword: str, page_size: int = 10, start_index: int = 0):
        params = {
            "keywordSearch": keyword,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        return self._request("", params=params)

    def fetch_cpe(
        self,
        vendor: str,
        product: str,
        results_per_page: int = 10,
        start_index: int = 0,
    ):
        params = {
            "keywordSearch": f"{vendor} {product}",
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }
        return self._request("", params=params, base_url=Config.CPE_API_BASE)

    def fetch_cves_by_cpe(
        self,
        cpe_name: str,
        page_size: int = 10,
        start_index: int = 0,
    ):
        params = {
            "cpeName": cpe_name,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        return self._request("", params=params)


def _retry_delay(error: requests.RequestException, attempt: int) -> float:
    response = error.response
    if response is not None and response.status_code in {429, 503}:
        retry_after = response.headers.get("Retry-After", "")
        try:
            return min(30.0, max(1.0, float(retry_after)))
        except ValueError:
            try:
                retry_at = parsedate_to_datetime(retry_after)
                if retry_at.tzinfo is None:
                    retry_at = retry_at.replace(tzinfo=UTC)
                delay = (retry_at - datetime.now(UTC)).total_seconds()
                return min(30.0, max(1.0, delay))
            except (TypeError, ValueError, OverflowError):
                return float(6 * (attempt + 1))
    return float(min(2 ** attempt, 4))


def _should_retry(error: requests.RequestException) -> bool:
    if error.response is None:
        return True
    return error.response.status_code in {429, 500, 502, 503, 504}
