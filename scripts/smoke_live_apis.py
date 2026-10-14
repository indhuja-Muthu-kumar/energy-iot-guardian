from __future__ import annotations

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def main():
    cve = requests.get(
        NVD_URL,
        params={"keywordSearch": "sma", "resultsPerPage": 1, "startIndex": 0},
        timeout=20,
    )
    kev = requests.get(KEV_URL, timeout=20)
    print(
        {
            "nvd_status": cve.status_code,
            "nvd_total": cve.json().get("totalResults", 0),
            "kev_status": kev.status_code,
            "kev_count": len(kev.json().get("vulnerabilities", [])),
        }
    )


if __name__ == "__main__":
    main()
