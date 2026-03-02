# scanner/nvd_api.py

import requests
import os

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
API_KEY = os.getenv("NVD_API_KEY")

def fetch_nvd_vulnerabilities(package_name):

    headers = {}
    if API_KEY:
        headers["apiKey"] = API_KEY

    params = {
        "keywordSearch": package_name,
        "resultsPerPage": 20
    }

    try:
        response = requests.get(
            NVD_API_URL,
            headers=headers,
            params=params,
            timeout=15
        )

        if response.status_code != 200:
            return []

        data = response.json()
        vulns = []

        for item in data.get("vulnerabilities", []):
            cve = item["cve"]

            cvss = 0
            metrics = cve.get("metrics", {})

            if "cvssMetricV31" in metrics:
                cvss = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]

            vulns.append({
                "cve_id": cve["id"],
                "cvss": cvss
            })

        return vulns

    except:
        return []
