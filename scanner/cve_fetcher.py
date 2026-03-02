import requests


OSV_API_URL = "https://api.osv.dev/v1/query"


def fetch_cve_data(package_name, version):
    """
    Fetch CVE data from OSV API for given package and version.
    """

    payload = {
        "package": {
            "name": package_name,
            "ecosystem": "PyPI"
        },
        "version": version
    }

    try:
        response = requests.post(OSV_API_URL, json=payload, timeout=10)

        if response.status_code != 200:
            return {
                "cve_count": 0,
                "avg_cvss": 0,
                "highest_severity": "NONE",
                "cve_ids": []
            }

        data = response.json()

        if "vulns" not in data:
            return {
                "cve_count": 0,
                "avg_cvss": 0,
                "highest_severity": "NONE",
                "cve_ids": []
            }

        vulns = data["vulns"]

        cve_ids = []
        severities = []

        for vuln in vulns:
            if "id" in vuln:
                cve_ids.append(vuln["id"])

            # Try to extract CVSS score
            if "severity" in vuln:
                for sev in vuln["severity"]:
                    if "score" in sev:
                        try:
                            score = float(sev["score"])
                            severities.append(score)
                        except:
                            pass

        cve_count = len(cve_ids)

        avg_cvss = round(sum(severities) / len(severities), 2) if severities else 0

        highest_severity = "NONE"
        if severities:
            max_score = max(severities)
            if max_score >= 9:
                highest_severity = "CRITICAL"
            elif max_score >= 7:
                highest_severity = "HIGH"
            elif max_score >= 4:
                highest_severity = "MEDIUM"
            else:
                highest_severity = "LOW"

        return {
            "cve_count": cve_count,
            "avg_cvss": avg_cvss,
            "highest_severity": highest_severity,
            "cve_ids": cve_ids
        }

    except Exception:
        return {
            "cve_count": 0,
            "avg_cvss": 0,
            "highest_severity": "NONE",
            "cve_ids": []
        }