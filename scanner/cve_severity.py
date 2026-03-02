def map_cvss_to_severity(cvss_score):
    if cvss_score >= 9.0:
        return "CRITICAL"
    elif cvss_score >= 7.0:
        return "HIGH"
    elif cvss_score >= 4.0:
        return "MEDIUM"
    elif cvss_score > 0:
        return "LOW"
    else:
        return "NONE"


def compute_severity_from_cves(cve_list):
    """
    Expects list of CVE dicts:
    [
        {"id": "...", "cvss": 7.5},
        ...
    ]
    """

    if not cve_list:
        return {
            "cve_count": 0,
            "avg_cvss": 0,
            "highest_cvss": 0,
            "highest_severity": "NONE"
        }

    scores = [cve.get("cvss", 0) for cve in cve_list]
    highest_cvss = max(scores)
    avg_cvss = sum(scores) / len(scores)

    return {
        "cve_count": len(cve_list),
        "avg_cvss": round(avg_cvss, 2),
        "highest_cvss": highest_cvss,
        "highest_severity": map_cvss_to_severity(highest_cvss)
    }