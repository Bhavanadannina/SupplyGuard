import os
import json
from packaging import version

# Global in-memory cache
NVD_INDEX = {}
INDEX_BUILT = False


def parse_cpe_uri(cpe_uri):
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return None

    return {
        "part": parts[2],
        "vendor": parts[3],
        "product": parts[4],
        "version": parts[5]
    }


def version_matches(installed_version, cpe_version, match_obj):
    """
    Simple version-aware comparison.
    Supports:
    - Exact match
    - Wildcard (*)
    - versionEndIncluding
    - versionEndExcluding
    """

    if cpe_version == "*" or installed_version == cpe_version:
        return True

    try:
        from packaging.version import parse as vparse

        installed = vparse(installed_version)

        if "versionEndIncluding" in match_obj:
            if installed <= vparse(match_obj["versionEndIncluding"]):
                return True

        if "versionEndExcluding" in match_obj:
            if installed < vparse(match_obj["versionEndExcluding"]):
                return True

    except Exception:
        pass

    return False


def build_nvd_index(dataset_folder="dataset"):
    global NVD_INDEX, INDEX_BUILT

    if INDEX_BUILT:
        return

    print("[*] Indexing NVD dataset into memory cache...")

    for file in os.listdir(dataset_folder):

        if not file.endswith(".json"):
            continue

        path = os.path.join(dataset_folder, file)

        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)

            vulnerabilities = data.get("vulnerabilities", [])

            for item in vulnerabilities:

                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id", "")

                metrics = cve_data.get("metrics", {})
                cvss_score = 0

                if "cvssMetricV31" in metrics:
                    cvss_score = metrics["cvssMetricV31"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV30" in metrics:
                    cvss_score = metrics["cvssMetricV30"][0]["cvssData"]["baseScore"]
                elif "cvssMetricV2" in metrics:
                    cvss_score = metrics["cvssMetricV2"][0]["cvssData"]["baseScore"]

                configurations = cve_data.get("configurations", [])

                for config in configurations:
                    nodes = config.get("nodes", [])

                    for node in nodes:
                        matches = node.get("cpeMatch", [])

                        for match in matches:

                            if not match.get("vulnerable", False):
                                continue

                            cpe_uri = match.get("criteria", "")
                            parsed = parse_cpe_uri(cpe_uri)

                            if not parsed:
                                continue

                            if parsed["part"] != "a":
                                continue

                            product = parsed["product"].lower()

                            entry = {
                                "cve_id": cve_id,
                                "product": product,
                                "version": parsed["version"],
                                "cvss": cvss_score,
                                "match_obj": match
                            }

                            if product not in NVD_INDEX:
                                NVD_INDEX[product] = []

                            NVD_INDEX[product].append(entry)

    INDEX_BUILT = True
    print(f"[+] Indexed {len(NVD_INDEX)} products into memory cache\n")


def get_indexed_vulnerabilities():
    if not INDEX_BUILT:
        build_nvd_index()
    return NVD_INDEX