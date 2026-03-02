import json
from datetime import datetime


def generate_sbom(dependencies, output_file="sbom.json"):

    components = []

    for dep in dependencies:

        scope = "required" if dep["dependency_type"] == "DIRECT" else "optional"

        component = {
            "type": "library",
            "name": dep["name"],
            "version": dep["version"],
            "scope": scope,
            "properties": [
                {
                    "name": "dependency_type",
                    "value": dep["dependency_type"]
                },
                {
                    "name": "depth",
                    "value": str(dep["depth"])
                },
                {
                    "name": "cve_count",
                    "value": str(dep["cve_count"])
                },
                {
                    "name": "highest_cvss",
                    "value": str(dep["highest_cvss"])
                },
                {
                    "name": "severity",
                    "value": dep["severity"]
                }
            ]
        }

        components.append(component)

    sbom = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:supplyguard-sbom",
        "version": 2,
        "metadata": {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "tools": [
                {
                    "vendor": "SupplyGuard",
                    "name": "SupplyGuard Dependency Scanner",
                    "version": "3.0"
                }
            ]
        },
        "components": components
    }

    with open(output_file, "w") as f:
        json.dump(sbom, f, indent=4)

    print(f"[+] SBOM generated successfully: {output_file}")