import os
import re


SECRET_PATTERNS = {
    "AWS Access Key": r"AKIA[0-9A-Z]{16}",
    "Private Key": r"-----BEGIN PRIVATE KEY-----",
    "Password Assignment": r"password\s*=\s*['\"].+['\"]",
    "API Key": r"api[_-]?key\s*=\s*['\"].+['\"]"
}


def scan_secrets(project_path):

    findings = []

    for root, _, files in os.walk(project_path):

        # Skip virtual environment
        if ".supplyguard_env" in root:
            continue

        for file in files:

            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", errors="ignore") as f:
                    content = f.read()

                    for name, pattern in SECRET_PATTERNS.items():
                        if re.search(pattern, content):
                            findings.append({
                                "type": name,
                                "file": file_path
                            })

            except Exception:
                continue

    return findings