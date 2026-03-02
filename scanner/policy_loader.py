import json
import os


DEFAULT_POLICY = {
    "block_cvss": 9.0,
    "block_cve_count": 5,
    "block_severity": ["CRITICAL"],
    "enable_secret_scan": False,
    "enable_iac_scan": False,
    "enable_docker_scan": False,
    "enable_node_scan": False,
    "enable_java_scan": False
}


def load_policy(policy_path="policy.json"):

    if not os.path.exists(policy_path):
        print("[!] policy.json not found. Using default policy.")
        return DEFAULT_POLICY

    try:
        with open(policy_path, "r") as f:
            policy = json.load(f)

        # Merge with defaults
        for key in DEFAULT_POLICY:
            if key not in policy:
                policy[key] = DEFAULT_POLICY[key]

        return policy

    except Exception:
        print("[!] Failed to load policy.json. Using default policy.")
        return DEFAULT_POLICY