import os
import yaml


def scan_pnpm_dependencies(project_path):

    print("[*] Running pnpm dependency scan...")

    lock_path = os.path.join(project_path, "pnpm-lock.yaml")

    if not os.path.exists(lock_path):
        return []

    try:
        with open(lock_path, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except Exception:
        print("[!] Failed to parse pnpm-lock.yaml")
        return []

    dependencies = []

    packages = data.get("packages", {})

    for key, info in packages.items():

        # key format: /package@version
        parts = key.strip("/").split("@")
        if len(parts) < 2:
            continue

        name = parts[0]
        version = parts[-1]

        dependencies.append({
            "name": name.lower(),
            "version": version,
            "depth": 1
        })

    print(f"[+] Found {len(dependencies)} pnpm dependencies")

    return dependencies