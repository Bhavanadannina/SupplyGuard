import os
import subprocess
import json
import yaml

def find_lockfile(project_path):

    for root, dirs, files in os.walk(project_path):
        if "package-lock.json" in files:
            return os.path.join(root, "package-lock.json"), "npm"
        if "pnpm-lock.yaml" in files:
            return os.path.join(root, "pnpm-lock.yaml"), "pnpm"

    return None, None


def parse_package_json(project_path):

    for root, dirs, files in os.walk(project_path):
        if "package.json" in files:
            with open(os.path.join(root, "package.json"), "r", encoding="utf-8") as f:
                data = json.load(f)

            deps = []

            for section in ["dependencies", "devDependencies"]:
                for name, version in data.get(section, {}).items():
                    deps.append({
                        "name": name.lower(),
                        "version": version,
                        "depth": 1
                    })

            return deps

    return []


def scan_node_dependencies(project_path):

    print("[*] Running Node.js dependency scan...")

    lockfile_path, lock_type = find_lockfile(project_path)

    dependencies = []

    # -----------------------------
    # Lockfile Mode (Best)
    # -----------------------------
    if lockfile_path:

        print(f"[*] Found {lock_type} lockfile at: {lockfile_path}")

        if lock_type == "npm":

            with open(lockfile_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            if "packages" in data:
                for pkg_path, info in data["packages"].items():
                    if pkg_path == "":
                        continue

                    name = pkg_path.split("node_modules/")[-1]
                    version = info.get("version", "unknown")

                    dependencies.append({
                        "name": name.lower(),
                        "version": version,
                        "depth": pkg_path.count("node_modules")
                    })

        elif lock_type == "pnpm":

            with open(lockfile_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f)

            packages = data.get("packages", {})

            for key in packages.keys():
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

    # -----------------------------
    # Fallback: package.json
    # -----------------------------
    else:
        print("[!] No lockfile found — falling back to package.json")
        dependencies = parse_package_json(project_path)

    print(f"[+] Found {len(dependencies)} Node dependencies")
    return dependencies