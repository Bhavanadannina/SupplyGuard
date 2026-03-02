import os
import xml.etree.ElementTree as ET


def scan_java_dependencies(project_path):

    print("[*] Running Java (Maven) dependency scan...")

    pom_path = None

    # Search recursively for pom.xml
    for root, dirs, files in os.walk(project_path):
        if "pom.xml" in files:
            pom_path = os.path.join(root, "pom.xml")
            break

    if not pom_path:
        print("[!] No pom.xml found")
        return []

    print(f"[*] Found pom.xml at: {pom_path}")

    dependencies = []

    try:
        tree = ET.parse(pom_path)
        root = tree.getroot()

        # Handle XML namespace if present
        ns = {"m": root.tag.split("}")[0].strip("{")} if "}" in root.tag else {}

        dep_nodes = root.findall(".//m:dependency", ns) if ns else root.findall(".//dependency")

        for dep in dep_nodes:

            group = dep.find("m:groupId", ns) if ns else dep.find("groupId")
            artifact = dep.find("m:artifactId", ns) if ns else dep.find("artifactId")
            version = dep.find("m:version", ns) if ns else dep.find("version")

            if artifact is None:
                continue

            name = artifact.text.lower()
            ver = version.text if version is not None else "unknown"

            dependencies.append({
                "name": name,
                "version": ver,
                "depth": 1
            })

    except Exception as e:
        print(f"[!] Failed to parse pom.xml: {e}")
        return []

    print(f"[+] Found {len(dependencies)} Java dependencies")
    return dependencies