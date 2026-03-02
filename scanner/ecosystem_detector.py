import os


def detect_ecosystem(project_path):

    detected = []

    # ---------------------------------
    # Python
    # ---------------------------------
    if os.path.exists(os.path.join(project_path, "requirements.txt")) \
       or os.path.exists(os.path.join(project_path, "pyproject.toml")) \
       or os.path.exists(os.path.join(project_path, "setup.py")):
        detected.append("python")

    # ---------------------------------
    # Node.js
    # ---------------------------------
    if os.path.exists(os.path.join(project_path, "package.json")):
        detected.append("node")

    # ---------------------------------
    # Java (Maven)
    # ---------------------------------
    if os.path.exists(os.path.join(project_path, "pom.xml")):
        detected.append("java")

    # ---------------------------------
    # Dockerfile
    # ---------------------------------
    if os.path.exists(os.path.join(project_path, "Dockerfile")):
        detected.append("docker")

    # ---------------------------------
    # Recursive scan for Terraform & YAML
    # ---------------------------------
    for root, dirs, files in os.walk(project_path):

        for file in files:

            # Terraform
            if file.endswith(".tf"):
                if "terraform" not in detected:
                    detected.append("terraform")

            # YAML / Kubernetes
            if file.endswith(".yaml") or file.endswith(".yml"):
                if "yaml" not in detected:
                    detected.append("yaml")

            # Docker Compose
            if "docker-compose" in file and file.endswith((".yml", ".yaml")):
                if "compose" not in detected:
                    detected.append("compose")

    if not detected:
        detected.append("unknown")

    return detected