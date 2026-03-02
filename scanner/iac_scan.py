import os
import yaml


def scan_yaml_iac(project_path):

    print("[*] Running YAML IaC security checks...")

    findings = []

    for root, dirs, files in os.walk(project_path):

        for file in files:
            if file.endswith(".yaml") or file.endswith(".yml"):

                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        docs = list(yaml.safe_load_all(f))
                except Exception:
                    continue

                for doc in docs:
                    if not isinstance(doc, dict):
                        continue

                    kind = doc.get("kind", "")

                    # ----------------------------
                    # Pod / Deployment checks
                    # ----------------------------
                    if kind in ["Pod", "Deployment", "StatefulSet"]:

                        spec = doc.get("spec", {})
                        template = spec.get("template", {})
                        pod_spec = template.get("spec", spec.get("spec", {}))

                        # hostNetwork
                        if pod_spec.get("hostNetwork") is True:
                            findings.append(f"{file}: hostNetwork enabled")

                        # hostPID
                        if pod_spec.get("hostPID") is True:
                            findings.append(f"{file}: hostPID enabled")

                        containers = pod_spec.get("containers", [])

                        for container in containers:

                            security = container.get("securityContext", {})

                            if security.get("privileged") is True:
                                findings.append(f"{file}: privileged container")

                            if security.get("runAsUser") == 0:
                                findings.append(f"{file}: running as root user")

                            if security.get("allowPrivilegeEscalation") is True:
                                findings.append(f"{file}: privilege escalation allowed")

                            if "imagePullPolicy" not in container:
                                findings.append(f"{file}: imagePullPolicy not specified")

                    # ----------------------------
                    # Service checks
                    # ----------------------------
                    if kind == "Service":

                        spec = doc.get("spec", {})

                        if spec.get("type") == "NodePort":
                            findings.append(f"{file}: Service type NodePort (public exposure)")

                # End doc loop

    if findings:
        print(f"[!] Found {len(findings)} YAML misconfigurations")
    else:
        print("[+] No YAML misconfigurations detected")

    return findings

def scan_docker_compose(project_path):

    print("[*] Running Docker Compose security checks...")

    findings = []

    for root, dirs, files in os.walk(project_path):

        for file in files:
            if file in ["docker-compose.yml", "docker-compose.yaml"]:

                file_path = os.path.join(root, file)

                try:
                    with open(file_path, "r", encoding="utf-8") as f:
                        data = yaml.safe_load(f)
                except Exception:
                    continue

                services = data.get("services", {})

                for service_name, service in services.items():

                    # privileged mode
                    if service.get("privileged") is True:
                        findings.append(f"{file}: {service_name} runs in privileged mode")

                    # host network
                    if service.get("network_mode") == "host":
                        findings.append(f"{file}: {service_name} uses host network")

                    # root user
                    if service.get("user") == "root":
                        findings.append(f"{file}: {service_name} runs as root user")

                    # public port exposure
                    ports = service.get("ports", [])
                    for port in ports:
                        if isinstance(port, str) and port.startswith("0.0.0.0"):
                            findings.append(f"{file}: {service_name} exposes public port {port}")

                    # no healthcheck
                    if "healthcheck" not in service:
                        findings.append(f"{file}: {service_name} has no healthcheck")

                    # writable filesystem
                    if service.get("read_only") is not True:
                        findings.append(f"{file}: {service_name} filesystem not read-only")

    if findings:
        print(f"[!] Found {len(findings)} Docker Compose misconfigurations")
    else:
        print("[+] No Docker Compose misconfigurations detected")

    return findings

# =========================================================
# Advanced Terraform Security Scanner (HCL-based)
# =========================================================

import hcl2


def scan_terraform(project_path):

    print("[*] Running Advanced Terraform security checks...")

    findings = []

    for root, dirs, files in os.walk(project_path):

        for file in files:

            if not file.endswith(".tf"):
                continue

            file_path = os.path.join(root, file)

            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    parsed = hcl2.load(f)
            except Exception:
                continue

            # ---------------------------------------
            # Check resources
            # ---------------------------------------

            resources = parsed.get("resource", [])

            for resource in resources:

                for resource_type, instances in resource.items():

                    for name, config in instances.items():

                        # ---------------------------------------
                        # AWS Security Group
                        # ---------------------------------------
                        if resource_type == "aws_security_group":

                            ingress = config.get("ingress", [])

                            for rule in ingress:
                                cidrs = rule.get("cidr_blocks", [])
                                if "0.0.0.0/0" in cidrs:
                                    findings.append(
                                        f"{file}: Security Group '{name}' allows 0.0.0.0/0"
                                    )

                        # ---------------------------------------
                        # AWS S3 Bucket
                        # ---------------------------------------
                        if resource_type == "aws_s3_bucket":

                            if config.get("acl") == "public-read":
                                findings.append(
                                    f"{file}: S3 bucket '{name}' is public"
                                )

                            if "server_side_encryption_configuration" not in config:
                                findings.append(
                                    f"{file}: S3 bucket '{name}' missing encryption"
                                )

                        # ---------------------------------------
                        # AWS RDS
                        # ---------------------------------------
                        if resource_type == "aws_db_instance":

                            if config.get("publicly_accessible") is True:
                                findings.append(
                                    f"{file}: RDS instance '{name}' publicly accessible"
                                )

                        # ---------------------------------------
                        # Hardcoded credentials
                        # ---------------------------------------
                        if resource_type == "aws_provider":

                            if config.get("access_key") or config.get("secret_key"):
                                findings.append(
                                    f"{file}: Hardcoded AWS credentials in provider"
                                )

    if findings:
        print(f"[!] Found {len(findings)} Advanced Terraform misconfigurations")
    else:
        print("[+] No Terraform misconfigurations detected")

    return findings