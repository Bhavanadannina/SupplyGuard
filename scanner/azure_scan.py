import os
from azure.identity import DefaultAzureCredential
from azure.mgmt.resource import SubscriptionClient
from azure.mgmt.network import NetworkManagementClient
from azure.mgmt.storage import StorageManagementClient
from azure.mgmt.sql import SqlManagementClient
from azure.mgmt.authorization import AuthorizationManagementClient


def scan_azure_environment():

    print("\n[*] Running Azure live security scan...")

    findings = []

    try:
        credential = DefaultAzureCredential()
        sub_client = SubscriptionClient(credential)

        subscriptions = list(sub_client.subscriptions.list())

        if not subscriptions:
            print("[!] No Azure subscriptions found.")
            return []

        subscription_id = subscriptions[0].subscription_id
        print("DEBUG: Azure Subscription =", subscription_id)

        network_client = NetworkManagementClient(credential, subscription_id)
        storage_client = StorageManagementClient(credential, subscription_id)
        sql_client = SqlManagementClient(credential, subscription_id)
        auth_client = AuthorizationManagementClient(credential, subscription_id)

    except Exception as e:
        print("[!] Azure authentication failed:", str(e))
        return []

    # =====================================================
    # NSG Check
    # =====================================================
    try:
        for nsg in network_client.network_security_groups.list_all():
            for rule in nsg.security_rules:
                if rule.source_address_prefix == "0.0.0.0/0":
                    findings.append({
                        "severity": "HIGH",
                        "issue": f"NSG '{nsg.name}' allows 0.0.0.0/0",
                        "remediation": "Restrict NSG inbound rules to trusted IP ranges."
                    })
    except Exception:
        pass

    # =====================================================
    # Storage Account Public Access
    # =====================================================
    try:
        for account in storage_client.storage_accounts.list():
            if account.allow_blob_public_access:
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"Storage Account '{account.name}' allows public blob access",
                    "remediation": "Disable public blob access in storage account settings."
                })
    except Exception:
        pass

    # =====================================================
    # SQL Public Exposure
    # =====================================================
    try:
        for server in sql_client.servers.list():
            if server.public_network_access == "Enabled":
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"Azure SQL Server '{server.name}' allows public access",
                    "remediation": "Disable public network access and use private endpoints."
                })
    except Exception:
        pass

    # =====================================================
    # Overly Permissive Roles
    # =====================================================
    try:
        for assignment in auth_client.role_assignments.list():
            if "Owner" in assignment.role_definition_id:
                findings.append({
                    "severity": "HIGH",
                    "issue": "Owner role assigned broadly",
                    "remediation": "Follow least privilege principle and reduce Owner role usage."
                })
    except Exception:
        pass

    # =====================================================
    # Final Output
    # =====================================================
    if findings:
        print(f"\n[!] Found {len(findings)} Azure misconfigurations\n")
        print("🚨 Azure Security Findings:")
        for f in findings:
            print(f"\n[{f['severity']}] {f['issue']}")
            print(f"   ➜ Remediation: {f['remediation']}")
    else:
        print("[+] No Azure misconfigurations detected")

    return findings