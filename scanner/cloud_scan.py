import boto3
from botocore.exceptions import NoCredentialsError, ClientError


def scan_aws_environment():

    print("[*] Running AWS live security scan...")

    findings = []

    try:
        REGION = "us-east-1"
        session = boto3.Session(region_name=REGION)

        sts = session.client("sts")
        identity = sts.get_caller_identity()
        print("\nDEBUG: AWS Account ID =", identity["Account"])
        print("DEBUG: Scanning Region =", REGION)

        s3 = session.client("s3")
        ec2 = session.client("ec2")
        rds = session.client("rds")
        iam = session.client("iam")

    except NoCredentialsError:
        print("[!] No AWS credentials found. Skipping cloud scan.")
        return []

    # =====================================================
    # Security Group Check
    # =====================================================
    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]

        for group in groups:
            for rule in group.get("IpPermissions", []):
                for ip_range in rule.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        findings.append({
                            "severity": "HIGH",
                            "issue": f"Security Group '{group['GroupName']}' allows 0.0.0.0/0",
                            "remediation": "Restrict inbound rules to specific IP ranges instead of 0.0.0.0/0."
                        })

    except ClientError:
        pass

    # =====================================================
    # RDS Check
    # =====================================================
    try:
        instances = rds.describe_db_instances()["DBInstances"]

        print("\nDEBUG: RDS Instances Found:")
        for db in instances:

            print(
                f"   - {db['DBInstanceIdentifier']} | "
                f"PubliclyAccessible={db.get('PubliclyAccessible')}"
            )

            if db.get("PubliclyAccessible"):
                findings.append({
                    "severity": "CRITICAL",
                    "issue": f"RDS '{db['DBInstanceIdentifier']}' is publicly accessible",
                    "remediation": "Modify DB instance and set 'Publicly Accessible' to No. Ensure it is inside private subnets."
                })

    except ClientError:
        pass

    # =====================================================
    # S3 Check
    # =====================================================
    try:
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            name = bucket["Name"]

            try:
                acl = s3.get_bucket_acl(Bucket=name)
                for grant in acl["Grants"]:
                    if "AllUsers" in str(grant.get("Grantee", {})):
                        findings.append({
                            "severity": "CRITICAL",
                            "issue": f"S3 bucket '{name}' is publicly accessible",
                            "remediation": "Enable 'Block Public Access' and remove public bucket policies."
                        })
            except ClientError:
                pass

    except ClientError:
        pass

    # =====================================================
    # Final Output
    # =====================================================
    if findings:
        print(f"\n[!] Found {len(findings)} cloud misconfigurations\n")
        print("🚨 Cloud Security Findings:")
        for f in findings:
            print(f"\n[{f['severity']}] {f['issue']}")
            print(f"   ➜ Remediation: {f['remediation']}")
    else:
        print("[+] No critical AWS misconfigurations detected")

    return findings