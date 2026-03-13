import sys
sys.stdout.reconfigure(encoding='utf-8')
import boto3
import json
from datetime import datetime, timezone


# ─────────────────────────────────────────────
#  HELPERS
# ─────────────────────────────────────────────

def finding(severity, resource_type, resource_id, region, description):
    """Create a standardised finding dict."""
    return {
        "severity": severity,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "region": region,
        "description": description,
    }


def print_finding(f):
    icons = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
    icon = icons.get(f["severity"], "⚪")
    print(f"  {icon} [{f['severity']}] {f['resource_type']} — {f['resource_id']}")
    print(f"     {f['description']}")
    print()


# ─────────────────────────────────────────────
#  CHECK 1 — S3 PUBLIC ACCESS
# ─────────────────────────────────────────────

def check_s3_public_access(findings):
    print("[ 1/5 ] Checking S3 buckets for public access...")
    s3 = boto3.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except Exception as e:
        print(f"  ⚠️  Could not list S3 buckets: {e}\n")
        return

    for bucket in buckets:
        name = bucket["Name"]
        try:
            pab = s3.get_public_access_block(Bucket=name)
            config = pab["PublicAccessBlockConfiguration"]
            all_blocked = all([
                config.get("BlockPublicAcls", False),
                config.get("IgnorePublicAcls", False),
                config.get("BlockPublicPolicy", False),
                config.get("RestrictPublicBuckets", False),
            ])
            if not all_blocked:
                f = finding(
                    severity="HIGH",
                    resource_type="S3 Bucket",
                    resource_id=name,
                    region="global",
                    description="Public access block is NOT fully enabled. Bucket may be publicly accessible.",
                )
                findings.append(f)
                print_finding(f)
        except s3.exceptions.NoSuchPublicAccessBlockConfiguration:
            # No block config at all → fully open
            f = finding(
                severity="HIGH",
                resource_type="S3 Bucket",
                resource_id=name,
                region="global",
                description="No public access block configuration found. Bucket is potentially public.",
            )
            findings.append(f)
            print_finding(f)
        except Exception as e:
            print(f"  ⚠️  Skipping bucket {name}: {e}")

    if not any(f["resource_type"] == "S3 Bucket" for f in findings):
        print("  ✅ All S3 buckets have public access blocked.\n")


# ─────────────────────────────────────────────
#  CHECK 2 — SECURITY GROUPS (SSH / ALL TRAFFIC)
# ─────────────────────────────────────────────

def check_security_groups(findings, region="us-east-1"):
    print("[ 2/5 ] Checking Security Groups for open SSH / all-traffic rules...")
    ec2 = boto3.client("ec2", region_name=region)

    try:
        sgs = ec2.describe_security_groups()["SecurityGroups"]
    except Exception as e:
        print(f"  ⚠️  Could not describe security groups: {e}\n")
        return

    for sg in sgs:
        sg_id = sg["GroupId"]
        sg_name = sg.get("GroupName", sg_id)

        for rule in sg.get("IpPermissions", []):
            from_port = rule.get("FromPort", -1)
            to_port = rule.get("ToPort", -1)
            ip_ranges = rule.get("IpRanges", [])
            ipv6_ranges = rule.get("Ipv6Ranges", [])

            open_to_world = any(
                r.get("CidrIp") == "0.0.0.0/0" for r in ip_ranges
            ) or any(
                r.get("CidrIpv6") == "::/0" for r in ipv6_ranges
            )

            if not open_to_world:
                continue

            # All traffic rule
            if rule.get("IpProtocol") == "-1":
                f = finding(
                    severity="HIGH",
                    resource_type="Security Group",
                    resource_id=f"{sg_id} ({sg_name})",
                    region=region,
                    description="Rule allows ALL traffic from 0.0.0.0/0. Completely open inbound.",
                )
                findings.append(f)
                print_finding(f)

            # SSH open to world
            elif from_port <= 22 <= to_port:
                f = finding(
                    severity="HIGH",
                    resource_type="Security Group",
                    resource_id=f"{sg_id} ({sg_name})",
                    region=region,
                    description="Port 22 (SSH) is open to 0.0.0.0/0. Brute-force risk.",
                )
                findings.append(f)
                print_finding(f)

            # RDP open to world
            elif from_port <= 3389 <= to_port:
                f = finding(
                    severity="HIGH",
                    resource_type="Security Group",
                    resource_id=f"{sg_id} ({sg_name})",
                    region=region,
                    description="Port 3389 (RDP) is open to 0.0.0.0/0. Remote access risk.",
                )
                findings.append(f)
                print_finding(f)

    if not any(f["resource_type"] == "Security Group" for f in findings):
        print("  ✅ No overly permissive security group rules found.\n")


# ─────────────────────────────────────────────
#  CHECK 3 — IAM USERS WITHOUT MFA
# ─────────────────────────────────────────────

def check_iam_mfa(findings):
    print("[ 3/5 ] Checking IAM users for missing MFA...")
    iam = boto3.client("iam")

    try:
        users = iam.list_users()["Users"]
    except Exception as e:
        print(f"  ⚠️  Could not list IAM users: {e}\n")
        return

    for user in users:
        username = user["UserName"]
        try:
            mfa_devices = iam.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                f = finding(
                    severity="MEDIUM",
                    resource_type="IAM User",
                    resource_id=username,
                    region="global",
                    description="No MFA device associated. Account vulnerable to credential theft.",
                )
                findings.append(f)
                print_finding(f)
        except Exception as e:
            print(f"  ⚠️  Could not check MFA for {username}: {e}")

    if not any(f["resource_type"] == "IAM User" for f in findings):
        print("  ✅ All IAM users have MFA enabled.\n")


# ─────────────────────────────────────────────
#  CHECK 4 — EC2 INSTANCES WITH PUBLIC IPs
# ─────────────────────────────────────────────

def check_ec2_public_ips(findings, region="us-east-1"):
    print("[ 4/5 ] Checking EC2 instances for public IP exposure...")
    ec2 = boto3.client("ec2", region_name=region)

    try:
        reservations = ec2.describe_instances()["Reservations"]
    except Exception as e:
        print(f"  ⚠️  Could not describe EC2 instances: {e}\n")
        return

    for res in reservations:
        for instance in res["Instances"]:
            instance_id = instance["InstanceId"]
            state = instance["State"]["Name"]

            if state == "terminated":
                continue

            public_ip = instance.get("PublicIpAddress")
            if public_ip:
                # Get Name tag if available
                tags = {t["Key"]: t["Value"] for t in instance.get("Tags", [])}
                name = tags.get("Name", instance_id)

                f = finding(
                    severity="MEDIUM",
                    resource_type="EC2 Instance",
                    resource_id=f"{instance_id} ({name})",
                    region=region,
                    description=f"Instance has a public IP: {public_ip}. Verify this exposure is intentional.",
                )
                findings.append(f)
                print_finding(f)

    if not any(f["resource_type"] == "EC2 Instance" for f in findings):
        print("  ✅ No EC2 instances with unexpected public IPs found.\n")


# ─────────────────────────────────────────────
#  CHECK 5 — CLOUDTRAIL LOGGING
# ─────────────────────────────────────────────

def check_cloudtrail(findings, region="us-east-1"):
    print("[ 5/5 ] Checking CloudTrail logging status...")
    ct = boto3.client("cloudtrail", region_name=region)

    try:
        trails = ct.describe_trails(includeShadowTrails=False)["trailList"]
    except Exception as e:
        print(f"  ⚠️  Could not describe CloudTrail trails: {e}\n")
        return

    if not trails:
        f = finding(
            severity="HIGH",
            resource_type="CloudTrail",
            resource_id="N/A",
            region=region,
            description="No CloudTrail trails found. AWS API activity is not being logged.",
        )
        findings.append(f)
        print_finding(f)
        return

    for trail in trails:
        trail_name = trail["Name"]
        trail_arn = trail["TrailARN"]
        try:
            status = ct.get_trail_status(Name=trail_arn)
            if not status.get("IsLogging", False):
                f = finding(
                    severity="HIGH",
                    resource_type="CloudTrail",
                    resource_id=trail_name,
                    region=region,
                    description="CloudTrail trail exists but logging is DISABLED. API activity not recorded.",
                )
                findings.append(f)
                print_finding(f)
        except Exception as e:
            print(f"  ⚠️  Could not get status for trail {trail_name}: {e}")

    if not any(f["resource_type"] == "CloudTrail" for f in findings):
        print("  ✅ CloudTrail logging is active.\n")


# ─────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────

def generate_report(findings):
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H-%M-%SZ")
    filename = f"cspm_report_{timestamp}.json"

    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        severity_counts[f["severity"]] = severity_counts.get(f["severity"], 0) + 1

    report = {
        "scan_timestamp": timestamp,
        "total_findings": len(findings),
        "severity_summary": severity_counts,
        "findings": findings,
    }

    with open(filename, "w") as out:
        json.dump(report, out, indent=2)

    return filename, report


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    # ── Set your AWS region here ──
    REGION = "us-east-1"

    print("=" * 55)
    print("  AWS CSPM Scanner — Cloud Security Posture Check")
    print("=" * 55)
    print()

    findings = []

    check_s3_public_access(findings)
    check_security_groups(findings, region=REGION)
    check_iam_mfa(findings)
    check_ec2_public_ips(findings, region=REGION)
    check_cloudtrail(findings, region=REGION)

    # ── Summary ──
    print("=" * 55)
    print("  SCAN COMPLETE")
    print("=" * 55)

    if not findings:
        print("\n✅ No misconfigurations found. Your AWS posture looks good!\n")
    else:
        high   = sum(1 for f in findings if f["severity"] == "HIGH")
        medium = sum(1 for f in findings if f["severity"] == "MEDIUM")
        low    = sum(1 for f in findings if f["severity"] == "LOW")

        print(f"\n  Total findings : {len(findings)}")
        print(f"  🔴 HIGH        : {high}")
        print(f"  🟡 MEDIUM      : {medium}")
        print(f"  🟢 LOW         : {low}\n")

        filename, _ = generate_report(findings)
        print(f"  📄 Report saved to: {filename}\n")


if __name__ == "__main__":
    main()
