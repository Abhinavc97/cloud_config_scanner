# scanner/scanner.py
import sys
from scanner.parser import parse_file
from scanner.rules import (
    check_aws_s3_bucket,
    check_aws_iam_role,
    check_aws_security_group,
    check_azure_storage_account,
    check_azure_sql_server,
    check_azure_nsg,
    check_gcp_storage_bucket,
    check_gcp_firewall,
    check_gcp_iam_policy,
    composite_aws_s3_bucket,  # New composite function for AWS S3 bucket
    composite_k8s_deployment,  # New composite function for Kubernetes resources
)

RULES_MAPPING = {
    # AWS
    "aws_s3_bucket": composite_aws_s3_bucket,
    "aws_iam_role": check_aws_iam_role,
    "aws_security_group": check_aws_security_group,
    # Azure
    "azure_storage_account": check_azure_storage_account,
    "azure_sql_server": check_azure_sql_server,
    "azure_nsg": check_azure_nsg,
    # GCP
    "gcp_storage_bucket": check_gcp_storage_bucket,
    "gcp_firewall": check_gcp_firewall,
    "gcp_iam_policy": check_gcp_iam_policy,
    # Kubernetes (for CNAS-1, CNAS-7, CNAS-9, CNAS-10, CNAS-5)
    "k8s_deployment": composite_k8s_deployment,
    "k8s_pod": composite_k8s_deployment,  # For demonstration, pods use the same checks as deployments.
}

def scan_file(file_path: str) -> dict:
    findings = {}
    try:
        config = parse_file(file_path)
    except Exception as e:
        findings['error'] = f"Failed to parse file: {str(e)}"
        return findings

    resources = config.get('resource', {})

    for resource_type, resource_entries in resources.items():
        for resource_name, resource in resource_entries.items():
            resource_copy = resource.copy()
            resource_copy['type'] = resource_type
            issues = []
            if resource_type in RULES_MAPPING:
                issues = RULES_MAPPING[resource_type](resource_copy)
            else:
                issues.append(f"No rules defined for this resource type.: {resource_type}")
            if issues:
                findings[f"{resource_type}.{resource_name}"] = issues
    return findings

def main():
    if len(sys.argv) != 2:
        print("Usage: python -m scanner.scanner <config_file>")
        sys.exit(1)
    file_path = sys.argv[1]
    result = scan_file(file_path)
    print(result)

if __name__ == '__main__':
    main()