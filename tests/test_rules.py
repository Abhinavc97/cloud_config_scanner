# tests/test_rules.py
from scanner.rules import (
    is_bucket_public,
    check_aws_s3_bucket,
    check_aws_iam_role,
    check_aws_security_group,
    check_azure_storage_account,
    check_azure_sql_server,
    check_azure_nsg,
    check_gcp_storage_bucket,
    check_gcp_firewall,
    check_gcp_iam_policy,
)

# AWS tests
def test_is_bucket_public_true():
    bucket = {"acl": "public-read"}
    assert is_bucket_public(bucket) is True

def test_is_bucket_public_false():
    bucket = {"acl": "private"}
    assert is_bucket_public(bucket) is False

def test_check_aws_s3_bucket():
    resource = {
        "acl": "public-read",
        "versioning": False,
        "type": "aws_s3_bucket"
    }
    issues = check_aws_s3_bucket(resource)
    assert "AWS S3 bucket is publicly accessible." in issues
    assert "AWS S3 bucket does not have versioning enabled." in issues

def test_check_aws_iam_role():
    resource = {
        "permissions": ["s3:ListBucket", "*"],
        "type": "aws_iam_role"
    }
    issues = check_aws_iam_role(resource)
    assert "AWS IAM role has overly permissive policy (wildcard permissions)." in issues

def test_check_aws_security_group():
    resource = {
        "inbound_rules": [{"cidr": "0.0.0.0/0", "port": 22}],
        "type": "aws_security_group"
    }
    issues = check_aws_security_group(resource)
    assert "AWS Security Group rule allows open access on port 22." in issues

# Azure tests
def test_check_azure_storage_account():
    resource = {
        "allowBlobPublicAccess": True,
        "enable_https_traffic_only": False,
        "type": "azure_storage_account"
    }
    issues = check_azure_storage_account(resource)
    assert "Azure Storage Account allows public blob access." in issues
    assert "Azure Storage Account is not enforcing HTTPS traffic only." in issues

def test_check_azure_sql_server():
    resource = {
        "publicNetworkAccess": "Enabled",
        "minimalTlsVersion": "1.0",
        "type": "azure_sql_server"
    }
    issues = check_azure_sql_server(resource)
    assert "Azure SQL Server allows public network access." in issues
    assert "Azure SQL Server has an insecure TLS version configured." in issues

def test_check_azure_nsg():
    resource = {
        "security_rules": [
            {"sourceAddressPrefix": "*", "sourcePortRange": "*"}
        ],
        "type": "azure_nsg"
    }
    issues = check_azure_nsg(resource)
    assert "Azure NSG rule may be overly permissive." in issues

# GCP tests
def test_check_gcp_storage_bucket():
    resource = {
        "iamConfiguration": {"publicAccessPrevention": "inherited"},
        "versioning": False,
        "type": "gcp_storage_bucket"
    }
    issues = check_gcp_storage_bucket(resource)
    assert "GCP Storage Bucket does not enforce public access prevention." in issues
    assert "GCP Storage Bucket does not have versioning enabled." in issues

def test_check_gcp_firewall():
    resource = {
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}],
        "type": "gcp_firewall"
    }
    issues = check_gcp_firewall(resource)
    assert "GCP Firewall rule allows open access to the internet." in issues

def test_check_gcp_iam_policy():
    resource = {
        "bindings": [
            {"role": "roles/editor", "members": ["user:example@example.com", "allUsers"]}
        ],
        "type": "gcp_iam_policy"
    }
    issues = check_gcp_iam_policy(resource)
    assert "GCP IAM binding uses risky role roles/editor." in issues
    assert "GCP IAM binding is granting access to all users." in issues


def test_validate_resource_input():
    from scanner.rules import validate_resource_input
    
    # Valid resource
    valid_resource = {"type": "aws_s3_bucket", "acl": "private"}
    assert validate_resource_input(valid_resource, "aws_s3_bucket") is True
    
    # Invalid resource (not dict)
    assert validate_resource_input("not_a_dict", "aws_s3_bucket") is False
    
    # Type mismatch
    wrong_type = {"type": "azure_storage", "acl": "private"}
    assert validate_resource_input(wrong_type, "aws_s3_bucket") is False

def test_get_containers_from_resource():
    from scanner.rules import get_containers_from_resource
    
    # Pod resource
    pod_resource = {
        "spec": {
            "containers": [{"name": "test", "image": "nginx:1.0"}]
        }
    }
    containers = get_containers_from_resource(pod_resource)
    assert len(containers) == 1
    assert containers[0]["name"] == "test"
    
    # Deployment resource
    deployment_resource = {
        "spec": {
            "template": {
                "spec": {
                    "containers": [{"name": "app", "image": "app:1.0"}]
                }
            }
        }
    }
    containers = get_containers_from_resource(deployment_resource)
    assert len(containers) == 1
    assert containers[0]["name"] == "app"
    
    # Empty resource
    assert get_containers_from_resource({}) == []