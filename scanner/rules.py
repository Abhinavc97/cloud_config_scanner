# scanner/rules.py
import requests
try:
    from packaging import version
except ImportError:
    # Fallback for string comparison
    version = None
import re
import os

# ---------------- AWS Rules (existing) ---------------- #

def is_bucket_public(resource: dict) -> bool:
    acl = resource.get('acl', '').lower()
    return acl in ['public-read', 'public-read-write']

def check_aws_s3_bucket(resource: dict) -> list:
    issues = []
    if is_bucket_public(resource):
        issues.append("AWS S3 bucket is publicly accessible.")
    if not resource.get('versioning', False):
        issues.append("AWS S3 bucket does not have versioning enabled.")
    return issues

def check_aws_iam_role(resource: dict) -> list:
    issues = []
    permissions = resource.get('permissions', [])
    if any(perm == "*" or perm.endswith(":*") for perm in permissions):
        issues.append("AWS IAM role has overly permissive policy (wildcard permissions).")
    return issues

def check_aws_security_group(resource: dict) -> list:
    issues = []
    rules = resource.get('inbound_rules', [])
    for rule in rules:
        cidr = rule.get('cidr', '')
        port = rule.get('port', 0)
        if cidr == "0.0.0.0/0" and port not in [80, 443]:
            issues.append(f"AWS Security Group rule allows open access on port {port}.")
    return issues

# ---------------- Azure Rules (existing) ---------------- #

def check_azure_storage_account(resource: dict) -> list:
    issues = []
    if resource.get('allowBlobPublicAccess', True):
        issues.append("Azure Storage Account allows public blob access.")
    if not resource.get('enable_https_traffic_only', False):
        issues.append("Azure Storage Account is not enforcing HTTPS traffic only.")
    return issues

def check_azure_sql_server(resource: dict) -> list:
    issues = []
    if resource.get('publicNetworkAccess', 'Enabled').lower() != 'disabled':
        issues.append("Azure SQL Server allows public network access.")
    
    tls_version = resource.get('minimalTlsVersion', '1.0')
    try:
        if version and version.parse(tls_version) < version.parse('1.2'):
            issues.append("Azure SQL Server has an insecure TLS version configured.")
        elif not version:
            # Fallback to string comparison for common cases
            if tls_version in ['1.0', '1.1']:
                issues.append("Azure SQL Server has an insecure TLS version configured.")
    except Exception:
        issues.append(f"Azure SQL Server has invalid TLS version: {tls_version}")
    
    return issues

def check_azure_nsg(resource: dict) -> list:
    issues = []
    security_rules = resource.get('security_rules', [])
    for rule in security_rules:
        if rule.get('sourceAddressPrefix', '') == '*' or rule.get('sourcePortRange', '') == '*':
            issues.append("Azure NSG rule may be overly permissive.")
    return issues

# ---------------- GCP Rules (existing) ---------------- #

def check_gcp_storage_bucket(resource: dict) -> list:
    issues = []
    iam_config = resource.get('iamConfiguration', {})
    if iam_config.get('publicAccessPrevention', 'inherited').lower() != 'enforced':
        issues.append("GCP Storage Bucket does not enforce public access prevention.")
    if not resource.get('versioning', False):
        issues.append("GCP Storage Bucket does not have versioning enabled.")
    return issues

def check_gcp_firewall(resource: dict) -> list:
    issues = []
    source_ranges = resource.get('sourceRanges', [])
    if "0.0.0.0/0" in source_ranges:
        issues.append("GCP Firewall rule allows open access to the internet.")
    return issues

def check_gcp_iam_policy(resource: dict) -> list:
    issues = []
    bindings = resource.get('bindings', [])
    for binding in bindings:
        role = binding.get('role', '')
        members = binding.get('members', [])
        if role in ['roles/editor', 'roles/owner']:
            issues.append(f"GCP IAM binding uses risky role {role}.")
        if any(member in ['allUsers', 'allAuthenticatedUsers'] for member in members):
            issues.append("GCP IAM binding is granting access to all users.")
    return issues

# ---------------- New Rules for Additional CNAS Checks ---------------- #

# CNAS-5: Insecure Secrets Storage
def check_hardcoded_secrets(resource: dict) -> list:
    issues = []
    # Scan top-level keys of the resource for potential secrets.
    for key, value in resource.items():
        if any(word in key.lower() for word in ["secret", "password", "api_key"]):
            # If the value is a non-empty string and does not appear to be a template variable
            if isinstance(value, str) and value and not (value.startswith("{{") and value.endswith("}}")):
                issues.append(f"Potential hardcoded secret found in key '{key}'.")
    return issues

def validate_resource_input(resource: dict, resource_type: str) -> bool:
    """Validate that resource is properly formatted."""
    if not isinstance(resource, dict):
        return False
    
    # Check if resource type matches expected
    if resource.get('type') and resource['type'] != resource_type:
        return False
    
    return True

def get_containers_from_resource(resource: dict) -> list:
    """Extract containers from various Kubernetes resource types."""
    # For Pods (direct spec.containers)
    if 'spec' in resource and 'containers' in resource.get('spec', {}):
        return resource['spec']['containers']
    
    # For Deployments, ReplicaSets, etc. (spec.template.spec.containers)
    if 'spec' in resource and 'template' in resource.get('spec', {}):
        template_spec = resource['spec']['template'].get('spec', {})
        return template_spec.get('containers', [])
    
    return []

# CNAS-1: Container Security (check if container runs as non-root)
def check_k8s_pod_security(resource: dict) -> list:
    issues = []
    containers = get_containers_from_resource(resource)
    for container in containers:
        security_context = container.get('securityContext', {})
        if not security_context.get('runAsNonRoot', False):
            issues.append(f"Container '{container.get('name', 'unknown')}' may be running as root.")
    return issues

# CNAS-7: Vulnerable Container Images via CVE API Check
def check_container_image_vulnerabilities(image: str) -> list:
    """Check container image for known vulnerabilities using external API."""
    issues = []
    
    # Validate image name format
    if not image or not re.match(r'^[a-zA-Z0-9._/-]+:[a-zA-Z0-9._-]+$', image):
        return []  # Skip invalid images silently
    
    # Use configurable API endpoint
    api_endpoint = os.getenv('CVE_API_ENDPOINT')
    if not api_endpoint:
        # Skip vulnerability check if no API configured
        return []
    
    try:
        response = requests.get(
            f"{api_endpoint}/vulnerabilities",
            params={"image": image},
            timeout=10,
            verify=True,  # Ensure SSL verification
            headers={'User-Agent': 'cloud-config-scanner/0.1.0'}
        )
        
        if response.status_code == 200:
            data = response.json()
            if data.get("vulnerable", False):
                vulnerabilities = data.get("issues", [])
                if vulnerabilities:
                    issues.append(f"Image '{image}' has known vulnerabilities: " + ", ".join(vulnerabilities))
                else:
                    issues.append(f"Image '{image}' is marked as vulnerable.")
        elif response.status_code == 404:
            # Image not found in vulnerability database - not an error
            pass
        else:
            # Log but don't add to issues - API problems shouldn't block scanning
            pass
    except requests.exceptions.RequestException:
        # Network issues shouldn't block the scan
        pass
    
    return issues

def check_container_image(resource: dict) -> list:
    issues = []
    containers = get_containers_from_resource(resource)
    for container in containers:
        image = container.get('image', '')
        if not image or image.endswith(":latest"):
            issues.append(f"Container image '{image}' should not use the 'latest' tag or be unspecified.")
        issues.extend(check_container_image_vulnerabilities(image))
    return issues

# CNAS-9: Inadequate Compute Resource Quota Limits (Check for missing resource limits)
def check_resource_limits(resource: dict) -> list:
    issues = []
    containers = get_containers_from_resource(resource)
    for container in containers:
        resources = container.get('resources', {})
        requests = resources.get('requests', {})
        limits = resources.get('limits', {})
        if not requests or not limits:
            issues.append(f"Resource limits and requests are missing for container '{container.get('name', 'unknown')}'.")
    return issues

# CNAS-10: Ineffective Logging & Monitoring (Very basic check)
def check_logging_monitoring(resource: dict) -> list:
    issues = []
    # This is a placeholder check; in many environments you'd expect logging/monitoring settings to be explicitly defined.
    if not resource.get('logging', {}).get('enabled', False):
        issues.append("Logging and monitoring configuration is missing or disabled.")
    return issues

# Composite functions to group multiple checks for the same resource type.
def composite_aws_s3_bucket(resource: dict) -> list:
    issues = []
    issues.extend(check_aws_s3_bucket(resource))
    issues.extend(check_hardcoded_secrets(resource))
    return issues

def composite_k8s_deployment(resource: dict) -> list:
    issues = []
    issues.extend(check_container_image(resource))    # CNAS-7
    issues.extend(check_resource_limits(resource))      # CNAS-9
    issues.extend(check_k8s_pod_security(resource))       # CNAS-1
    issues.extend(check_logging_monitoring(resource))     # CNAS-10
    issues.extend(check_hardcoded_secrets(resource))      # CNAS-5 (if any secrets in the pod spec)
    return issues