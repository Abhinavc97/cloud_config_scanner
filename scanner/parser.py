# scanner/parser.py
import json
import yaml

# --- Register a generic constructor for CloudFormation intrinsic functions --- #
def cfn_generic_constructor(loader, node):
    """
    Generic constructor for CloudFormation intrinsic functions. Converts, for example,
    '!Equals [ a, b ]' into {'Fn::Equals': [a, b]}.
    """
    tag = node.tag.lstrip('!')
    # Determine if the node is a sequence, mapping, or scalar
    if isinstance(node, yaml.SequenceNode):
        return {"Fn::" + tag: loader.construct_sequence(node)}
    elif isinstance(node, yaml.MappingNode):
        return {"Fn::" + tag: loader.construct_mapping(node)}
    else:
        return {"Fn::" + tag: loader.construct_scalar(node)}

# Register the constructor for commonly used CloudFormation intrinsic function tags.
for intrinsic in ["Equals", "Ref", "Select", "GetAtt", "GetAZs", "Join"]:
    yaml.SafeLoader.add_constructor("!"+intrinsic, cfn_generic_constructor)

# --- End of intrinsic functions registration --- #

def parse_file(file_path: str) -> dict:
    """
    Read and parse an actual cloud configuration file.
    Supports JSON and YAML formats for CloudFormation, ARM templates,
    Kubernetes manifests, etc., and transforms them into an internal
    format that uses a top-level "resource" key.
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            # Limit file size to prevent memory issues (10MB max)
            max_size = 10 * 1024 * 1024  # 10MB
            content = f.read(max_size)
            if f.read(1):  # Check if there's more content
                raise ValueError(f"File {file_path} is too large (>10MB)")
    except UnicodeDecodeError:
        raise ValueError(f"File {file_path} is not valid UTF-8 text")
    except IOError as e:
        raise ValueError(f"Cannot read file {file_path}: {e}")

    # Attempt JSON first
    try:
        parsed = json.loads(content)
    except json.JSONDecodeError:
        # For YAML, allow multiple documents (e.g., Kubernetes manifests)
        documents = list(yaml.safe_load_all(content))
        if len(documents) == 1:
            parsed = documents[0]
        else:
            # If there are multiple documents, assume they are separate Kubernetes manifests.
            k8s_resources = {}
            for doc in documents:
                if doc and isinstance(doc, dict) and "kind" in doc:
                    kind = doc.get("kind", "").lower()
                    name = doc.get("metadata", {}).get("name", "unnamed")
                    key = map_k8s_kind(kind)
                    if key not in k8s_resources:
                        k8s_resources[key] = {}
                    k8s_resources[key][name] = doc
            if k8s_resources:
                return {"resource": k8s_resources}
            else:
                # Fall back to first document
                parsed = documents[0]

    # At this point, parsed should be a dictionary.
    if isinstance(parsed, dict):
        # Transform CloudFormation template if "Resources" key exists.
        if "Resources" in parsed:
            return transform_cloudformation(parsed)
        # Transform ARM template if "resources" key exists.
        if "resources" in parsed:
            return transform_arm_template(parsed)
        # Transform Kubernetes manifest if "kind" exists.
        if "kind" in parsed:
            return transform_kubernetes(parsed)
    
    # If not a recognized format, return the parsed object as is.
    return parsed

def transform_cloudformation(template: dict) -> dict:
    """
    Transform a CloudFormation template into our internal format.
    CloudFormation templates use a "Resources" key. Each resource has a "Type"
    (e.g. "AWS::S3::Bucket") and a "Properties" key.
    """
    new_dict = {"resource": {}}
    for res_name, res_val in template.get("Resources", {}).items():
        cfn_type = res_val.get("Type", "")
        internal_type = map_cfn_type(cfn_type)
        if internal_type not in new_dict["resource"]:
            new_dict["resource"][internal_type] = {}
        # Use the Properties sub-dictionary if available.
        properties = res_val.get("Properties", res_val)
        new_dict["resource"][internal_type][res_name] = properties
    return new_dict

def transform_arm_template(template: dict) -> dict:
    """
    Transform an ARM template into our internal format.
    ARM templates typically have a top-level "resources" list; each resource has a "type"
    and "name". This function builds a dictionary keyed by an internal type.
    """
    new_dict = {"resource": {}}
    for res in template.get("resources", []):
        arm_type = res.get("type", "")
        internal_type = map_arm_type(arm_type)
        res_name = res.get("name", "unnamed")
        if internal_type not in new_dict["resource"]:
            new_dict["resource"][internal_type] = {}
        new_dict["resource"][internal_type][res_name] = res
    return new_dict

def transform_kubernetes(manifest: dict) -> dict:
    """
    Transform a single Kubernetes manifest into our internal format.
    This function maps the "kind" field to an internal type (for example,
    "Deployment" -> "k8s_deployment", "Pod" -> "k8s_pod").
    """
    kind = manifest.get("kind", "").lower()
    internal_type = map_k8s_kind(kind)
    name = manifest.get("metadata", {}).get("name", "unnamed")
    return {"resource": {internal_type: {name: manifest}}}

def map_cfn_type(cfn_type: str) -> str:
    """
    Map a CloudFormation resource type to the internal type format.
    """
    mapping = {
        "AWS::S3::Bucket": "aws_s3_bucket",
        "AWS::EC2::Instance": "aws_ec2_instance",
        # Add additional mappings as required.
    }
    return mapping.get(cfn_type, cfn_type.lower().replace("::", "_"))

def map_arm_type(arm_type: str) -> str:
    """
    Map an ARM resource type to the internal type format.
    """
    mapping = {
        "Microsoft.Storage/storageAccounts": "azure_storage_account",
        "Microsoft.Sql/servers": "azure_sql_server",
        "Microsoft.Network/networkSecurityGroups": "azure_nsg",
        # Add additional mappings as required.
    }
    return mapping.get(arm_type, arm_type.lower().replace("/", "_"))

def map_k8s_kind(kind: str) -> str:
    """
    Map a Kubernetes resource "kind" to an internal type.
    """
    mapping = {
        "deployment": "k8s_deployment",
        "pod": "k8s_pod",
        # You can add more kinds as needed.
    }
    return mapping.get(kind, "k8s_other")