# ☁️ Cloud Configuration Security Scanner (CCS)

[![Python](https://img.shields.io/badge/python-3.7+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-passing-brightgreen.svg)](tests/)

**Detect and prevent cloud misconfigurations *before* they reach production.**

A production-ready, security-hardened tool that scans **AWS**, **Azure**, **GCP**, and **Kubernetes** IaC files for misconfigurations directly in your CI/CD pipeline or development environment. Built with enterprise-grade security practices and comprehensive OWASP CNAS compliance.

---

## 🚀 Overview

Cloud misconfigurations account for **95% of successful cyber attacks** on cloud infrastructure. **CCS** shifts security left by catching these issues during development, before they reach production environments.

### Why CCS?

* **🔒 Security-First Design:** Hardened against common vulnerabilities with proper input validation and secure API handling
* **🌐 Multi-Cloud Coverage:** Native support for AWS, Azure, GCP, and Kubernetes configurations
* **📋 OWASP CNAS Compliant:** Implements industry-standard Cloud-Native Application Security checks
* **⚡ Developer-Friendly:** Lightweight CLI with comprehensive error reporting and actionable recommendations
* **🧪 Production-Ready:** Extensive test coverage, proper error handling, and enterprise configuration options

---

## 🏗️ Architecture & Features

### 🛡️ Security Capabilities

✅ **Multi-Cloud Infrastructure as Code Support:**
- **AWS CloudFormation** (with intrinsic functions: `!Ref`, `!GetAtt`, `!Select`, etc.)
- **Azure ARM Templates** 
- **GCP Deployment Manager**
- **Kubernetes Manifests** (single and multi-document YAML)
- **Terraform Configuration** (basic support)

✅ **OWASP CNAS Top 10 Security Checks:**
- **CNAS-1:** Insecure cloud/container/orchestration configuration
- **CNAS-3:** Improper authentication & authorization  
- **CNAS-5:** Insecure secrets storage (hardcoded credentials detection)
- **CNAS-6:** Over-permissive network policies
- **CNAS-7:** Components with known vulnerabilities (CVE integration)
- **CNAS-9:** Inadequate compute resource limits
- **CNAS-10:** Ineffective logging & monitoring

✅ **Enterprise Security Features:**
- Input validation and sanitization
- Secure HTTP handling with SSL verification
- Configurable vulnerability scanning APIs
- Memory-safe file processing (10MB limit)
- Semantic version comparison for security policies

### 🔧 Technical Features

✅ **Robust Error Handling:** Graceful failures with actionable error messages  
✅ **Extensible Rule Engine:** Easy addition of custom security rules  
✅ **Professional CLI:** Click-based interface with comprehensive help  
✅ **Comprehensive Testing:** 16+ unit tests covering all modules  
✅ **Memory Efficient:** Safe processing of large configuration files  

---

## 📁 Project Structure

```
cloud_config_scanner/
│
├── scanner/                    # Core security scanner package
│   ├── __init__.py             # Package initialization
│   ├── parser.py               # Multi-format IaC parser with CloudFormation support
│   ├── rules.py                # Security rules engine (OWASP CNAS compliance)
│   ├── scanner.py              # Core scanning logic and rule orchestration
│   └── reporter.py             # Formatted security reporting
│
├── tests/                      # Comprehensive test suite (16+ tests)
│   ├── test_parser.py          # Parser functionality tests
│   ├── test_rules.py           # Security rule validation tests
│   └── test_scanner.py         # End-to-end scanning workflow tests
│
├── examples/                   # Real-world example configurations
│   ├── aws_config.yaml         # AWS S3 misconfigurations
│   ├── azure_config.json       # Azure security issues
│   ├── gcp_config.yaml         # GCP access control problems
│   ├── Config.yaml             # Complex CloudFormation with intrinsics
│   └── terraform_example.tf    # Terraform configuration
│
├── cli.py                      # Professional CLI entry point
├── setup.py                    # Production package configuration
├── requirements.txt            # Pinned dependencies
└── README.md                   # Project documentation
```

---

## ⚙️ Installation

### Prerequisites
- Python 3.7+
- pip package manager

### Quick Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/cloud_config_scanner.git
cd cloud_config_scanner

# Create virtual environment
python -m venv ccs
source ccs/bin/activate      # On macOS/Linux
ccs\Scripts\activate         # On Windows

# Install dependencies
pip install -r requirements.txt

# Install the scanner
pip install -e .
```

### Dependencies
- **PyYAML ≥5.1** - Secure YAML parsing with CloudFormation intrinsics
- **click ≥7.0** - Professional CLI framework
- **requests ≥2.25.0** - Secure HTTP client for CVE APIs
- **packaging ≥20.0** - Semantic version comparison for security policies

---

## 🔍 Usage

### Command-Line Interface

```bash
# Scan any configuration file
ccs <config_file>

# Get help and usage information
ccs --help

# Alternative execution methods
python cli.py <config_file>
python -m scanner.reporter <config_file>
python -m scanner.scanner <config_file>
```

### Example Scans

```bash
# Test different cloud providers
ccs examples/aws_config.yaml      # AWS CloudFormation
ccs examples/azure_config.json    # Azure ARM Template
ccs examples/gcp_config.yaml      # GCP Configuration
ccs examples/Config.yaml          # Complex CloudFormation
ccs examples/terraform_example.tf # Terraform
```

### Environment Configuration

Optional environment variables for enhanced functionality:

```bash
# Enable vulnerability scanning (optional)
export CVE_API_ENDPOINT=https://your-vulnerability-api.com/api/v1

# Configure logging level
export LOG_LEVEL=INFO
```

---

## 🎯 Example Security Findings

### AWS S3 Bucket Misconfigurations
```bash
$ ccs examples/aws_config.yaml

Potential Issues Detected:

Resource: aws_s3_bucket.my_bucket
 - AWS S3 bucket is publicly accessible.
 - AWS S3 bucket does not have versioning enabled.
```

### Azure Multi-Resource Security Issues
```bash
$ ccs examples/azure_config.json

Potential Issues Detected:

Resource: azure_storage_account.myStorage
 - Azure Storage Account allows public blob access.
 - Azure Storage Account is not enforcing HTTPS traffic only.

Resource: azure_sql_server.mySQLServer
 - Azure SQL Server allows public network access.
 - Azure SQL Server has an insecure TLS version configured.

Resource: azure_nsg.myNSG
 - Azure NSG rule may be overly permissive.
```

### GCP Security Policy Violations
```bash
$ ccs examples/gcp_config.yaml

Potential Issues Detected:

Resource: gcp_storage_bucket.myBucket
 - GCP Storage Bucket does not enforce public access prevention.
 - GCP Storage Bucket does not have versioning enabled.

Resource: gcp_firewall.myFirewall
 - GCP Firewall rule allows open access to the internet.

Resource: gcp_iam_policy.myIamPolicy
 - GCP IAM binding uses risky role roles/editor.
 - GCP IAM binding is granting access to all users.
```

---

## 🧠 How It Works

### 1️⃣ **Intelligent Parsing**

CCS handles complex IaC formats with enterprise-grade parsing:

```yaml
# CloudFormation with intrinsic functions
Conditions:
  CreateDeliveryChannel: !Equals
    - !Ref DeliveryChannelExists
    - "false"

Resources:
  Ec2Volume:
    Properties:
      AvailabilityZone: !Select [0, !GetAZs]
      Tags:
        - Key: !Ref Ec2VolumeTagKey
          Value: Ec2VolumeTagValue
```

**Parsing Features:**
- **Secure file handling:** UTF-8 validation, size limits (10MB), memory protection
- **Multi-document YAML:** Kubernetes manifests with multiple resources
- **CloudFormation intrinsics:** Full support for `!Ref`, `!GetAtt`, `!Select`, `!Join`, etc.
- **Error resilience:** Graceful handling of malformed configurations

### 2️⃣ **Security Rule Engine**

**AWS Security Rules:**
- S3 bucket public access detection and versioning validation
- IAM role excessive permissions analysis (`*` wildcard detection)
- Security group open access validation (non-standard ports)
- Hardcoded secrets scanning across all resource properties

**Azure Security Rules:**
- Storage account public access configuration
- SQL Server network exposure and TLS security (semantic version comparison)
- Network Security Group rule permissiveness analysis

**GCP Security Rules:**
- Storage bucket public access prevention enforcement
- Firewall internet exposure detection (`0.0.0.0/0` analysis)
- IAM policy risky role assignments and public access grants

**Kubernetes/Container Security (OWASP CNAS):**
- Container root user execution detection
- Resource limits and requests validation
- Container image tag security (`latest` tag prevention)
- Vulnerability scanning integration (configurable CVE APIs)
- Logging and monitoring configuration validation

### 3️⃣ **Advanced Security Features**

**Input Validation:**
```python
def validate_resource_input(resource: dict, resource_type: str) -> bool:
    """Validate resource format and type consistency."""
    if not isinstance(resource, dict):
        return False
    if resource.get('type') and resource['type'] != resource_type:
        return False
    return True
```

**Secure CVE Integration:**
```python
# Configurable vulnerability scanning with secure defaults
response = requests.get(
    f"{api_endpoint}/vulnerabilities",
    params={"image": image},
    timeout=10,
    verify=True,  # SSL verification enforced
    headers={'User-Agent': 'cloud-config-scanner/0.1.0'}
)
```

**Semantic Version Security:**
```python
# Proper TLS version comparison (not string-based)
if version.parse(tls_version) < version.parse('1.2'):
    issues.append("Azure SQL Server has insecure TLS configuration.")
```

---

## 🧪 Testing & Quality Assurance

### Comprehensive Test Suite

```bash
# Run all tests (16+ test cases)
pytest tests/ -v

# Run specific test modules
pytest tests/test_parser.py -v      # Configuration parsing tests
pytest tests/test_rules.py -v       # Security rule validation tests  
pytest tests/test_scanner.py -v     # End-to-end workflow tests

# Test coverage report
pytest tests/ --cov=scanner --cov-report=html
```

### Test Coverage
- **Parser Module:** JSON/YAML parsing, CloudFormation intrinsics, multi-document handling
- **Security Rules:** All cloud provider rules, input validation, container security
- **Scanner Integration:** Multi-resource scanning, error handling, resource type mapping
- **Edge Cases:** Invalid inputs, large files, network failures, malformed configurations

**Expected Output:**
```
=================== test session starts ====================
collected 18 items

tests/test_parser.py ....
tests/test_rules.py ..............
tests/test_scanner.py ..

=================== 18 passed in 0.08s ===================
```

---

## 🔧 Supported Configurations

### Input Format Support

| Cloud Provider | Format | Extensions | Intrinsic Functions | Example |
|---------------|--------|------------|-------------------|---------|
| **AWS** | CloudFormation | `.yaml`, `.json` | ✅ `!Ref`, `!GetAtt`, `!Select` | `examples/aws_config.yaml` |
| **Azure** | ARM Templates | `.json` | ⚠️ Limited | `examples/azure_config.json` |
| **GCP** | Deployment Manager | `.yaml` | ❌ None | `examples/gcp_config.yaml` |
| **Kubernetes** | Manifests | `.yaml` | ❌ None | `examples/Config.yaml` |
| **Terraform** | Configuration | `.tf` | ⚠️ Basic | `examples/terraform_example.tf` |

### Security Check Matrix

| Resource Type | Public Access | Encryption | Versioning | Network Security | IAM/RBAC |
|--------------|---------------|------------|------------|-----------------|-----------|
| **AWS S3** | ✅ | ⚠️ Planned | ✅ | N/A | ⚠️ Planned |
| **Azure Storage** | ✅ | ⚠️ Planned | ⚠️ Planned | ✅ HTTPS | ⚠️ Planned |
| **GCP Storage** | ✅ | ⚠️ Planned | ✅ | N/A | ✅ |
| **Kubernetes Pods** | N/A | N/A | N/A | ⚠️ Planned | ✅ Security Context |
| **Network Resources** | ✅ | N/A | N/A | ✅ | ✅ |

---

## 🚀 CI/CD Integration

### GitHub Actions Example

```yaml
name: Security Scan
on: [push, pull_request]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install CCS
        run: |
          pip install -e .
      
      - name: Scan Infrastructure
        run: |
          find . -name "*.yaml" -o -name "*.json" | xargs -I {} ccs {}
```

### GitLab CI Example

```yaml
security_scan:
  stage: security
  image: python:3.9
  script:
    - pip install -e .
    - find . -name "*.yaml" -o -name "*.json" | xargs -I {} ccs {}
  only:
    - merge_requests
    - main
```

---

## 🛠️ Development & Extension

### Adding Custom Security Rules

```python
# In scanner/rules.py

def check_custom_security_rule(resource: dict) -> list:
    """Add your custom security validation."""
    if not validate_resource_input(resource, 'your_resource_type'):
        return ["Invalid resource format"]
    
    issues = []
    if resource.get('dangerous_setting'):
        issues.append("Custom security violation detected.")
    return issues

# In scanner/scanner.py RULES_MAPPING
"your_resource_type": check_custom_security_rule,
```

### Contributing Guidelines

1. **Fork the repository** and create a feature branch
2. **Add security rules** following the existing pattern
3. **Write comprehensive tests** for new functionality
4. **Update documentation** and example configurations
5. **Run the full test suite** (`pytest tests/ -v`)
6. **Submit a Pull Request** with detailed description

---

## 📈 Roadmap

### Immediate Priorities
🔹 **Enhanced Terraform support** - Complete HCL parsing and resource mapping  
🔹 **Encryption validation** - At-rest and in-transit encryption checks  
🔹 **Custom rule configuration** - YAML-based rule definitions  
🔹 **SARIF output format** - GitHub security tab integration  

### Medium Term Goals
🔹 **Real-time CVE integration** - Live vulnerability database APIs  
🔹 **Policy as Code** - Organization-specific security policies  
🔹 **IDE plugins** - VS Code and IntelliJ integration  
🔹 **Performance optimization** - Async scanning for large configurations  

### Long Term Vision
🔹 **Machine learning** - Anomaly detection in cloud configurations  
🔹 **Auto-remediation** - Suggested fixes for detected issues  
🔹 **Compliance frameworks** - SOC2, PCI-DSS, HIPAA policy mapping  
🔹 **Enterprise dashboard** - Web UI for security teams  

---

## 📊 Performance & Limits

- **File size limit:** 10MB per configuration file
- **Memory usage:** ~50MB baseline, scales with file complexity
- **Scan speed:** ~100 resources per second on modern hardware
- **Concurrent scans:** Supported via CLI scripting
- **Network timeouts:** 10 seconds for CVE API calls
- **Error resilience:** Graceful degradation on parsing failures

---

## 🤝 Contributing

We welcome contributions from the security and DevOps community!

**Areas for Contribution:**
- New cloud provider support (Oracle Cloud, IBM Cloud, etc.)
- Additional security rules and OWASP CNAS categories
- Performance optimizations and async processing
- Documentation improvements and example configurations

**Development Setup:**
```bash
git clone https://github.com/yourusername/cloud_config_scanner.git
cd cloud_config_scanner
python -m venv dev
source dev/bin/activate
pip install -e ".[dev]"
pytest tests/
```

---

## 📄 License

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

---

## 👤 Author & Acknowledgments

**Abhinav Chaudhary**  
*Cybersecurity Researcher | Security Engineer | SOC Analyst*

📧 **Contact:** [abhi.199724@gmail.com](mailto:abhi.199724@gmail.com)  
🔗 **LinkedIn:** [linkedin.com/in/abhinavc97](https://linkedin.com/in/abhinavc97)  
💻 **GitHub:** [github.com/abhinavc97](https://github.com/abhinavc97)

### Special Thanks
- **[OWASP Cloud-Native Application Security Top 10](https://owasp.org/www-project-cloud-native-application-security-top-10/)** - Security framework foundation
- **[AWS Well-Architected Framework](https://aws.amazon.com/architecture/well-architected/)** - Cloud security best practices
- **[CIS Benchmarks](https://www.cisecurity.org/cis-benchmarks/)** - Industry security standards
- **[Prowler](https://github.com/prowler-cloud/prowler)** & **[CloudSploit](https://github.com/aquasecurity/cloudsploit)** - Inspiration for cloud security automation

---

## 🔒 Security Disclosure

If you discover a security vulnerability in CCS itself, please send an email to [abhi.199724@gmail.com](mailto:abhi.199724@gmail.com). All security vulnerabilities will be promptly addressed.

---

**⭐ Star this repository if CCS helps secure your cloud infrastructure!**

*Built with security-first principles for the cloud-native era.*
