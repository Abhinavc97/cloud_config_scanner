# tests/test_scanner.py
import os
import tempfile
from scanner.scanner import scan_file

def test_scan_file_multiple_resources():
    sample_yaml = """
resource:
  aws_s3_bucket:
    aws_bucket:
      acl: public-read
      versioning: false
  azure_storage_account:
    azure_store:
      allowBlobPublicAccess: true
      enable_https_traffic_only: false
  gcp_storage_bucket:
    gcp_bucket:
      iamConfiguration:
        publicAccessPrevention: inherited
      versioning: false
"""
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(sample_yaml)
        tmp_path = tmp.name
    findings = scan_file(tmp_path)
    os.unlink(tmp_path)
    
    # Verify findings for each resource
    assert "aws_s3_bucket.aws_bucket" in findings
    assert "AWS S3 bucket is publicly accessible." in findings["aws_s3_bucket.aws_bucket"]
    
    assert "azure_storage_account.azure_store" in findings
    assert "Azure Storage Account allows public blob access." in findings["azure_storage_account.azure_store"]
    
    assert "gcp_storage_bucket.gcp_bucket" in findings
    assert "GCP Storage Bucket does not enforce public access prevention." in findings["gcp_storage_bucket.gcp_bucket"]