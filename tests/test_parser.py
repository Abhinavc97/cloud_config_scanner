# tests/test_parser.py
import os
import tempfile
from scanner.parser import parse_file

def test_parse_json():
    sample_json = '{"resource": {"aws_s3_bucket": {"my_bucket": {"acl": "private", "versioning": true}}}}'
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(sample_json)
        tmp_path = tmp.name
    result = parse_file(tmp_path)
    os.unlink(tmp_path)
    assert "resource" in result
    assert result["resource"]["aws_s3_bucket"]["my_bucket"]["acl"] == "private"

def test_parse_yaml():
    sample_yaml = """
resource:
  aws_s3_bucket:
    my_bucket:
      acl: public-read
      versioning: false
"""
    with tempfile.NamedTemporaryFile("w+", delete=False) as tmp:
        tmp.write(sample_yaml)
        tmp_path = tmp.name
    result = parse_file(tmp_path)
    os.unlink(tmp_path)
    assert "resource" in result
    assert result["resource"]["aws_s3_bucket"]["my_bucket"]["acl"] == "public-read"