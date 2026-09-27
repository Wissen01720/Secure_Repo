# securerepo:ignore-file - benchmark corpus: deliberately insecure infrastructure definitions.
resource "aws_s3_bucket_acl" "logs" {
  acl = "public-read" # expect: SR-IAC-002
}

resource "aws_db_instance" "database" {
  publicly_accessible = true  # expect: SR-IAC-004
  storage_encrypted   = false # expect: SR-IAC-003
}

resource "aws_security_group_rule" "ssh" {
  cidr_blocks = ["0.0.0.0/0"] # expect: SR-IAC-001
}
