#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "Usage: $0 FILE BUCKET EXPECTED_BUCKET_OWNER REGION RETENTION_DAYS [PREFIX]" >&2
  exit 2
}

[[ $# -ge 5 && $# -le 6 ]] || usage
file=$1
bucket=$2
expected_owner=$3
region=$4
retention_days=$5
prefix=${6:-openshield/audit}
[[ "$prefix" != /* && "$prefix" != *".."* ]] || { echo "PREFIX must be a relative S3 key prefix without .." >&2; exit 1; }

[[ -f "$file" && ! -L "$file" ]] || { echo "Export must be a regular, non-symlink file" >&2; exit 1; }
[[ "$expected_owner" =~ ^[0-9]{12}$ ]] || { echo "EXPECTED_BUCKET_OWNER must be a 12-digit AWS account ID" >&2; exit 1; }
[[ "$retention_days" =~ ^[1-9][0-9]*$ ]] && (( retention_days >= 1 && retention_days <= 36500 )) || {
  echo "RETENTION_DAYS must be between 1 and 36500; choose an approved retention period" >&2
  exit 1
}
command -v aws >/dev/null || { echo "AWS CLI v2 is required" >&2; exit 1; }
aws_version=$(aws --version 2>&1)
[[ "$aws_version" == aws-cli/2.* ]] || { echo "AWS CLI v2 is required" >&2; exit 1; }
command -v python3 >/dev/null || { echo "Python 3 is required" >&2; exit 1; }
command -v openssl >/dev/null || { echo "OpenSSL is required" >&2; exit 1; }

chmod 600 "$file"
file_size=$(wc -c < "$file")
(( file_size <= 5000000000 )) || { echo "S3 single-request upload limit is 5 GB" >&2; exit 1; }

# Validate the export independently before sending it to the immutable destination.
python3 - "$file" <<'PY'
import hashlib
import json
import sys
from datetime import UTC, datetime

path = sys.argv[1]
previous_hash = "0" * 64
record_count = 0
last_audit_id = 0
records_digest = hashlib.sha256()
header = None
checkpoint = None

with open(path, "rb") as stream:
    for raw_line in stream:
        if not raw_line.endswith(b"\n"):
            raise SystemExit("Invalid audit export: line is not newline-terminated")
        item = json.loads(raw_line)
        if header is None:
            header = item
            if header.get("type") != "header" or header.get("schema_version") != 1:
                raise SystemExit("Invalid audit export header")
            continue
        if item.get("type") == "checkpoint":
            if checkpoint is not None:
                raise SystemExit("Invalid audit export: duplicate checkpoint")
            checkpoint = item
            if stream.read(1):
                raise SystemExit("Invalid audit export: data follows checkpoint")
            break
        if item.get("type") != "record":
            raise SystemExit("Invalid audit export record type")

        audit_id = int(item["audit_id"])
        occurred_at = datetime.fromisoformat(item["occurred_at"])
        if occurred_at.tzinfo is None or occurred_at.utcoffset() is None:
            raise SystemExit("Invalid audit export timestamp")
        if item["previous_hash"] != previous_hash:
            raise SystemExit("Invalid audit export predecessor hash")

        canonical_record = {
            "version": "openshield.audit.v1",
            "audit_id": audit_id,
            "occurred_at": occurred_at.astimezone(UTC).isoformat(
                timespec="microseconds"
            ).replace("+00:00", "Z"),
            "actor_id": item["actor_id"],
            "action": item["action"],
            "target_id": item["target_id"],
            "details": item["details"],
            "previous_hash": previous_hash,
        }
        payload = json.dumps(
            canonical_record,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        calculated_hash = hashlib.sha256(payload).hexdigest()
        if item["record_hash"] != calculated_hash:
            raise SystemExit("Invalid audit export record hash")

        previous_hash = calculated_hash
        last_audit_id = audit_id
        record_count += 1
        records_digest.update(raw_line)

if header is None or checkpoint is None:
    raise SystemExit("Invalid audit export: complete checkpoint is missing")
if checkpoint.get("valid") is not True:
    raise SystemExit("Invalid audit export: checkpoint is not valid")
if checkpoint.get("records_checked") != record_count:
    raise SystemExit("Invalid audit export record count")
if checkpoint.get("last_audit_id") != last_audit_id:
    raise SystemExit("Invalid audit export last audit ID")
if checkpoint.get("head_hash") != previous_hash:
    raise SystemExit("Invalid audit export chain head")
if checkpoint.get("records_sha256") != records_digest.hexdigest():
    raise SystemExit("Invalid audit export record digest")

print(json.dumps({
    "records": record_count,
    "last_audit_id": last_audit_id,
    "head_hash": previous_hash,
    "records_sha256": records_digest.hexdigest(),
}, sort_keys=True))
PY

audit_metadata=$(python3 - "$file" <<'PY'
import json
import sys
with open(sys.argv[1], encoding="utf-8") as stream:
    header = json.loads(next(stream))
    checkpoint = None
    for line in stream:
        item = json.loads(line)
        if item.get("type") == "checkpoint":
            checkpoint = item
            break
if checkpoint is None:
    raise SystemExit("Missing audit checkpoint")
print(
    f"schema-version={header['schema_version']},"
    f"head-hash={checkpoint['head_hash']},"
    f"last-audit-id={checkpoint['last_audit_id']},"
    f"records={checkpoint['records_checked']}"
)
PY
)

caller_account=$(aws sts get-caller-identity --query Account --output text --region "$region" --no-cli-pager)
[[ "$caller_account" =~ ^[0-9]{12}$ ]] || { echo "Could not determine AWS caller account" >&2; exit 1; }
[[ "$caller_account" != "$expected_owner" ]] || {
  echo "WORM bucket must be owned by a separate AWS account from the uploader identity" >&2
  exit 1
}

lock_configuration=$(aws s3api get-object-lock-configuration \
  --bucket "$bucket" --expected-bucket-owner "$expected_owner" \
  --region "$region" --no-cli-pager)
lock_enabled=$(printf '%s' "$lock_configuration" | python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("ObjectLockConfiguration", {}).get("ObjectLockEnabled", ""))')
[[ "$lock_enabled" == "Enabled" ]] || {
  echo "Target bucket does not have S3 Object Lock enabled" >&2
  exit 1
}

versioning=$(aws s3api get-bucket-versioning \
  --bucket "$bucket" --expected-bucket-owner "$expected_owner" \
  --region "$region" --no-cli-pager --query Status --output text)
[[ "$versioning" == "Enabled" ]] || {
  echo "Target bucket versioning is not enabled" >&2
  exit 1
}

retain_until=$(python3 - "$retention_days" <<'PY'
from datetime import UTC, datetime, timedelta
import sys
print((datetime.now(UTC) + timedelta(days=int(sys.argv[1]))).replace(
    microsecond=0
).isoformat().replace("+00:00", "Z"))
PY
)
date_prefix=$(date -u +%Y/%m/%d)
unique_id=$(python3 -c 'import uuid; print(uuid.uuid4().hex)')
key="${prefix%/}/${date_prefix}/${unique_id}-audit.ndjson"
content_md5=$(openssl dgst -md5 -binary "$file" | base64 | tr -d '\n')
checksum_sha256=$(openssl dgst -sha256 -binary "$file" | base64 | tr -d '\n')

put_result=$(aws s3api put-object \
  --bucket "$bucket" --key "$key" --body "$file" \
  --expected-bucket-owner "$expected_owner" --region "$region" --no-cli-pager \
  --content-type application/x-ndjson --content-md5 "$content_md5" \
  --checksum-algorithm SHA256 --checksum-sha256 "$checksum_sha256" \
  --server-side-encryption AES256 \
  --object-lock-mode COMPLIANCE --object-lock-retain-until-date "$retain_until" \
  --metadata "$audit_metadata")

version_id=$(printf '%s' "$put_result" | python3 -c \
  'import json,sys; print(json.load(sys.stdin).get("VersionId") or "")')
[[ -n "$version_id" ]] || {
  echo "S3 upload returned no object version ID; inspect bucket before retrying" >&2
  exit 1
}

retention_result=$(aws s3api get-object-retention \
  --bucket "$bucket" --key "$key" --version-id "$version_id" \
  --expected-bucket-owner "$expected_owner" --region "$region" --no-cli-pager)
python3 - "$retention_result" "$retain_until" <<'PY'
import json
import sys
from datetime import datetime

result = json.loads(sys.argv[1])
retention = result.get("Retention", {})
if retention.get("Mode") != "COMPLIANCE":
    raise SystemExit("Uploaded object is not protected in COMPLIANCE mode")
actual = datetime.fromisoformat(retention["RetainUntilDate"].replace("Z", "+00:00"))
expected = datetime.fromisoformat(sys.argv[2].replace("Z", "+00:00"))
if actual < expected:
    raise SystemExit("Uploaded object retention is shorter than requested")
print(actual.isoformat().replace("+00:00", "Z"))
PY

echo "Audit anchor uploaded and retention verified:"
echo "s3://$bucket/$key"
echo "version_id=$version_id"
echo "retention_mode=COMPLIANCE"
echo "retain_until=$retain_until"
