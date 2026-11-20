# External audit anchoring with AWS S3 Object Lock

OpenShield can export the complete verified audit chain and publish it to an
S3 bucket in a separate AWS account with Object Lock **COMPLIANCE** retention.
This creates an external immutable checkpoint; it does not make the PostgreSQL
database itself immutable.

## Prerequisites

- AWS CLI v2 and Python 3 on the operator workstation.
- An S3 general-purpose bucket with Object Lock enabled and versioning enabled.
- The bucket belongs to an AWS account different from the AWS identity used to
  run the upload.
- The uploader identity can call STS GetCallerIdentity and has only the
  required cross-account S3 permissions: s3:GetBucketObjectLockConfiguration,
  s3:GetBucketVersioning, s3:PutObject and s3:GetObjectRetention.
- An approved retention period. The upload command requires it explicitly;
  COMPLIANCE retention cannot be shortened or bypassed before expiry.

The destination account should be controlled separately from the Node and
PostgreSQL administrators. Restrict bucket policy and access to the export
objects. Do not give the Node runtime the destination account's administrative
credentials.

## Export a verified snapshot

The export reads the audit rows and persisted chain head inside one PostgreSQL
REPEATABLE READ snapshot. It refuses to create a complete export unless every
row hash, predecessor hash and the persisted head match.

Run from the repository root while the database service is available:

~~~bash
mkdir -m 700 -p ./secure-audit-export

docker compose run --rm \
  -v "$PWD/secure-audit-export:/exports" \
  openshield-test \
  python scripts/ops/export_audit_anchor.py \
  --output "/exports/audit-$(date -u +%Y%m%dT%H%M%SZ).ndjson"
~~~

The file is created with mode 0600. It contains a header, one JSON record per
line, and a final checkpoint with the record count, final audit ID, chain head
and digest of the record lines. Treat the export as sensitive: audit details
may contain operational information. Keep the local directory private and
remove the export after its retention in S3 has been confirmed, unless a
separate encrypted archive is intentionally required.

The exporter does not write an audit event about its own export. Doing so would
change the chain immediately after the exported checkpoint and create a
self-referential workflow.

## Upload and verify COMPLIANCE retention

Use AWS credentials from the source/uploader account. The destination bucket
owner must be a different 12-digit account ID:

~~~bash
bash scripts/ops/upload_audit_anchor.sh \
  ./secure-audit-export/audit-YYYYMMDDTHHMMSSZ.ndjson \
  openshield-audit-archive \
  123456789012 \
  us-east-1 \
  365 \
  openshield/audit
~~~

Replace the example file, bucket, owner, region and retention with deployment
values. Retention days are mandatory; do not copy the illustrative 365-day
value without approval.

The uploader:
1. Recomputes the record hashes, predecessor chain and checkpoint digest from
   the export before contacting S3.
2. Confirms the active AWS caller account differs from the expected bucket
   owner.
3. Confirms Object Lock is enabled and bucket versioning is enabled.
4. Uploads a unique NDJSON object using COMPLIANCE mode, the requested retain
   until date, Content-MD5 and SHA-256 checksums, and server-side AES-256
   encryption.
5. Fetches the uploaded object's retention configuration and requires
   COMPLIANCE mode with a retain-until date at least as long as requested.

The command prints the S3 object key, version ID and verified retention date.
Store that result with the deployment's operational evidence. A failed
verification is not a successful anchor, even if an S3 object was created;
inspect the bucket before retrying.

S3 requires a Content-MD5 or SDK checksum when uploading with Object Lock
retention. The uploader supplies both MD5 and SHA-256 checksums. See the
[AWS S3 PutObject documentation](https://docs.aws.amazon.com/boto3/latest/reference/services/s3/client/put_object.html)
and [Object Lock retention documentation](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html).

## Recovery and limitations

- Download the exact object **version ID** recorded by the uploader, not merely
  the current key version.
- Validate the NDJSON checkpoint and all record hashes before using it as audit
  evidence. The uploader performs this validation before upload; an independent
  recovery verifier should repeat it after download.
- The anchor proves that this audit-chain prefix existed no later than the
  S3 object retention timestamp. It is not a trusted third-party timestamp or
  a digital signature over the identity of each actor.
- A later database rewrite can still alter the live database. Compare its
  verified chain head with the externally stored checkpoint to detect divergence.
- This workflow anchors the full current chain prefix on each run; it does not
  delete, truncate or archive database rows.
- No schedule is enabled by default. Run the export/upload as an explicitly
  monitored operational task and record failed runs.
- Audit retention, legal holds, deletion authority and chain continuation after
  archival remain undefined. Automatic deletion stays disabled.
