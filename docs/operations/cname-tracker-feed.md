# CNAME tracker feed maintenance

The scheduled CNAME tracker workflow downloads the AdGuard original-trackers feed and opens a review PR. It does not update the production feed automatically.

## Download size limit

The updater streams both the GitHub commit response and the raw feed in chunks. The default maximum is **2 MiB per response**, with a hard configurable range of 1 KiB to 64 MiB.

Set `OPENSHIELD_CNAME_TRACKER_MAX_BYTES` in the workflow environment to raise the limit when the upstream feed legitimately grows. Keep the value only as large as required.

The updater rejects:
- a declared `Content-Length` larger than the configured limit;
- a streamed response that exceeds the limit;
- a body shorter than its declared `Content-Length`;
- invalid UTF-8, missing or invalid timezone-aware `TimeUpdated` metadata, fewer than 50 unique domains, or invalid domain entries.

Both feed and metadata output are prepared only after validation succeeds. The feed and metadata include the upstream commit and update timestamp; review the generated diff before merging the scheduled update.

## Local run

From the repository root:

```bash
OPENSHIELD_CNAME_TRACKER_MAX_BYTES=2097152 python scripts/update_cname_tracker_feed.py
```
