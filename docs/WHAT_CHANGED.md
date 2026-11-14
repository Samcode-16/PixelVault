# What v3 adds, and the complexity behind it

| Area | v2 (before) | v3 (now) | Concept learned |
|---|---|---|---|
| Image pipeline | Store the file as-is | Validate → read EXIF → rotate → make 480 px thumbnail → upload original **and** thumbnail | Image processing (Pillow), 2 S3 writes per upload |
| Database | 2 tables, created once | 5 tables, **versioned migrations** (`PRAGMA user_version`) with a file lock | Schema evolution without losing data |
| Timeline | Flat grid | Grouped by date taken (EXIF), fallback upload date | Metadata extraction, date grouping |
| Delete | Immediate | Soft delete → Trash → auto-purge after 30 days → permanent purge removes S3 objects | State machines, data lifecycle |
| Albums | none | Many-to-many (`album_images`) | Relational modelling |
| Sharing | Pre-signed URL (cannot be cancelled) | DB-backed token `/s/<token>`, expiry, views, **revoke**; server issues a 60-second S3 URL per click | Indirection gives control |
| Duplicates | none | SHA-256 content hash per user | Hashing / dedupe |
| Front-end | Server-rendered page + sorting | JSON API + single-page UI, hash routing, multi-select, undo toasts | REST API design, client state |
| Security checks | Row ownership | Ownership on every id (bulk), trash revokes links, 401 JSON for API, CSP-safe DOM building | Authorization at scale |
| Ops | none | `backfill` CLI, DB backup in `upgrade.sh`, WAL mode | Operational tooling |

# v4 - making the server replaceable and the delivery fast

| Area | v3 | v4 | Cloud concept |
|---|---|---|---|
| Metadata | SQLite file on the instance disk | **DynamoDB** single table, on-demand, point-in-time recovery | Stateless compute: lose the EC2 instance, lose nothing |
| Unique usernames | UNIQUE index | Conditional write on a `USERNAME#` item | Atomic checks without a SQL engine |
| Share-link cleanup | Rows stay forever | DynamoDB **TTL** deletes expired links | Managed data lifecycle |
| Image delivery | S3 pre-signed URLs | **CloudFront** signed URLs; bucket reachable only through an Origin Access Control | CDN caching, private origin |
| Signing key | n/a | RSA private key in **SSM Parameter Store** (SecureString), read via the IAM role | Secrets management |
| Cache headers | none | `max-age=1y, immutable` on objects; URLs stable for 15 min | Cache design |
| Old versions | Kept forever | **S3 lifecycle**: noncurrent versions expire after 30 days | Cost control |
| Resilience | n/a | CDN failure falls back to S3 URLs automatically | Graceful degradation |
