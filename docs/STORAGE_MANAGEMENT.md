# Storage Management

The dashboard now exposes a safe, allowlisted storage subsystem for `logs`,
`pcaps`, `sessions`, and `iocs`.

## API

- `GET /api/storage` returns disk and per-category file statistics.
- `POST /api/storage/preview` accepts `categories`, `older_than_days`, and
  `archive` and does not modify data.
- `POST /api/storage/cleanup` accepts the same payload and performs cleanup.
- `POST /api/cleanup` remains backward compatible with the existing
  `{ "mode": "partial" | "full" }` dashboard request.

Example:

```json
{
  "categories": ["logs", "pcaps"],
  "older_than_days": 7,
  "archive": true
}
```

Use `"all"` for `older_than_days` to select every eligible file. IOC user
settings (`blocked_ips.json` and `watchlist.json`) are always protected.

## Consistency and safety

Cleanup only traverses configured category roots and never follows symlinks.
Files are archived and verified first, then moved into per-operation quarantine.
Matching session and IOC rows are deleted from Supabase using snapshots. A
remote failure restores both the rows and the staged files before returning an
error.

Archives and the rotating cleanup audit log are stored in `ARCHIVE_DIR`.
Docker Compose mounts this at `./data/archive` by default.

## Retention entry points

Schedulers and cron wrappers can import:

```python
from storage_manager import cleanup_old_logs, cleanup_old_pcaps

cleanup_old_logs(7, initiated_by="cron")
cleanup_old_pcaps(7, initiated_by="cron", archive=True)
```

Equivalent helpers exist for sessions and IOCs.

## Deployment notes

1. Rebuild and restart the dashboard container so the archive mount and
   environment variables are applied.
2. Ensure the dashboard's Supabase service-role variables are configured when
   remote session/IOC deletion is required.
3. The archive directory must have enough free space for the selected data.
4. Existing dashboard cleanup behavior is unchanged: partial selects logs,
   sessions, and IOCs; full also selects PCAPs.
