#!/usr/bin/env python3
"""
Sync honeypot files from Oracle VM volumes into Supabase.
Run alongside docker-compose on the VM (service: supabase-sync).
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", "/sessions"))
IOCS_DIR = Path(os.getenv("IOCS_DIR", "/iocs"))
LOGS_DIR = Path(os.getenv("LOGS_DIR", "/logs"))
PCAPS_DIR = Path(os.getenv("PCAPS_DIR", "/pcaps"))
SYNC_INTERVAL = int(os.getenv("SUPABASE_SYNC_INTERVAL", "15"))
STATE_FILE = Path(os.getenv("SYNC_STATE_FILE", "/tmp/honeypot_sync_state.json"))


def get_client():
    from supabase import create_client

    url = os.environ["SUPABASE_URL"]
    key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
    return create_client(url, key)


def load_state() -> dict:
    if STATE_FILE.exists():
        try:
            return json.loads(STATE_FILE.read_text())
        except Exception:
            pass
    return {"sessions": {}, "iocs": {}, "logs_offset": 0, "pcaps": {}}


def save_state(state: dict) -> None:
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))


def file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0


def sync_sessions(client, state: dict) -> int:
    count = 0
    if not SESSIONS_DIR.exists():
        return 0
    for path in SESSIONS_DIR.glob("*.json"):
        key = path.name
        mtime = file_mtime(path)
        if state["sessions"].get(key) == mtime:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            logger.warning("Skip session %s: %s", path, e)
            continue
        if not isinstance(data, dict):
            continue
        row = {
            "file_name": key,
            "client_ip": data.get("client_ip"),
            "protocol": data.get("protocol"),
            "service": data.get("service") or data.get("type"),
            "session_data": data,
            "location": data.get("location"),
            "attacks": data.get("attacks"),
            "attack_summary": data.get("attack_summary"),
            "updated_at": datetime.utcnow().isoformat(),
        }
        client.table("honeypot_sessions").upsert(row, on_conflict="file_name").execute()
        state["sessions"][key] = mtime
        count += 1
    return count


def sync_iocs(client, state: dict) -> int:
    count = 0
    if not IOCS_DIR.exists():
        return 0
    skip = {"blocked_ips.json", "watchlist.json"}
    for path in IOCS_DIR.glob("*.json"):
        if path.name in skip:
            continue
        key = path.name
        mtime = file_mtime(path)
        if state["iocs"].get(key) == mtime:
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            logger.warning("Skip IOC %s: %s", path, e)
            continue
        if isinstance(data, list):
            continue
        if not isinstance(data, dict):
            continue
        client.table("honeypot_iocs").upsert(
            {"file_name": key, "ioc_data": data},
            on_conflict="file_name",
        ).execute()
        state["iocs"][key] = mtime
        count += 1
    return count


def sync_logs(client, state: dict) -> int:
    count = 0
    log_file = LOGS_DIR / "aggregated.log"
    if not log_file.exists():
        return 0
    offset = state.get("logs_offset", 0)
    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            f.seek(offset)
            new_lines = f.readlines()
            state["logs_offset"] = f.tell()
    except Exception as e:
        logger.error("Log read failed: %s", e)
        return 0
    for line in new_lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            entry = {"message": line, "timestamp": datetime.utcnow().isoformat()}
        client.table("honeypot_logs").insert(
            {
                "source": entry.get("source", ""),
                "message": entry.get("message", line[:500]),
                "log_entry": entry,
            }
        ).execute()
        count += 1
    return count


def sync_pcaps(client, state: dict) -> int:
    count = 0
    if not PCAPS_DIR.exists():
        return 0
    for path in PCAPS_DIR.glob("*.pcap"):
        key = path.name
        mtime = file_mtime(path)
        if state["pcaps"].get(key) == mtime:
            continue
        try:
            size = path.stat().st_size
        except OSError:
            size = 0
        client.table("honeypot_pcaps").upsert(
            {
                "file_name": key,
                "file_path": str(path),
                "size_bytes": size,
                "captured_at": datetime.utcfromtimestamp(mtime).isoformat() + "Z",
            },
            on_conflict="file_name",
        ).execute()
        state["pcaps"][key] = mtime
        count += 1
    return count


def main():
    if not os.getenv("SUPABASE_URL") or not os.getenv("SUPABASE_SERVICE_ROLE_KEY"):
        logger.error("Set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY")
        raise SystemExit(1)
    client = get_client()
    logger.info("Supabase sync started (interval=%ss)", SYNC_INTERVAL)
    while True:
        state = load_state()
        try:
            s = sync_sessions(client, state)
            i = sync_iocs(client, state)
            l = sync_logs(client, state)
            p = sync_pcaps(client, state)
            save_state(state)
            if s or i or l or p:
                logger.info("Synced sessions=%s iocs=%s logs=%s pcaps=%s", s, i, l, p)
        except Exception as e:
            logger.exception("Sync cycle failed: %s", e)
        time.sleep(SYNC_INTERVAL)


if __name__ == "__main__":
    main()
