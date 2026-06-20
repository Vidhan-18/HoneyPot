#!/usr/bin/env python3
"""
Sync honeypot files from AWS EC2 volumes into Supabase.
Run alongside docker-compose on the VM (service: supabase-sync).
"""

import json
import logging
import os
import time
from datetime import datetime
from pathlib import Path
from supabase import create_client


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", "/sessions"))
IOCS_DIR = Path(os.getenv("IOCS_DIR", "/iocs"))
LOGS_DIR = Path(os.getenv("LOGS_DIR", "/logs"))
PCAPS_DIR = Path(os.getenv("PCAPS_DIR", "/pcaps"))
SYNC_INTERVAL = int(os.getenv("SUPABASE_SYNC_INTERVAL", "60"))
STATE_FILE = Path(os.getenv("SYNC_STATE_FILE", "/data/sync_state.json"))


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
    logger.info("Writing state file to %s", STATE_FILE)

    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(json.dumps(state))

    logger.info(
        "Saved state: sessions=%s iocs=%s",
        len(state.get("sessions", {})),
        len(state.get("iocs", {}))
    )


def file_mtime(path: Path) -> float:
    try:
        return path.stat().st_mtime
    except OSError:
        return 0







def sanitize_json(obj):
    if isinstance(obj, dict):
        return {k: sanitize_json(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [sanitize_json(v) for v in obj]
    elif isinstance(obj, str):
        return obj.replace("\x00", "")
    return obj





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
            data = sanitize_json(data)
        except Exception as e:
            logger.warning("Skip session %s: %s", path, e)
            continue
        if not isinstance(data, dict):
            continue

        try:
            location = get_ip_location(data.get("client_ip", ""))
        except Exception:
            location = None

        try:
            attacks = classify_attack(data)
            attack_summary = get_attack_summary(attacks)
        except Exception:
            attacks = []
            attack_summary = {
                "total": 0,
                "critical": 0,
                "high": 0,
                "medium": 0,
                "categories": []
            }


        row = {
            "file_name": key,
            "client_ip": data.get("client_ip"),
            "protocol": data.get("protocol"),
            "service": data.get("service") or data.get("type"),
            "session_data": data,
            "location": location,
            "attacks": attacks,
            "attack_summary": attack_summary,
            "updated_at": datetime.utcnow().isoformat(),
        }
        try:
            client.table("honeypot_sessions").upsert(row, on_conflict="file_name").execute()
        except Exception as e:
            logger.error("Failed uploading session %s: %s", key, e)
            continue
        state["sessions"][key] = mtime
        count += 1

        if count % 100 == 0:
            logger.info("Processed %s session files", count)
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
        logger.info("IOC FILE FOLUND: %s", key)
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

        logger.info("Uploading IOC %s", key)

        client.table("honeypot_iocs").upsert(
            {"file_name": key, "ioc_data": data},
            on_conflict="file_name",
        ).execute()
        logger.info("IOC UPLOADED: %s", key)
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
            logger.info("STARTING SESSION SYNC")
            s = sync_sessions(client, state)
            logger.info("SESSION SYNC DONE: %s", s)

            logger.info("STARTING IOC SYNC")
            i = sync_iocs(client, state)
            logger.info("IOC SYNC DONE: %s", i)

            logger.info("STARTING LOG SYNC")
            l = sync_logs(client, state)

            p = sync_pcaps(client, state)
            logger.info("STARTING PCAP SYNC")

            logger.info("ABOUT TO SAVE STATE")

            save_state(state)

            logger.info("STATE SAVED")

            if s or i or l or p:
                logger.info("Synced sessions=%s iocs=%s logs=%s pcaps=%s", s, i, l, p)
        except Exception as e:
            logger.exception("Sync cycle failed: %s", e)
        time.sleep(SYNC_INTERVAL)



if __name__ == "__main__":
    main()
