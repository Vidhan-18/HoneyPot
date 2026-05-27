"""
Data access layer: Supabase (production/Vercel) or local filesystem (Docker dev).
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

LOGS_DIR = Path(os.getenv("LOGS_DIR", "/logs"))
SESSIONS_DIR = Path(os.getenv("SESSIONS_DIR", "/sessions"))
IOCS_DIR = Path(os.getenv("IOCS_DIR", "/iocs"))
PCAPS_DIR = Path(os.getenv("PCAPS_DIR", "/pcaps"))


def use_supabase() -> bool:
    return bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"))


def _read_json_file(file_path: Path) -> Optional[dict]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            return json.load(f)
    except Exception as e:
        logger.error("Error reading %s: %s", file_path, e)
        return None


class DataStore(ABC):
    @abstractmethod
    def list_sessions(self, limit: int = 50) -> List[dict]:
        pass

    @abstractmethod
    def get_session(self, identifier: str) -> Optional[dict]:
        pass

    @abstractmethod
    def list_iocs(self, limit: int = 50) -> List[dict]:
        pass

    @abstractmethod
    def get_ioc(self, identifier: str) -> Optional[dict]:
        pass

    @abstractmethod
    def list_logs(self, limit: int = 100, service: str = "") -> List[dict]:
        pass

    @abstractmethod
    def list_pcaps(self, limit: int = 20) -> List[dict]:
        pass

    @abstractmethod
    def get_statistics(self) -> dict:
        pass

    @abstractmethod
    def list_blocked_ips(self) -> List[dict]:
        pass

    @abstractmethod
    def add_blocked_ip(self, ip: str, reason: str = "manual_block") -> List[dict]:
        pass

    @abstractmethod
    def list_watchlist(self) -> List[dict]:
        pass

    @abstractmethod
    def add_watchlist_ip(
        self, ip: str, reason: str = "manual_watchlist", notes: str = ""
    ) -> List[dict]:
        pass

    @abstractmethod
    def iter_sessions_for_map(self, limit: int = 500) -> List[dict]:
        """Sessions with file/id for threat map."""
        pass


class FilesystemStore(DataStore):
    def list_sessions(self, limit: int = 50) -> List[dict]:
        sessions = []
        if not SESSIONS_DIR.exists():
            return sessions

        def safe_mtime(x):
            try:
                return x.stat().st_mtime
            except OSError:
                return 0

        for session_file in sorted(
            SESSIONS_DIR.glob("*.json"), key=safe_mtime, reverse=True
        )[:limit]:
            session = _read_json_file(session_file)
            if session:
                session["file"] = session_file.name
                sessions.append(session)
        return sessions

    def get_session(self, identifier: str) -> Optional[dict]:
        session_file = SESSIONS_DIR / identifier
        if not session_file.exists():
            return None
        session = _read_json_file(session_file)
        if session:
            session["file"] = session_file.name
        return session

    def list_iocs(self, limit: int = 50) -> List[dict]:
        iocs = []
        if not IOCS_DIR.exists():
            return iocs

        def safe_mtime(x):
            try:
                return x.stat().st_mtime
            except OSError:
                return 0

        for ioc_file in sorted(IOCS_DIR.glob("*.json"), key=safe_mtime, reverse=True)[
            :limit
        ]:
            try:
                ioc = json.loads(ioc_file.read_text())
                if isinstance(ioc, list):
                    continue
                if isinstance(ioc, dict):
                    ioc["file"] = ioc_file.name
                    iocs.append(ioc)
            except Exception as e:
                logger.warning("Error reading IOC %s: %s", ioc_file, e)
        return iocs

    def get_ioc(self, identifier: str) -> Optional[dict]:
        ioc_file = IOCS_DIR / identifier
        if not ioc_file.exists():
            return None
        ioc = _read_json_file(ioc_file)
        if ioc and isinstance(ioc, dict):
            ioc["file"] = ioc_file.name
        return ioc if isinstance(ioc, dict) else None

    def list_logs(self, limit: int = 100, service: str = "") -> List[dict]:
        logs = []
        log_file = LOGS_DIR / "aggregated.log"
        if not log_file.exists():
            return logs
        try:
            with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
                for line in f.readlines()[-limit:]:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        log_entry = json.loads(line)
                        if service and service.lower() not in log_entry.get(
                            "source", ""
                        ).lower():
                            continue
                        logs.append(log_entry)
                    except json.JSONDecodeError:
                        logs.append(
                            {"message": line, "timestamp": datetime.now().isoformat()}
                        )
        except Exception as e:
            logger.error("Error reading logs: %s", e)
        return logs[-limit:]

    def list_pcaps(self, limit: int = 20) -> List[dict]:
        if not PCAPS_DIR.exists():
            return []
        files = []
        for file_path in PCAPS_DIR.glob("*.pcap"):
            try:
                stat = file_path.stat()
                files.append(
                    {
                        "name": file_path.name,
                        "path": str(file_path),
                        "size": stat.st_size,
                        "modified": datetime.fromtimestamp(stat.st_mtime).isoformat(),
                    }
                )
            except Exception as e:
                logger.error("Error reading pcap %s: %s", file_path, e)
        files.sort(key=lambda x: x["modified"], reverse=True)
        return files[:limit]

    def get_statistics(self) -> dict:
        stats = {
            "total_sessions": 0,
            "total_iocs": 0,
            "total_pcaps": 0,
            "recent_activity": 0,
            "services": {"ssh": 0, "http": 0, "db": 0, "smb_ftp": 0},
        }
        one_hour_ago = datetime.now() - timedelta(hours=1)

        if SESSIONS_DIR.exists():
            for session_file in SESSIONS_DIR.glob("*.json"):
                stats["total_sessions"] += 1
                name = session_file.name.lower()
                if "ssh" in name:
                    stats["services"]["ssh"] += 1
                elif "http" in name:
                    stats["services"]["http"] += 1
                elif "postgres" in name or "mysql" in name:
                    stats["services"]["db"] += 1
                elif "smb" in name or "ftp" in name:
                    stats["services"]["smb_ftp"] += 1
                try:
                    if datetime.fromtimestamp(session_file.stat().st_mtime) > one_hour_ago:
                        stats["recent_activity"] += 1
                except OSError:
                    pass

        if IOCS_DIR.exists():
            stats["total_iocs"] = len(list(IOCS_DIR.glob("*.json")))
        if PCAPS_DIR.exists():
            stats["total_pcaps"] = len(list(PCAPS_DIR.glob("*.pcap")))
        return stats

    def list_blocked_ips(self) -> List[dict]:
        blocked_file = IOCS_DIR / "blocked_ips.json"
        if blocked_file.exists():
            try:
                data = json.loads(blocked_file.read_text())
                return data if isinstance(data, list) else []
            except Exception:
                pass
        return []

    def add_blocked_ip(self, ip: str, reason: str = "manual_block") -> List[dict]:
        blocked = self.list_blocked_ips()
        if not any(b.get("ip") == ip for b in blocked):
            blocked.append(
                {"ip": ip, "blocked_at": datetime.utcnow().isoformat(), "reason": reason}
            )
            blocked_file = IOCS_DIR / "blocked_ips.json"
            blocked_file.parent.mkdir(parents=True, exist_ok=True)
            blocked_file.write_text(json.dumps(blocked, indent=2))
        return blocked

    def list_watchlist(self) -> List[dict]:
        watchlist_file = IOCS_DIR / "watchlist.json"
        if watchlist_file.exists():
            try:
                data = json.loads(watchlist_file.read_text())
                return data if isinstance(data, list) else []
            except Exception:
                pass
        return []

    def add_watchlist_ip(
        self, ip: str, reason: str = "manual_watchlist", notes: str = ""
    ) -> List[dict]:
        watchlist = self.list_watchlist()
        if not any(w.get("ip") == ip for w in watchlist):
            watchlist.append(
                {
                    "ip": ip,
                    "added_at": datetime.utcnow().isoformat(),
                    "reason": reason,
                    "notes": notes,
                }
            )
            watchlist_file = IOCS_DIR / "watchlist.json"
            watchlist_file.parent.mkdir(parents=True, exist_ok=True)
            watchlist_file.write_text(json.dumps(watchlist, indent=2))
        return watchlist

    def iter_sessions_for_map(self, limit: int = 500) -> List[dict]:
        result = []
        if not SESSIONS_DIR.exists():
            return result

        def safe_mtime(x):
            try:
                return x.stat().st_mtime
            except OSError:
                return 0

        for session_file in sorted(
            SESSIONS_DIR.glob("*.json"), key=safe_mtime, reverse=True
        )[:limit]:
            session = _read_json_file(session_file)
            if session:
                session["_file"] = session_file.name
                session["_id"] = session_file.stem
                result.append(session)
        return result


class SupabaseStore(DataStore):
    def __init__(self):
        from supabase import create_client

        url = os.environ["SUPABASE_URL"]
        key = os.environ["SUPABASE_SERVICE_ROLE_KEY"]
        self.client = create_client(url, key)

    def _row_to_session(self, row: dict) -> dict:
        session = dict(row.get("session_data") or {})
        session["file"] = row.get("file_name")
        session["id"] = str(row.get("id", ""))
        if row.get("location"):
            session["location"] = row["location"]
        if row.get("attacks"):
            session["attacks"] = row["attacks"]
        if row.get("attack_summary"):
            session["attack_summary"] = row["attack_summary"]
        return session

    def list_sessions(self, limit: int = 50) -> List[dict]:
        res = (
            self.client.table("honeypot_sessions")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        return [self._row_to_session(r) for r in (res.data or [])]

    def get_session(self, identifier: str) -> Optional[dict]:
        by_file = (
            self.client.table("honeypot_sessions")
            .select("*")
            .eq("file_name", identifier)
            .limit(1)
            .execute()
        )
        rows = by_file.data or []
        if not rows:
            by_id = (
                self.client.table("honeypot_sessions")
                .select("*")
                .eq("id", identifier)
                .limit(1)
                .execute()
            )
            rows = by_id.data or []
        if not rows:
            return None
        return self._row_to_session(rows[0])

    def list_iocs(self, limit: int = 50) -> List[dict]:
        res = (
            self.client.table("honeypot_iocs")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        iocs = []
        for row in res.data or []:
            ioc = dict(row.get("ioc_data") or {})
            ioc["file"] = row.get("file_name")
            iocs.append(ioc)
        return iocs

    def get_ioc(self, identifier: str) -> Optional[dict]:
        res = (
            self.client.table("honeypot_iocs")
            .select("*")
            .eq("file_name", identifier)
            .limit(1)
            .execute()
        )
        if not res.data:
            return None
        row = res.data[0]
        ioc = dict(row.get("ioc_data") or {})
        ioc["file"] = row.get("file_name")
        return ioc

    def list_logs(self, limit: int = 100, service: str = "") -> List[dict]:
        query = (
            self.client.table("honeypot_logs")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
        )
        res = query.execute()
        logs = []
        for row in res.data or []:
            entry = row.get("log_entry") or {}
            if not entry:
                entry = {"message": row.get("message"), "source": row.get("source")}
            if service and service.lower() not in str(entry.get("source", "")).lower():
                continue
            logs.append(entry)
        return list(reversed(logs))[-limit:]

    def list_pcaps(self, limit: int = 20) -> List[dict]:
        res = (
            self.client.table("honeypot_pcaps")
            .select("*")
            .order("captured_at", desc=True)
            .limit(limit)
            .execute()
        )
        return [
            {
                "name": r.get("file_name"),
                "path": r.get("file_path"),
                "size": r.get("size_bytes", 0),
                "modified": r.get("captured_at"),
            }
            for r in (res.data or [])
        ]

    def get_statistics(self) -> dict:
        stats = {
            "total_sessions": 0,
            "total_iocs": 0,
            "total_pcaps": 0,
            "recent_activity": 0,
            "services": {"ssh": 0, "http": 0, "db": 0, "smb_ftp": 0},
        }
        sessions = (
            self.client.table("honeypot_sessions").select("file_name, created_at").execute()
        )
        one_hour_ago = datetime.utcnow() - timedelta(hours=1)
        for row in sessions.data or []:
            stats["total_sessions"] += 1
            name = (row.get("file_name") or "").lower()
            if "ssh" in name:
                stats["services"]["ssh"] += 1
            elif "http" in name:
                stats["services"]["http"] += 1
            elif "postgres" in name or "mysql" in name:
                stats["services"]["db"] += 1
            elif "smb" in name or "ftp" in name:
                stats["services"]["smb_ftp"] += 1
            created = row.get("created_at")
            if created:
                try:
                    ts = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    if ts.replace(tzinfo=None) > one_hour_ago:
                        stats["recent_activity"] += 1
                except ValueError:
                    pass

        iocs = self.client.table("honeypot_iocs").select("id").execute()
        stats["total_iocs"] = len(iocs.data or [])

        pcaps = self.client.table("honeypot_pcaps").select("id").execute()
        stats["total_pcaps"] = len(pcaps.data or [])

        return stats

    def list_blocked_ips(self) -> List[dict]:
        res = self.client.table("blocked_ips").select("*").execute()
        return res.data or []

    def add_blocked_ip(self, ip: str, reason: str = "manual_block") -> List[dict]:
        self.client.table("blocked_ips").upsert(
            {"ip": ip, "blocked_at": datetime.utcnow().isoformat(), "reason": reason}
        ).execute()
        return self.list_blocked_ips()

    def list_watchlist(self) -> List[dict]:
        res = self.client.table("watchlist").select("*").execute()
        return res.data or []

    def add_watchlist_ip(
        self, ip: str, reason: str = "manual_watchlist", notes: str = ""
    ) -> List[dict]:
        self.client.table("watchlist").upsert(
            {
                "ip": ip,
                "added_at": datetime.utcnow().isoformat(),
                "reason": reason,
                "notes": notes,
            }
        ).execute()
        return self.list_watchlist()

    def iter_sessions_for_map(self, limit: int = 500) -> List[dict]:
        res = (
            self.client.table("honeypot_sessions")
            .select("*")
            .order("created_at", desc=True)
            .limit(limit)
            .execute()
        )
        out = []
        for row in res.data or []:
            session = self._row_to_session(row)
            session["_file"] = row.get("file_name")
            session["_id"] = str(row.get("id", ""))
            out.append(session)
        return out


_store: Optional[DataStore] = None


def get_store() -> DataStore:
    global _store
    if _store is None:
        if use_supabase():
            logger.info("Using Supabase data store")
            _store = SupabaseStore()
        else:
            logger.info("Using filesystem data store")
            _store = FilesystemStore()
    return _store
