#!/usr/bin/env python3
"""HA Guardian - Brute-Force Protection for Home Assistant (Multi-Source)"""

import asyncio
import json
import logging
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Optional

import aiohttp as aiohttp_client
from aiohttp import web
import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OPTIONS_FILE = "/data/options.json"
STATE_FILE = "/data/guardian_state.json"
BANS_FILE = "/config/ip_bans.yaml"
SOURCES_FILE = "/data/guardian_sources.json"
LOG_FILE_DEFAULT = "/config/home-assistant.log"
SUPERVISOR_URL = "http://supervisor"
VERSION = "1.5.0"
PORT = 8099

# Directories to scan for log files
LOG_SCAN_DIRS = [
    "/config",
    "/config/logs",
    "/addon_configs",
    "/share",
    "/media",
]

# Skip these paths during discovery to avoid noise
LOG_SKIP_PATTERNS = [
    "*/node_modules/*",
    "*/.git/*",
    "*/cache/*",
    "*/tmp/*",
    "*/__pycache__/*",
    "*/venv/*",
    # /config/addons_config is a duplicate of /addon_configs — skip it
    "/config/addons_config/*",
    "/config/addons_config",
    "*/addons_config/*",
]

# Max depth for recursive scanning
MAX_SCAN_DEPTH = 4

# Only show log files modified within this many hours (0 = show all)
MAX_LOG_AGE_HOURS = 48

# Skip rotated log files (e.g. .log.1, .log.2, .log.gz)
ROTATED_LOG_RE = re.compile(r"\.log\.\d+$|\.log\.gz$|\.log\.bz2$|\.log\.xz$|\.log\.old$")

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("guardian")

# ---------------------------------------------------------------------------
# Detection patterns — each yields an IP via group(1) or group(2)
# ---------------------------------------------------------------------------
PATTERNS = {
    "ha_ban": re.compile(
        r"\[homeassistant\.components\.http\.ban\]"
        r".*?(?:from\s+\S+\s+\(([0-9a-fA-F:.]+)\)|from\s+([0-9a-fA-F:.]+))"
    ),
    "nginx_auth": re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r'.*"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s.*"\s+(?:401|403)\s'
    ),
    "generic_fail": re.compile(
        r"(?:authentication fail|login fail|invalid password|unauthorized|"
        r"access denied|bad password|failed login|invalid credential|"
        r"wrong password|login error|auth error|permission denied)"
        r".*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    "ssh_fail": re.compile(
        r"[Ff]ailed password for.*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
    "nextcloud": re.compile(
        r'"remoteAddr"\s*:\s*"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"'
        r'.*"message"\s*:\s*"(?:Login failed|Bruteforce)',
        re.IGNORECASE,
    ),
    "vaultwarden": re.compile(
        r"(?:Username or password is incorrect|Invalid admin password)"
        r".*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    "dovecot_postfix": re.compile(
        r"(?:auth failed|authentication failure|SASL .+ authentication failed)"
        r".*?(?:rip=|from=\[?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    # Laravel apps (2FAuth, Heimdall, etc.) — matches both failed and throttled
    # Format: [date] level.LEVEL: Message from IP
    "laravel_auth": re.compile(
        r"production\.(?:WARNING|NOTICE|ERROR|INFO)"
        r".*?(?:Failed login|failed to authenticate|login attempt|"
        r"Invalid (?:password|credentials|OTP)|throttle|too many (?:attempts|login)|"
        r"blocked|locked out|User authentication failed|"
        r"These credentials do not match)"
        r".*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    # Broader Laravel: any line with IP + auth failure keywords (reverse order)
    "laravel_ip_first": re.compile(
        r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r".*?(?:fail|invalid|wrong|denied|throttl|locked|block|credentials do not match)",
        re.IGNORECASE,
    ),
    # 2FAuth specific: "User login requested" is logged for EVERY attempt;
    # failed ones are followed by throttle/error. Catch the request line.
    # This is intentionally broad — matches all login requests to catch
    # failed ones. Combine with max_attempts threshold for auto-ban.
    "2fauth_login": re.compile(
        r"production\.(?:WARNING|NOTICE|ERROR)"
        r".*?(?:Failed|failed|Invalid|invalid|Throttle|throttle|"
        r"credentials do not match|Too many)"
        r".*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
}

URL_RE = re.compile(r"URL:\s*'([^']*)'")

# Keywords that suggest auth-related log lines (used for unmatched detection)
AUTH_KEYWORDS_RE = re.compile(
    r"(?:login|auth|password|credential|sign.?in|session|token|"
    r"401|403|forbidden|denied|locked|brute|attempt|fail|invalid|"
    r"wrong|bad.?pass|blocked|reject|unauth)",
    re.IGNORECASE,
)


def extract_ip(line: str):
    """Try all patterns and return (ip, pattern_name) or None."""
    for name, pat in PATTERNS.items():
        m = pat.search(line)
        if m:
            ip = m.group(1) or (m.group(2) if m.lastindex and m.lastindex >= 2 else None)
            if ip:
                try:
                    ip_address(ip)
                    return ip, name
                except ValueError:
                    pass
    return None


def _is_auth_related(line: str) -> bool:
    """Check if a line looks auth-related but didn't match any pattern."""
    return bool(AUTH_KEYWORDS_RE.search(line))


# ---------------------------------------------------------------------------
# Persistent State — survives addon restarts
# ---------------------------------------------------------------------------
class PersistentState:
    """
    Separate state file that persists whitelist, config overrides, and other
    runtime data across addon restarts. HA Supervisor overwrites options.json
    on each restart, so we store user-modified values here instead.
    """

    def __init__(self):
        self._path = STATE_FILE
        self._data: dict = {
            "whitelist": [],
            "trusted_domains": [],
            "config_overrides": {},
        }
        self._load()

    def _load(self):
        try:
            if Path(self._path).exists():
                with open(self._path) as f:
                    saved = json.load(f)
                self._data.update(saved)
                log.info("Loaded persistent state from %s", self._path)
        except Exception as e:
            log.warning("Could not load state: %s", e)

    def save(self):
        try:
            tmp = self._path + ".tmp"
            with open(tmp, "w") as f:
                json.dump(self._data, f, indent=2)
            os.replace(tmp, self._path)
        except Exception as e:
            log.error("Could not save state: %s", e)

    # -- Whitelist --
    @property
    def whitelist(self) -> list:
        return self._data.get("whitelist", [])

    @whitelist.setter
    def whitelist(self, value: list):
        self._data["whitelist"] = value
        self.save()

    # -- Trusted domains --
    @property
    def trusted_domains(self) -> list:
        return self._data.get("trusted_domains", [])

    @trusted_domains.setter
    def trusted_domains(self, value: list):
        self._data["trusted_domains"] = value
        self.save()

    # -- Config overrides --
    @property
    def config_overrides(self) -> dict:
        return self._data.get("config_overrides", {})

    def set_override(self, key: str, value):
        if "config_overrides" not in self._data:
            self._data["config_overrides"] = {}
        self._data["config_overrides"][key] = value
        self.save()


# ---------------------------------------------------------------------------
# Config — merges options.json defaults with persistent state overrides
# ---------------------------------------------------------------------------
class Config:
    def __init__(self, state: PersistentState):
        self._state = state
        self.max_attempts: int = 5
        self.window_minutes: int = 5
        self.ban_duration_minutes: int = 240
        self.alert_window_hours: int = 24
        self.log_file: str = LOG_FILE_DEFAULT
        self._load()

    def _load(self):
        # 1) Load defaults from Supervisor options
        try:
            with open(OPTIONS_FILE) as f:
                d = json.load(f)
            self.max_attempts = max(1, int(d.get("max_attempts", 5)))
            self.window_minutes = max(1, int(d.get("window_minutes", 5)))
            self.ban_duration_minutes = max(0, int(d.get("ban_duration_minutes", 240)))
            self.alert_window_hours = max(1, int(d.get("alert_window_hours", 24)))
            self.log_file = d.get("log_file", LOG_FILE_DEFAULT)

            # Seed state from options.json if state has empty whitelist
            # (first run after install)
            opts_wl = d.get("whitelist", [])
            opts_td = d.get("trusted_domains", [])
            if not self._state.whitelist and opts_wl:
                self._state.whitelist = opts_wl
            if not self._state.trusted_domains and opts_td:
                self._state.trusted_domains = opts_td
        except Exception as e:
            log.warning("Could not load options.json: %s — using defaults", e)

        # 2) Apply persistent overrides
        ov = self._state.config_overrides
        if "max_attempts" in ov:
            self.max_attempts = max(1, int(ov["max_attempts"]))
        if "window_minutes" in ov:
            self.window_minutes = max(1, int(ov["window_minutes"]))
        if "ban_duration_minutes" in ov:
            self.ban_duration_minutes = max(0, int(ov["ban_duration_minutes"]))
        if "alert_window_hours" in ov:
            self.alert_window_hours = max(1, int(ov["alert_window_hours"]))

    @property
    def whitelist(self) -> list:
        return self._state.whitelist

    @whitelist.setter
    def whitelist(self, value: list):
        self._state.whitelist = value

    @property
    def trusted_domains(self) -> list:
        return self._state.trusted_domains

    @trusted_domains.setter
    def trusted_domains(self, value: list):
        self._state.trusted_domains = value

    def save(self):
        """Persist config changes made via UI."""
        self._state.set_override("max_attempts", self.max_attempts)
        self._state.set_override("window_minutes", self.window_minutes)
        self._state.set_override("ban_duration_minutes", self.ban_duration_minutes)
        self._state.set_override("alert_window_hours", self.alert_window_hours)
        # Whitelist and trusted_domains are auto-saved via property setters

    def to_dict(self) -> dict:
        return {
            "max_attempts": self.max_attempts,
            "window_minutes": self.window_minutes,
            "ban_duration_minutes": self.ban_duration_minutes,
            "alert_window_hours": self.alert_window_hours,
            "log_file": self.log_file,
            "whitelist": self.whitelist,
            "trusted_domains": self.trusted_domains,
        }

    def is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        for entry in self.whitelist:
            try:
                if "/" in entry:
                    if addr in ip_network(entry, strict=False):
                        return True
                elif addr == ip_address(entry):
                    return True
            except ValueError:
                pass
        return False


# ---------------------------------------------------------------------------
# Source Manager — discovers and manages log sources
# ---------------------------------------------------------------------------
def _should_skip(path: str) -> bool:
    for pat in LOG_SKIP_PATTERNS:
        if fnmatch(path, pat):
            return True
    return False


def _scan_directory_for_logs(base_dir: str, max_depth: int = MAX_SCAN_DEPTH) -> list:
    """Recursively scan a directory for recent, non-rotated log files.

    Returns list of dicts: {"path": str, "mtime": float, "size": int}
    """
    found = []
    base = Path(base_dir)
    if not base.is_dir():
        return found

    now = datetime.now().timestamp()
    age_cutoff = now - (MAX_LOG_AGE_HOURS * 3600) if MAX_LOG_AGE_HOURS > 0 else 0

    try:
        for item in base.iterdir():
            path_str = str(item)
            if _should_skip(path_str):
                continue
            if item.is_file():
                name_lower = item.name.lower()
                # Only .log files (not rotated ones like .log.1, .log.gz)
                if not name_lower.endswith(".log"):
                    # Also allow .log.txt or files with "log" in .txt name
                    if not (name_lower.endswith(".log.txt")
                            or (name_lower.endswith(".txt") and "log" in name_lower)):
                        continue
                # Skip rotated logs
                if ROTATED_LOG_RE.search(item.name):
                    continue
                try:
                    st = item.stat()
                    # Skip empty files
                    if st.st_size == 0:
                        continue
                    # Skip files older than cutoff
                    if age_cutoff > 0 and st.st_mtime < age_cutoff:
                        continue
                    found.append({
                        "path": path_str,
                        "mtime": st.st_mtime,
                        "size": st.st_size,
                    })
                except OSError:
                    pass
            elif item.is_dir() and max_depth > 0:
                found.extend(_scan_directory_for_logs(path_str, max_depth - 1))
    except PermissionError:
        pass
    except Exception as e:
        log.debug("Error scanning %s: %s", base_dir, e)
    return found


def _extract_addon_slug_from_path(path: str) -> Optional[str]:
    """Extract the addon slug from an addon_configs path."""
    p = Path(path)
    parts = p.parts
    if "addon_configs" in parts:
        idx = parts.index("addon_configs")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    return None


def _friendly_name(path: str, addon_names: dict = None) -> str:
    """Generate a human-readable name from a log file path.

    addon_names: mapping of addon dir slug -> display name from Supervisor API
    """
    p = Path(path)
    addon_names = addon_names or {}

    # For addon_configs, use the real addon name if available
    slug = _extract_addon_slug_from_path(path)
    if slug:
        if slug in addon_names:
            return f"{addon_names[slug]}: {p.name}"
        # Fallback: clean up slug
        name = slug.split("_", 1)[-1] if "_" in slug else slug
        name = name.replace("-", " ").replace("_", " ").title()
        return f"{name}: {p.name}"

    # For share/media, include parent dir
    stem = p.stem.replace("-", " ").replace("_", " ").title()
    parent = p.parent.name
    if parent and parent not in ("config", "logs", "log"):
        parent_clean = parent.split("_", 1)[-1] if "_" in parent else parent
        parent_clean = parent_clean.replace("-", " ").replace("_", " ").title()
        return f"{parent_clean}: {stem}"
    return stem


def _format_mtime(mtime: float) -> str:
    return datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat()


class SourceManager:
    def __init__(self, config: Config):
        self.config = config
        self._sources: dict = {}  # id -> source dict
        self._supervisor_token = os.environ.get("SUPERVISOR_TOKEN", "")
        self._load()

    def _default_sources(self) -> list:
        return [
            {
                "id": "file:" + self.config.log_file,
                "name": "Home Assistant Core",
                "type": "file",
                "path": self.config.log_file,
                "enabled": True,
            }
        ]

    def _load(self):
        try:
            if Path(SOURCES_FILE).exists():
                with open(SOURCES_FILE) as f:
                    data = json.load(f)
                for s in data.get("sources", []):
                    self._sources[s["id"]] = s
                log.info("Loaded %d log source(s) from disk", len(self._sources))
        except Exception as e:
            log.warning("Could not load sources: %s", e)

        if not self._sources:
            for s in self._default_sources():
                self._sources[s["id"]] = s
            self._save()

    def _save(self):
        try:
            tmp = SOURCES_FILE + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"sources": list(self._sources.values())}, f, indent=2)
            os.replace(tmp, SOURCES_FILE)
        except Exception as e:
            log.error("Could not save sources: %s", e)

    async def _fetch_addon_map(self) -> dict:
        """Fetch addon slug -> display name mapping from Supervisor API.
        Returns {slug: name} for all installed addons.
        """
        addon_map = {}  # slug -> name
        addon_states = {}  # slug -> state
        if not self._supervisor_token:
            return addon_map
        try:
            async with aiohttp_client.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {self._supervisor_token}",
                    "Content-Type": "application/json",
                }
                async with session.get(
                    f"{SUPERVISOR_URL}/addons",
                    headers=headers,
                    timeout=aiohttp_client.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        for addon in data.get("data", {}).get("addons", []):
                            slug = addon.get("slug", "")
                            addon_map[slug] = addon.get("name", slug)
                            addon_states[slug] = addon.get("state", "")
        except Exception as e:
            log.warning("Could not fetch addon list: %s", e)
        self._addon_states = addon_states
        return addon_map

    async def discover(self):
        """Discover log files in all mapped directories + addon docker logs."""
        discovered = 0

        # Fetch addon name mapping first (used for both file naming and docker logs)
        addon_map = await self._fetch_addon_map()

        # Remove stale file sources: doesn't exist, too old, or duplicate path
        now_ts = datetime.now().timestamp()
        age_cutoff = now_ts - (MAX_LOG_AGE_HOURS * 3600) if MAX_LOG_AGE_HOURS > 0 else 0
        stale = []
        for sid, s in self._sources.items():
            if s["type"] != "file":
                continue
            path = s.get("path", "")
            p = Path(path)
            # Remove if file doesn't exist
            if not p.exists():
                stale.append(sid)
                continue
            # Remove if in a duplicate mount path (addons_config inside /config)
            if _should_skip(path):
                stale.append(sid)
                continue
            # Remove if file is too old
            try:
                mtime = p.stat().st_mtime
                if age_cutoff > 0 and mtime < age_cutoff:
                    stale.append(sid)
                    continue
            except OSError:
                stale.append(sid)
        for sid in stale:
            name = self._sources[sid].get("name", sid)
            del self._sources[sid]
            log.info("Removed stale/duplicate source: %s", name)

        # 1) Scan all mapped directories for recent log files (recursive)
        for base_dir in LOG_SCAN_DIRS:
            for entry in _scan_directory_for_logs(base_dir):
                path = entry["path"]
                sid = "file:" + path
                mtime_iso = _format_mtime(entry["mtime"])
                size = entry["size"]

                if sid in self._sources:
                    # Update mtime and size for existing sources
                    self._sources[sid]["last_modified"] = mtime_iso
                    self._sources[sid]["size"] = size
                    # Update name if addon_map has better info
                    slug = _extract_addon_slug_from_path(path)
                    if slug and slug in addon_map:
                        self._sources[sid]["name"] = f"{addon_map[slug]}: {Path(path).name}"
                        self._sources[sid]["addon_slug"] = slug
                    continue

                name = _friendly_name(path, addon_map)
                enabled = (path == self.config.log_file)

                source_entry = {
                    "id": sid,
                    "name": name,
                    "type": "file",
                    "path": path,
                    "enabled": enabled,
                    "last_modified": mtime_iso,
                    "size": size,
                }
                # Link to addon if in addon_configs
                slug = _extract_addon_slug_from_path(path)
                if slug:
                    source_entry["addon_slug"] = slug

                self._sources[sid] = source_entry
                discovered += 1
                log.info("Discovered log: %s (%s, modified %s)", name, path, mtime_iso)

        # 2) Discover HA addon docker logs via Supervisor API
        for slug, display_name in addon_map.items():
            if "ha_guardian" in slug:
                continue
            sid = "addon:" + slug
            state = getattr(self, "_addon_states", {}).get(slug, "")
            if sid not in self._sources:
                self._sources[sid] = {
                    "id": sid,
                    "name": f"Docker: {display_name}",
                    "type": "addon",
                    "slug": slug,
                    "state": state,
                    "enabled": False,
                }
                discovered += 1
                log.info("Discovered addon docker log: %s (%s)", display_name, slug)
            else:
                self._sources[sid]["state"] = state
                self._sources[sid]["name"] = f"Docker: {display_name}"

        if discovered:
            log.info("Discovered %d new source(s) — total: %d", discovered, len(self._sources))
        self._save()

    def get_all(self) -> list:
        # Sort: enabled first, then by last_modified (most recent first), then by name
        return sorted(
            self._sources.values(),
            key=lambda s: (
                not s.get("enabled"),
                -(datetime.fromisoformat(s["last_modified"]).timestamp()
                  if s.get("last_modified") else 0),
                s.get("name", ""),
            ),
        )

    def get_enabled(self, source_type: Optional[str] = None) -> list:
        return [
            s for s in self._sources.values()
            if s.get("enabled") and (source_type is None or s["type"] == source_type)
        ]

    def toggle(self, source_id: str, enabled: bool) -> bool:
        if source_id in self._sources:
            self._sources[source_id]["enabled"] = enabled
            self._save()
            return True
        return False

    def get_supervisor_token(self) -> str:
        return self._supervisor_token

    def get_source(self, source_id: str) -> Optional[dict]:
        return self._sources.get(source_id)

    async def preview_source(self, source_id: str, lines: int = 50) -> list:
        """Return the last N lines of a log source (for debugging)."""
        src = self._sources.get(source_id)
        if not src:
            return []

        if src["type"] == "file":
            path = src.get("path", "")
            if not path or not Path(path).exists():
                return []
            try:
                with open(path, errors="replace") as f:
                    all_lines = f.readlines()
                return [l.rstrip() for l in all_lines[-lines:]]
            except Exception as e:
                return [f"Error reading file: {e}"]

        elif src["type"] == "addon":
            slug = src.get("slug", "")
            token = self._supervisor_token
            if not slug or not token:
                return ["No Supervisor token available"]
            try:
                async with aiohttp_client.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {token}"}
                    url = f"{SUPERVISOR_URL}/addons/{slug}/logs"
                    async with session.get(
                        url, headers=headers,
                        timeout=aiohttp_client.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status != 200:
                            return [f"Supervisor API returned {resp.status}"]
                        text = await resp.text()
                return text.splitlines()[-lines:]
            except Exception as e:
                return [f"Error fetching addon logs: {e}"]

        return []


# ---------------------------------------------------------------------------
# Ban Manager
# ---------------------------------------------------------------------------
class BanManager:
    def __init__(self, config: Config):
        self.config = config
        self._bans: dict = {}
        self._lock = asyncio.Lock()
        self._load()

    def _load(self):
        try:
            path = Path(BANS_FILE)
            if not path.exists():
                return
            with open(path) as f:
                data = yaml.safe_load(f) or {}
            now = datetime.now(timezone.utc)
            for ip_key, info in data.items():
                ip = str(ip_key)
                if not isinstance(info, dict):
                    continue
                banned_at_str = info.get("banned_at", now.isoformat())
                try:
                    banned_at = datetime.fromisoformat(str(banned_at_str))
                    if banned_at.tzinfo is None:
                        banned_at = banned_at.replace(tzinfo=timezone.utc)
                except (ValueError, TypeError):
                    banned_at = now
                dur = self.config.ban_duration_minutes
                expires_at = (banned_at + timedelta(minutes=dur)).isoformat() if dur > 0 else None
                self._bans[ip] = {
                    "ip": ip,
                    "banned_at": banned_at.isoformat(),
                    "expires_at": expires_at,
                    "reason": "restored",
                    "manual": False,
                    "attempt_count": 0,
                    "source": "",
                }
            log.info("Loaded %d existing ban(s)", len(self._bans))
        except Exception as e:
            log.error("Error loading ip_bans.yaml: %s", e)

    async def _flush(self):
        tmp = BANS_FILE + ".tmp"
        try:
            data = {}
            for ip, b in self._bans.items():
                data[ip] = {"banned_at": b["banned_at"]}
            with open(tmp, "w") as f:
                yaml.dump(data, f, default_flow_style=False)
            os.replace(tmp, BANS_FILE)
        except Exception as e:
            log.error("Error writing ip_bans.yaml: %s", e)

    async def ban(self, ip, reason="auto", manual=False, attempts=0,
                  duration_minutes=None, source="") -> bool:
        if self.config.is_whitelisted(ip):
            log.info("IP %s is whitelisted — skipping ban", ip)
            return False
        dur = duration_minutes if duration_minutes is not None else self.config.ban_duration_minutes
        now = datetime.now(timezone.utc)
        expires = (now + timedelta(minutes=dur)).isoformat() if dur > 0 else None
        async with self._lock:
            self._bans[ip] = {
                "ip": ip,
                "banned_at": now.isoformat(),
                "expires_at": expires,
                "reason": reason,
                "manual": manual,
                "attempt_count": attempts,
                "source": source,
            }
            await self._flush()
        log.info("Banned %s for %d min — %s", ip, dur, reason)
        return True

    async def unban(self, ip: str) -> bool:
        async with self._lock:
            if ip not in self._bans:
                return False
            del self._bans[ip]
            await self._flush()
        log.info("Unbanned %s", ip)
        return True

    def is_banned(self, ip: str) -> bool:
        return ip in self._bans

    def list_bans(self) -> list:
        now = datetime.now(timezone.utc)
        result = []
        for b in self._bans.values():
            entry = dict(b)
            if b.get("expires_at"):
                try:
                    exp = datetime.fromisoformat(b["expires_at"])
                    if exp.tzinfo is None:
                        exp = exp.replace(tzinfo=timezone.utc)
                    entry["expires_in_seconds"] = max(0, int((exp - now).total_seconds()))
                except ValueError:
                    entry["expires_in_seconds"] = None
            else:
                entry["expires_in_seconds"] = None
            result.append(entry)
        result.sort(key=lambda x: x["banned_at"], reverse=True)
        return result

    async def expire_loop(self):
        while True:
            await asyncio.sleep(60)
            now = datetime.now(timezone.utc)
            expired = []
            for ip, b in list(self._bans.items()):
                if b.get("expires_at"):
                    try:
                        exp = datetime.fromisoformat(b["expires_at"])
                        if exp.tzinfo is None:
                            exp = exp.replace(tzinfo=timezone.utc)
                        if now >= exp:
                            expired.append(ip)
                    except ValueError:
                        pass
            if expired:
                async with self._lock:
                    for ip in expired:
                        if ip in self._bans:
                            del self._bans[ip]
                            log.info("Ban expired for %s", ip)
                    await self._flush()


# ---------------------------------------------------------------------------
# Alert Tracker — per-source statistics
# ---------------------------------------------------------------------------
class AlertTracker:
    def __init__(self, config: Config):
        self.config = config
        self._records: dict = defaultdict(lambda: deque(maxlen=5000))

    def record(self, source_id: str, source_name: str, ip: str):
        self._records[source_id].append({
            "time": datetime.now(timezone.utc),
            "ip": ip,
            "source_name": source_name,
        })

    def get_alerts(self) -> list:
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(hours=self.config.alert_window_hours)
        alerts = []
        for source_id, records in self._records.items():
            recent = [r for r in records if r["time"] >= cutoff]
            if not recent:
                continue
            unique_ips = set(r["ip"] for r in recent)
            source_name = recent[-1].get("source_name", source_id)
            last_attempt = max(r["time"] for r in recent)
            alerts.append({
                "source_id": source_id,
                "source_name": source_name,
                "attempts": len(recent),
                "unique_ips": len(unique_ips),
                "top_ips": self._top_ips(recent, 5),
                "last_attempt": last_attempt.isoformat(),
                "window_hours": self.config.alert_window_hours,
            })
        alerts.sort(key=lambda a: a["attempts"], reverse=True)
        return alerts

    def _top_ips(self, records, limit):
        counts = defaultdict(int)
        for r in records:
            counts[r["ip"]] += 1
        return sorted(
            [{"ip": ip, "count": c} for ip, c in counts.items()],
            key=lambda x: x["count"], reverse=True,
        )[:limit]


# ---------------------------------------------------------------------------
# Detector
# ---------------------------------------------------------------------------
class Detector:
    def __init__(self, config: Config, bans: BanManager, alerts: AlertTracker):
        self.config = config
        self.bans = bans
        self.alerts = alerts
        self._windows: dict = defaultdict(deque)
        self._events: deque = deque(maxlen=500)
        self._total_attempts = 0
        self._total_bans = 0
        self._started = datetime.now(timezone.utc)

    async def record(self, ip, source_id, source_name, url="", pattern=""):
        if self.config.is_whitelisted(ip):
            return
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=self.config.window_minutes)
        dq = self._windows[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        self._total_attempts += 1
        self.alerts.record(source_id, source_name, ip)
        banned_now = False

        if len(dq) >= self.config.max_attempts and not self.bans.is_banned(ip):
            ok = await self.bans.ban(ip, reason="auto", attempts=len(dq), source=source_id)
            if ok:
                self._total_bans += 1
                banned_now = True
                dq.clear()

        self._events.appendleft({
            "time": now.isoformat(), "ip": ip,
            "source_id": source_id, "source_name": source_name,
            "url": url, "pattern": pattern,
            "count": len(dq) if not banned_now else self.config.max_attempts,
            "banned": banned_now,
        })
        log.warning(
            "Failed login from %s via %s (%d/%d)%s",
            ip, source_name,
            len(dq) if not banned_now else self.config.max_attempts,
            self.config.max_attempts,
            " — BANNED" if banned_now else "",
        )

    def stats(self) -> dict:
        uptime = int((datetime.now(timezone.utc) - self._started).total_seconds())
        return {
            "active_bans": len(self.bans._bans),
            "total_attempts": self._total_attempts,
            "total_bans": self._total_bans,
            "tracked_ips": len(self._windows),
            "uptime_seconds": uptime,
            "version": VERSION,
        }

    def events(self) -> list:
        return list(self._events)


# ---------------------------------------------------------------------------
# Log Scanner — tails files + polls addon docker logs
# ---------------------------------------------------------------------------
class LogScanner:
    def __init__(self, source_mgr: SourceManager, detector: Detector):
        self.source_mgr = source_mgr
        self.detector = detector
        self._file_state: dict = {}   # path -> {"inode": int, "pos": int}
        self._addon_state: dict = {}  # slug -> last_length
        # Buffer of recent unmatched auth-related lines (for debugging)
        self.unmatched_lines: deque = deque(maxlen=200)

    async def run(self):
        await self.source_mgr.discover()
        enabled = self.source_mgr.get_enabled()
        log.info("Log scanner started — %d source(s) enabled out of %d total",
                 len(enabled), len(self.source_mgr.get_all()))
        for s in enabled:
            log.info("  Active: %s (%s)", s.get("name"), s.get("path", s.get("slug", "")))

        while True:
            for src in self.source_mgr.get_enabled("file"):
                await self._scan_file(src)
            for src in self.source_mgr.get_enabled("addon"):
                await self._poll_addon(src)
            await asyncio.sleep(1)

    async def _scan_file(self, src: dict):
        path = src["path"]
        try:
            if not Path(path).exists():
                return
            stat = os.stat(path)
            inode, size = stat.st_ino, stat.st_size
            state = self._file_state.get(path)

            if state is None:
                self._file_state[path] = {"inode": inode, "pos": size}
                return

            if inode != state["inode"] or size < state["pos"]:
                state["inode"] = inode
                state["pos"] = 0
                log.info("Log rotated: %s", path)

            if state["pos"] >= size:
                return

            with open(path, errors="replace") as f:
                f.seek(state["pos"])
                for line in f:
                    await self._process_line(line, src)
                state["pos"] = f.tell()
        except Exception as e:
            log.error("Error scanning %s: %s", path, e)

    async def _poll_addon(self, src: dict):
        slug = src.get("slug", "")
        token = self.source_mgr.get_supervisor_token()
        if not token or not slug:
            return
        try:
            async with aiohttp_client.ClientSession() as session:
                headers = {"Authorization": f"Bearer {token}"}
                url = f"{SUPERVISOR_URL}/addons/{slug}/logs"
                async with session.get(
                    url, headers=headers, timeout=aiohttp_client.ClientTimeout(total=10)
                ) as resp:
                    if resp.status != 200:
                        return
                    text = await resp.text()

            last_len = self._addon_state.get(slug)
            if last_len is None:
                self._addon_state[slug] = len(text)
                return
            if len(text) < last_len:
                last_len = 0
            if len(text) > last_len:
                new_content = text[last_len:]
                for line in new_content.splitlines():
                    await self._process_line(line, src)
            self._addon_state[slug] = len(text)
        except Exception as e:
            log.debug("Error polling addon %s: %s", slug, e)

    async def _process_line(self, line: str, src: dict):
        line = line.strip()
        if not line:
            return
        result = extract_ip(line)
        if result:
            ip, pattern_name = result
            url = ""
            um = URL_RE.search(line)
            if um:
                url = um.group(1)
            await self.detector.record(
                ip=ip, source_id=src["id"],
                source_name=src.get("name", src["id"]),
                url=url, pattern=pattern_name,
            )
        elif _is_auth_related(line):
            # Line looks auth-related but no pattern matched — log for debugging
            self.unmatched_lines.appendleft({
                "time": datetime.now(timezone.utc).isoformat(),
                "source_id": src["id"],
                "source_name": src.get("name", src["id"]),
                "line": line[:500],  # truncate very long lines
            })
            log.debug("UNMATCHED auth line [%s]: %s", src.get("name", "?"), line[:200])

    async def rediscover_loop(self):
        while True:
            await asyncio.sleep(300)
            await self.source_mgr.discover()


# ---------------------------------------------------------------------------
# Web Server
# ---------------------------------------------------------------------------
_INDEX_HTML: Optional[str] = None


def _index_html() -> str:
    global _INDEX_HTML
    if _INDEX_HTML is None:
        _INDEX_HTML = (Path(__file__).parent / "www" / "index.html").read_text()
    return _INDEX_HTML


def build_app(config, bans, detector, source_mgr, alerts, scanner=None) -> web.Application:
    app = web.Application()

    async def handle_index(req):
        base = req.headers.get("X-Ingress-Path", "").rstrip("/") + "/"
        html = _index_html().replace("__BASE_HREF__", base)
        return web.Response(text=html, content_type="text/html")

    async def handle_stats(req):
        return web.json_response(detector.stats())

    async def handle_events(req):
        return web.json_response(detector.events())

    async def handle_get_bans(req):
        return web.json_response(bans.list_bans())

    async def handle_post_ban(req):
        try:
            d = await req.json()
            ip = d.get("ip", "").strip()
            ip_address(ip)
            dur = int(d.get("duration_minutes", config.ban_duration_minutes))
            reason = d.get("reason", "manual") or "manual"
            ok = await bans.ban(ip, reason=reason, manual=True, duration_minutes=dur)
            if ok:
                return web.json_response({"ok": True})
            return web.json_response({"ok": False, "error": "IP is whitelisted"}, status=400)
        except (ValueError, TypeError) as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def handle_delete_ban(req):
        ip = req.match_info["ip"]
        ok = await bans.unban(ip)
        if ok:
            return web.json_response({"ok": True})
        return web.json_response({"ok": False, "error": "not found"}, status=404)

    async def handle_get_whitelist(req):
        return web.json_response(config.whitelist)

    async def handle_post_whitelist(req):
        d = await req.json()
        entry = d.get("entry", "").strip()
        if not entry:
            return web.json_response({"ok": False, "error": "empty entry"}, status=400)
        wl = list(config.whitelist)
        if entry not in wl:
            wl.append(entry)
            config.whitelist = wl
        return web.json_response({"ok": True})

    async def handle_delete_whitelist(req):
        entry = req.match_info["entry"]
        wl = list(config.whitelist)
        if entry in wl:
            wl.remove(entry)
            config.whitelist = wl
        return web.json_response({"ok": True})

    async def handle_get_sources(req):
        return web.json_response(source_mgr.get_all())

    async def handle_toggle_source(req):
        d = await req.json()
        sid = d.get("id", "")
        enabled = bool(d.get("enabled", False))
        ok = source_mgr.toggle(sid, enabled)
        if ok:
            return web.json_response({"ok": True})
        return web.json_response({"ok": False, "error": "source not found"}, status=404)

    async def handle_discover_sources(req):
        await source_mgr.discover()
        return web.json_response({"ok": True, "sources": source_mgr.get_all()})

    async def handle_get_alerts(req):
        return web.json_response(alerts.get_alerts())

    async def handle_get_config(req):
        return web.json_response(config.to_dict())

    async def handle_post_config(req):
        d = await req.json()
        if "max_attempts" in d:
            config.max_attempts = max(1, int(d["max_attempts"]))
        if "window_minutes" in d:
            config.window_minutes = max(1, int(d["window_minutes"]))
        if "ban_duration_minutes" in d:
            config.ban_duration_minutes = max(0, int(d["ban_duration_minutes"]))
        if "alert_window_hours" in d:
            config.alert_window_hours = max(1, int(d["alert_window_hours"]))
        if "trusted_domains" in d:
            config.trusted_domains = [s.strip() for s in d["trusted_domains"] if s.strip()]
        config.save()
        return web.json_response({"ok": True})

    async def handle_health(req):
        return web.json_response({"status": "ok", "version": VERSION})

    # --- Source Preview (last N lines of a log) ---
    async def handle_preview_source(req):
        d = await req.json()
        sid = d.get("id", "")
        n = min(int(d.get("lines", 50)), 200)
        lines = await source_mgr.preview_source(sid, n)
        return web.json_response({"lines": lines})

    # --- Unmatched auth lines (for debugging patterns) ---
    async def handle_unmatched(req):
        if scanner:
            return web.json_response(list(scanner.unmatched_lines))
        return web.json_response([])

    app.router.add_get("/", handle_index)
    app.router.add_get("/api/stats", handle_stats)
    app.router.add_get("/api/events", handle_events)
    app.router.add_get("/api/bans", handle_get_bans)
    app.router.add_post("/api/bans", handle_post_ban)
    app.router.add_delete("/api/bans/{ip}", handle_delete_ban)
    app.router.add_get("/api/whitelist", handle_get_whitelist)
    app.router.add_post("/api/whitelist", handle_post_whitelist)
    app.router.add_delete("/api/whitelist/{entry}", handle_delete_whitelist)
    app.router.add_get("/api/sources", handle_get_sources)
    app.router.add_post("/api/sources/toggle", handle_toggle_source)
    app.router.add_post("/api/sources/discover", handle_discover_sources)
    app.router.add_post("/api/sources/preview", handle_preview_source)
    app.router.add_get("/api/unmatched", handle_unmatched)
    app.router.add_get("/api/alerts", handle_get_alerts)
    app.router.add_get("/api/config", handle_get_config)
    app.router.add_post("/api/config", handle_post_config)
    app.router.add_get("/api/health", handle_health)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main():
    state = PersistentState()
    config = Config(state)
    bans = BanManager(config)
    alert_tracker = AlertTracker(config)
    detector = Detector(config, bans, alert_tracker)
    source_mgr = SourceManager(config)
    scanner = LogScanner(source_mgr, detector)

    log.info("HA Guardian %s starting on port %d", VERSION, PORT)

    app = build_app(config, bans, detector, source_mgr, alert_tracker, scanner)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info("Web server ready")

    await asyncio.gather(
        scanner.run(),
        scanner.rediscover_loop(),
        bans.expire_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())
