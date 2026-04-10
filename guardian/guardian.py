#!/usr/bin/env python3
"""HA Guardian - Brute-Force Protection for Home Assistant (Multi-Source)"""

import asyncio
import json
import logging
import os
import re
import subprocess
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatch, translate as fnmatch_translate
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
VERSION = "1.26.0"
RULES_FILE = "/data/guardian_rules.json"
PORT = int(os.environ.get("GUARDIAN_PORT", 8098))

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

# Max file size for initial scan (bytes). Files larger than this are still tailed
# for new lines, but the initial catch-up read is capped at this size from the end.
MAX_INITIAL_READ_BYTES = 5 * 1024 * 1024  # 5 MB

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("guardian")

# ---------------------------------------------------------------------------
# Detection patterns — each yields an IP via group(1) or group(2)
# ---------------------------------------------------------------------------
# Detection patterns — populated at runtime by RulesManager
# ---------------------------------------------------------------------------
PATTERNS: dict = {}  # mutable; rebuilt by RulesManager._apply()

DEFAULT_RULE_DEFS = [
    {
        "id": "ha_ban",
        "description": "Home Assistant HTTP ban component log messages",
        "pattern": r"\[homeassistant\.components\.http\.ban\].*?(?:from\s+\S+\s+\(([0-9a-fA-F:.]+)\)|from\s+([0-9a-fA-F:.]+))",
        "flags": "",
        "enabled": True,
    },
    {
        "id": "nginx_auth",
        "description": "Nginx HTTP 401/403 authentication failures",
        "pattern": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s.*\"\s+(?:401|403)\s",
        "flags": "",
        "enabled": True,
    },
    {
        "id": "generic_fail",
        "description": "Generic authentication failure keywords (keyword before IP)",
        "pattern": r"(?:authentication fail|login fail|invalid password|unauthorized|access denied|bad password|failed login|invalid credential|wrong password|login error|auth error|permission denied).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "ssh_fail",
        "description": "SSH failed password log entries",
        "pattern": r"[Ff]ailed password for.*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "flags": "",
        "enabled": True,
    },
    {
        "id": "nextcloud",
        "description": "Nextcloud JSON log: Login failed or Bruteforce with remoteAddr",
        "pattern": r"\"remoteAddr\"\s*:\s*\"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\".*\"message\"\s*:\s*\"(?:Login failed|Bruteforce)",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "vaultwarden",
        "description": "Vaultwarden: Username or password is incorrect / Invalid admin password",
        "pattern": r"(?:Username or password is incorrect|Invalid admin password).*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "dovecot_postfix",
        "description": "Dovecot/Postfix SASL authentication failures",
        "pattern": r"(?:auth failed|authentication failure|SASL .+ authentication failed).*?(?:rip=|from=\[?)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "laravel_auth",
        "description": "Laravel apps (2FAuth, Heimdall…): failed login / throttle messages",
        "pattern": r"production\.(?:WARNING|NOTICE|ERROR|INFO).*?(?:Failed login|failed to authenticate|login attempt|Invalid (?:password|credentials|OTP)|throttle|too many (?:attempts|login)|blocked|locked out|User authentication failed|These credentials do not match).*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "laravel_ip_first",
        "description": "Laravel: IP first, then auth failure keyword",
        "pattern": r"from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*?(?:fail|invalid|wrong|denied|throttl|locked|block|credentials do not match)",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "webtrees_fail",
        "description": "Webtrees: failed login POST redirect (HTTP 302)",
        "pattern": r"(\d{1,3}(?:\.\d{1,3}){3}).*\"POST\s+/login[^\"]*\s+HTTP/\S+\"\s+302\s",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "dokuwiki_auth",
        "description": "DokuWiki auth.log: LOGIN FAILURE or auth_failure",
        "pattern": r"(?:LOGIN FAILURE|auth.?fail|authentication fail).*?(?:\[|from\s+)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "2fauth_login",
        "description": "2FAuth NPM proxy: 500 on POST /user/login with [Client IP]",
        "pattern": r"\[.*\] - 500 500 - POST https 2fa\.biker633\.ddnss\.de \"/user/login\" \[Client (\d{1,3}(?:\.\d{1,3}){3})\]",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "ha_core_invalid_auth",
        "description": "HA Core: Login attempt or invalid authentication from IP",
        "pattern": r"(?:Login attempt|invalid authentication).*?\((\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "http_login_fail",
        "description": "HTTP access log: POST to login URL with 4xx/5xx status",
        "pattern": r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\"POST\s+\S*(?:/login|/signin|/sign_in|/auth|/user/login|/api/v\d+/auth)\s+HTTP/\S+\"\s+(?:4[0-9]{2}|5[0-9]{2})\s",
        "flags": "IGNORECASE",
        "enabled": True,
    },
    {
        "id": "npm_proxy",
        "description": "Nginx Proxy Manager: custom log with [Client IP] and 4xx/5xx on login path",
        "pattern": r"(?:4[0-9]{2}|5[0-9]{2}).*?\"(?:[^\"]*(?:/login|/signin|/sign_in|/auth|/user/login|/admin|/identity/connect/token|/api/v\d+/auth)[^\"]*)\"\s+\[Client\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]",
        "flags": "IGNORECASE",
        "enabled": True,
    },
]


class RulesManager:
    """Manages detection rules: load/save from JSON, CRUD, factory reset."""

    def __init__(self):
        self._rules: list = self._load()
        self._apply()

    def _load(self) -> list:
        if Path(RULES_FILE).exists():
            try:
                with open(RULES_FILE) as f:
                    data = json.load(f)
                if isinstance(data, list) and data:
                    return data
            except Exception as e:
                log.error("Error loading rules file: %s — using defaults", e)
        return [r.copy() for r in DEFAULT_RULE_DEFS]

    def _apply(self):
        """Recompile all enabled rules into the global PATTERNS dict."""
        new_patterns: dict = {}
        for rule in self._rules:
            if not rule.get("enabled", True):
                continue
            try:
                flags = 0
                for f in rule.get("flags", "").split("|"):
                    f = f.strip().upper()
                    if f == "IGNORECASE":
                        flags |= re.IGNORECASE
                    elif f == "MULTILINE":
                        flags |= re.MULTILINE
                new_patterns[rule["id"]] = re.compile(rule["pattern"], flags)
            except re.error as e:
                log.warning("Rule '%s' has invalid regex — skipped: %s", rule["id"], e)
        PATTERNS.clear()
        PATTERNS.update(new_patterns)
        log.info("Detection rules loaded: %d active", len(PATTERNS))

    def save(self):
        try:
            with open(RULES_FILE, "w") as f:
                json.dump(self._rules, f, indent=2)
        except Exception as e:
            log.error("Error saving rules: %s", e)

    def get_all(self) -> list:
        return [dict(r) for r in self._rules]

    def get(self, rule_id: str) -> Optional[dict]:
        return next((r for r in self._rules if r["id"] == rule_id), None)

    def upsert(self, data: dict) -> tuple:
        """Create or update a rule. Returns (ok, error_string)."""
        rule_id = str(data.get("id", "")).strip()
        if not rule_id:
            return False, "id required"
        pattern_str = str(data.get("pattern", "")).strip()
        if not pattern_str:
            return False, "pattern required"
        flags_str = str(data.get("flags", "")).strip()
        try:
            flags = 0
            for f in flags_str.split("|"):
                f = f.strip().upper()
                if f == "IGNORECASE":
                    flags |= re.IGNORECASE
                elif f == "MULTILINE":
                    flags |= re.MULTILINE
            re.compile(pattern_str, flags)
        except re.error as e:
            return False, f"invalid regex: {e}"
        existing = self.get(rule_id)
        if existing:
            existing["description"] = data.get("description", existing.get("description", ""))
            existing["pattern"] = pattern_str
            existing["flags"] = flags_str
            existing["enabled"] = bool(data.get("enabled", existing.get("enabled", True)))
        else:
            self._rules.append({
                "id": rule_id,
                "description": data.get("description", ""),
                "pattern": pattern_str,
                "flags": flags_str,
                "enabled": bool(data.get("enabled", True)),
            })
        self.save()
        self._apply()
        return True, None

    def delete(self, rule_id: str) -> bool:
        before = len(self._rules)
        self._rules = [r for r in self._rules if r["id"] != rule_id]
        if len(self._rules) < before:
            self.save()
            self._apply()
            return True
        return False

    def reset(self):
        """Restore factory defaults and delete the saved rules file."""
        self._rules = [r.copy() for r in DEFAULT_RULE_DEFS]
        try:
            Path(RULES_FILE).unlink(missing_ok=True)
        except Exception:
            pass
        self._apply()
        log.info("Rules reset to factory defaults")

URL_RE = re.compile(r"URL:\s*'([^']*)'")

# Keywords that suggest auth-related log lines (used for unmatched detection)
AUTH_KEYWORDS_RE = re.compile(
    r"(?:login|auth|password|credential|sign.?in|session|token|"
    r"401|403|forbidden|denied|locked|brute|attempt|fail|invalid|"
    r"wrong|bad.?pass|blocked|reject|unauth)",
    re.IGNORECASE,
)


# ---------------------------------------------------------------------------
# Timestamp parsing — used to skip log lines outside the monitoring window
# ---------------------------------------------------------------------------
_TS_PATTERNS = [
    # ISO / Docker: 2026-03-29T10:00:00 or 2026-03-29 10:00:00
    re.compile(r'(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})'),
    # CLF Apache/Nginx: 29/Mar/2026:10:00:00
    re.compile(r'(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})'),
    # Vaultwarden: [2026-03-29][10:00:00]
    re.compile(r'\[(\d{4}-\d{2}-\d{2})\]\[(\d{2}:\d{2}:\d{2})\]'),
    # Syslog: Mar 29 10:00:00
    re.compile(r'(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'),
]

_TS_FORMATS = [
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S",
    "%d/%b/%Y:%H:%M:%S",
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",  # syslog single-digit day with extra space
]


_TZ_OFFSET_RE = re.compile(r'([+-])(\d{2}):?(\d{2})(?:\s|]|$)')


def _parse_line_timestamp(line: str) -> Optional[datetime]:
    """Extract the timestamp from a log line, corrected to UTC. Returns None if not recognisable."""
    # Try to extract a UTC offset from the line (+0200, -05:00, etc.)
    tz: timezone = timezone.utc
    tz_m = _TZ_OFFSET_RE.search(line)
    if tz_m:
        sign = 1 if tz_m.group(1) == '+' else -1
        tz = timezone(timedelta(hours=sign * int(tz_m.group(2)),
                                minutes=sign * int(tz_m.group(3))))

    for pat in _TS_PATTERNS:
        m = pat.search(line)
        if not m:
            continue
        s = " ".join(g for g in m.groups() if g)
        for fmt in _TS_FORMATS:
            try:
                dt = datetime.strptime(s.strip(), fmt)
                if dt.year == 1900:  # syslog has no year
                    dt = dt.replace(year=datetime.now().year)
                # Tag with the detected timezone (or UTC if none found),
                # then normalise to UTC for comparison.
                return dt.replace(tzinfo=tz).astimezone(timezone.utc)
            except ValueError:
                continue
    return None


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

    # -- My IP (dynamic, auto-updated, separate from whitelist) --
    @property
    def my_ip(self) -> Optional[str]:
        return self._data.get("my_ip")

    @my_ip.setter
    def my_ip(self, value: Optional[str]):
        self._data["my_ip"] = value
        self.save()

    # -- CrowdSec Integration --
    @property
    def crowdsec_enabled(self) -> bool:
        return self._data.get("crowdsec_enabled", False)

    @crowdsec_enabled.setter
    def crowdsec_enabled(self, value: bool):
        self._data["crowdsec_enabled"] = bool(value)
        self.save()

    @property
    def crowdsec_lapi_url(self) -> str:
        return self._data.get("crowdsec_lapi_url", "")

    @crowdsec_lapi_url.setter
    def crowdsec_lapi_url(self, value: str):
        self._data["crowdsec_lapi_url"] = value
        self.save()

    @property
    def crowdsec_machine_id(self) -> str:
        return self._data.get("crowdsec_machine_id", "")

    @crowdsec_machine_id.setter
    def crowdsec_machine_id(self, value: str):
        self._data["crowdsec_machine_id"] = value
        self.save()

    @property
    def crowdsec_machine_password(self) -> str:
        pw = self._data.get("crowdsec_machine_password", "")
        # Safety: v1.23.2 accidentally stored SHA256 hash instead of plaintext.
        # Detect and clear it — 64 hex chars is almost certainly a hash, not a real password.
        if pw and len(pw) == 64 and all(c in "0123456789abcdef" for c in pw):
            log.warning("CrowdSec: stored password looks like a SHA256 hash — clearing it. "
                        "Please re-enter your password in Settings.")
            self._data["crowdsec_machine_password"] = ""
            self.save()
            return ""
        return pw

    @crowdsec_machine_password.setter
    def crowdsec_machine_password(self, value: str):
        self._data["crowdsec_machine_password"] = value
        self.save()

    # -- Ban targets (where to write bans) --
    @property
    def ban_to_ipbans(self) -> bool:
        """Write bans to ip_bans.yaml (HA application-level blocking). Default True."""
        return self._data.get("ban_to_ipbans", True)

    @ban_to_ipbans.setter
    def ban_to_ipbans(self, value: bool):
        self._data["ban_to_ipbans"] = bool(value)
        self.save()

    @property
    def ban_to_crowdsec(self) -> bool:
        """Send bans to CrowdSec LAPI. Default True (if CrowdSec is configured)."""
        return self._data.get("ban_to_crowdsec", True)

    @ban_to_crowdsec.setter
    def ban_to_crowdsec(self, value: bool):
        self._data["ban_to_crowdsec"] = bool(value)
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
        self.scan_interval_seconds: int = 1
        self.addon_poll_interval: int = 15
        self.log_interval_minutes: int = 5
        self.discover_interval_minutes: int = 15
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
            self.scan_interval_seconds = max(1, int(d.get("scan_interval_seconds", 1)))
            self.addon_poll_interval = max(5, int(d.get("addon_poll_interval", 15)))
            self.log_interval_minutes = max(1, int(d.get("log_interval_minutes", 5)))
            self.discover_interval_minutes = max(1, int(d.get("discover_interval_minutes", 15)))
            self.log_file = d.get("log_file", LOG_FILE_DEFAULT)

            # Seed state from options.json if state has empty whitelist
            # (first run after install)
            opts_wl = d.get("whitelist", [])
            opts_td = d.get("trusted_domains", [])
            if not self._state.whitelist and opts_wl:
                self._state.whitelist = opts_wl
            if not self._state.trusted_domains and opts_td:
                self._state.trusted_domains = opts_td

            # Ensure HA internal networks are always whitelisted
            self._ensure_default_whitelist()
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
        if "scan_interval_seconds" in ov:
            self.scan_interval_seconds = max(1, int(ov["scan_interval_seconds"]))
        if "addon_poll_interval" in ov:
            self.addon_poll_interval = max(5, int(ov["addon_poll_interval"]))
        if "log_interval_minutes" in ov:
            self.log_interval_minutes = max(1, int(ov["log_interval_minutes"]))
        if "discover_interval_minutes" in ov:
            self.discover_interval_minutes = max(1, int(ov["discover_interval_minutes"]))

    # HA internal networks that should never be banned
    HA_DEFAULT_WHITELIST = [
        "172.30.32.0/23",   # HA Supervisor internal network
        "127.0.0.1",        # localhost
    ]

    def _ensure_default_whitelist(self):
        """Ensure HA internal IPs are always in the whitelist."""
        wl = list(self._state.whitelist)
        changed = False
        for entry in self.HA_DEFAULT_WHITELIST:
            if entry not in wl:
                wl.append(entry)
                changed = True
                log.info("Auto-added %s to whitelist (HA internal)", entry)
        if changed:
            self._state.whitelist = wl

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
        self._state.set_override("scan_interval_seconds", self.scan_interval_seconds)
        self._state.set_override("addon_poll_interval", self.addon_poll_interval)
        self._state.set_override("log_interval_minutes", self.log_interval_minutes)
        self._state.set_override("discover_interval_minutes", self.discover_interval_minutes)
        # Whitelist and trusted_domains are auto-saved via property setters

    def to_dict(self) -> dict:
        return {
            "max_attempts": self.max_attempts,
            "window_minutes": self.window_minutes,
            "ban_duration_minutes": self.ban_duration_minutes,
            "alert_window_hours": self.alert_window_hours,
            "scan_interval_seconds": self.scan_interval_seconds,
            "addon_poll_interval": self.addon_poll_interval,
            "log_interval_minutes": self.log_interval_minutes,
            "discover_interval_minutes": self.discover_interval_minutes,
            "log_file": self.log_file,
            "whitelist": self.whitelist,
            "trusted_domains": self.trusted_domains,
            # CrowdSec — password intentionally omitted from API response
            "crowdsec_enabled": self._state.crowdsec_enabled,
            "crowdsec_lapi_url": self._state.crowdsec_lapi_url,
            "crowdsec_machine_id": self._state.crowdsec_machine_id,
            "crowdsec_configured": bool(
                self._state.crowdsec_lapi_url
                and self._state.crowdsec_machine_id
                and self._state.crowdsec_machine_password
            ),
            # Ban targets
            "ban_to_ipbans": self._state.ban_to_ipbans,
            "ban_to_crowdsec": self._state.ban_to_crowdsec,
        }

    def is_whitelisted(self, ip: str) -> bool:
        try:
            addr = ip_address(ip)
        except ValueError:
            return False
        # Check "my ip" (dynamic, auto-updated)
        my = self._state.my_ip
        if my:
            try:
                if addr == ip_address(my):
                    return True
            except ValueError:
                pass
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
# CrowdSec Manager — submits ban decisions to CrowdSec LAPI
# ---------------------------------------------------------------------------
class CrowdSecManager:
    """Logs in to the CrowdSec Local API as a watcher machine and submits
    ban decisions for each IP that Guardian bans.

    Setup (one-time, in the CrowdSec addon terminal):
        cscli machines add ha-guardian --password <your_password>
    Then configure LAPI URL, machine_id and password in Guardian Settings.
    """

    def __init__(self, state: PersistentState):
        self._state = state
        self._jwt: Optional[str] = None
        self._jwt_expires: Optional[datetime] = None
        self._lock = asyncio.Lock()

    @property
    def enabled(self) -> bool:
        return (
            self._state.ban_to_crowdsec
            and bool(self._state.crowdsec_lapi_url)
            and bool(self._state.crowdsec_machine_id)
            and bool(self._state.crowdsec_machine_password)
        )

    def _build_alert_payload(self, ip: str, duration_minutes: int, reason: str) -> list:
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        # CrowdSec uses decision.duration for ban expiry (until = created_at + duration).
        # stop_at is just alert metadata — set to same as start_at.
        if duration_minutes > 0:
            h, m = divmod(duration_minutes, 60)
            duration_str = f"{h}h{m}m0s"  # Go canonical: "1h0m0s", "4h0m0s"
        else:
            # 0 = permanent in Guardian → 10 years in CrowdSec
            duration_str = "87600h0m0s"
        log.info("CrowdSec: building alert for %s — duration_str=%s, duration_minutes=%d",
                 ip, duration_str, duration_minutes)
        return [{
            "message": reason,
            "events": [{"timestamp": now_str, "meta": [{"key": "source_ip", "value": ip}]}],
            "events_count": 1,
            "stop_at": now_str,
            "start_at": now_str,
            "capacity": -1,
            "leakspeed": "0s",
            "simulated": False,
            "source": {"scope": "ip", "value": ip, "ip": ip},
            "scenario": "guardian/brute-force",
            "scenario_version": VERSION,
            "scenario_hash": "",
            "decisions": [{
                "duration": duration_str,
                "origin": "ha-guardian",
                "scenario": "guardian/brute-force",
                "scope": "ip",
                "simulated": False,
                "type": "ban",
                "value": ip,
            }],
        }]

    @staticmethod
    def _http_request(url: str, method: str = "GET", data: bytes = None,
                      headers: dict = None, timeout: int = 10) -> tuple:
        """Low-level HTTP via urllib (stdlib). Returns (status_int, body_str).
        Bypasses aiohttp entirely — uses the same code-path as curl/wget."""
        import urllib.request
        import urllib.error
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Content-Type", "application/json")
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return resp.status, resp.read().decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            body = e.read().decode("utf-8", errors="replace") if e.fp else str(e)
            return e.code, body
        except urllib.error.URLError as e:
            return 0, str(e.reason)
        except Exception as e:
            return 0, str(e)

    async def _post_alert(self, url: str, payload: list, headers: dict) -> tuple:
        """POST /v1/alerts via urllib. Returns (ok_bool, status_int, body_str)."""
        data = json.dumps(payload).encode("utf-8")
        status, body = await asyncio.to_thread(
            self._http_request, f"{url}/v1/alerts", "POST", data, headers
        )
        return status in (200, 201), status, body

    async def submit_ban(self, ip: str, duration_minutes: int, reason: str) -> dict:
        """Submit a ban decision to CrowdSec. Returns result dict."""
        if not self.enabled:
            msg = (f"skipped — not enabled (enabled={self._state.crowdsec_enabled}, "
                   f"url={bool(self._state.crowdsec_lapi_url)}, "
                   f"id={bool(self._state.crowdsec_machine_id)}, "
                   f"pw={bool(self._state.crowdsec_machine_password)})")
            log.info("CrowdSec: submit_ban %s", msg)
            return {"ok": False, "error": msg}
        url = self._state.crowdsec_lapi_url.rstrip("/")
        payload = self._build_alert_payload(ip, duration_minutes, reason)
        log.info("CrowdSec: submitting ban for %s to %s", ip, url)

        # Try trusted-IP mode first (no auth)
        ok, status, body = await self._post_alert(url, payload, {})
        if ok:
            log.info("CrowdSec: decision submitted for %s (trusted-IP mode)", ip)
            return {"ok": True, "mode": "trusted-ip"}
        log.info("CrowdSec: trusted-IP mode failed (%d) — %s", status, body[:200])

        # Fall back to machine login + JWT
        async with self._lock:
            now = datetime.now(timezone.utc)
            if not (self._jwt and self._jwt_expires and now < self._jwt_expires):
                self._jwt, _ = await self._login()
        if not self._jwt:
            log.warning("CrowdSec: login failed — cannot submit ban for %s", ip)
            return {"ok": False, "error": "login failed"}
        ok, status, body = await self._post_alert(url, payload, {"Authorization": f"Bearer {self._jwt}"})
        if ok:
            log.info("CrowdSec: decision submitted for %s (JWT mode)", ip)
            return {"ok": True, "mode": "jwt"}
        log.warning("CrowdSec: submit failed for %s (%d): %s", ip, status, body[:200])
        return {"ok": False, "error": f"HTTP {status}: {body[:200]}"}

    async def delete_ban(self, ip: str) -> dict:
        """Remove all CrowdSec decisions for an IP. Returns result dict."""
        if not self.enabled:
            log.info("CrowdSec: delete_ban skipped — not enabled")
            return {"ok": False, "error": "not enabled"}
        url = self._state.crowdsec_lapi_url.rstrip("/")
        endpoint = f"{url}/v1/decisions?ip={ip}"
        log.info("CrowdSec: deleting decisions for %s", ip)

        # Try trusted-IP mode first
        status, body = await asyncio.to_thread(
            self._http_request, endpoint, "DELETE", None, {}
        )
        if status in (200, 201):
            log.info("CrowdSec: decisions deleted for %s (trusted-IP mode)", ip)
            return {"ok": True, "mode": "trusted-ip"}
        log.info("CrowdSec: trusted-IP DELETE failed (%d) — %s", status, body[:200])

        # Fall back to JWT
        async with self._lock:
            now = datetime.now(timezone.utc)
            if not (self._jwt and self._jwt_expires and now < self._jwt_expires):
                self._jwt, _ = await self._login()
        if not self._jwt:
            log.warning("CrowdSec: login failed — cannot delete decisions for %s", ip)
            return {"ok": False, "error": "login failed"}
        status, body = await asyncio.to_thread(
            self._http_request, endpoint, "DELETE", None,
            {"Authorization": f"Bearer {self._jwt}"}
        )
        if status in (200, 201):
            log.info("CrowdSec: decisions deleted for %s (JWT mode)", ip)
            return {"ok": True, "mode": "jwt"}
        log.warning("CrowdSec: DELETE failed for %s (%d): %s", ip, status, body[:200])
        return {"ok": False, "error": f"HTTP {status}: {body[:200]}"}

    async def _login(self, url: str = None, machine_id: str = None, password: str = None) -> tuple:
        """Returns (token_or_None, error_str_or_None). Uses urllib (stdlib)."""
        url = (url or self._state.crowdsec_lapi_url or "").rstrip("/")
        machine_id = machine_id or self._state.crowdsec_machine_id
        password = password or self._state.crowdsec_machine_password
        pw_hint = f"{password[:3]}***{password[-2:]}" if password and len(password) > 5 else "???"
        log.info("CrowdSec: login attempt — machine_id=%s, pw_hint=%s, pw_len=%d, url=%s",
                 machine_id, pw_hint, len(password) if password else 0, url)
        data = json.dumps({"machine_id": machine_id, "password": password, "scenarios": []}).encode("utf-8")
        status, body = await asyncio.to_thread(
            self._http_request, f"{url}/v1/watchers/login", "POST", data, {}
        )
        if status == 200:
            try:
                tok = json.loads(body).get("token")
            except Exception:
                return None, f"HTTP 200 but bad JSON: {body[:200]}"
            if not tok:
                return None, f"HTTP 200 but no token: {body[:200]}"
            self._jwt = tok
            self._jwt_expires = datetime.now(timezone.utc) + timedelta(hours=23)
            log.info("CrowdSec: logged in as '%s'", machine_id)
            return self._jwt, None
        log.warning("CrowdSec login failed (%d): %s", status, body[:300])
        return None, f"HTTP {status}: {body[:300]}"

    async def test_connection(self, url: str = None, machine_id: str = None, password: str = None) -> dict:
        """Test connectivity via urllib. Tries trusted-IP mode first, then machine login."""
        test_url = (url or self._state.crowdsec_lapi_url or "").rstrip("/")
        if not test_url:
            return {"ok": False, "error": "LAPI URL not configured"}

        # 1) Reachability check via GET /v1/heartbeat
        status, body = await asyncio.to_thread(
            self._http_request, f"{test_url}/v1/heartbeat", "GET", None, None, 5
        )
        if status == 0:
            return {"ok": False, "error": f"Cannot reach LAPI: {body}"}
        log.info("CrowdSec heartbeat: %d", status)

        # 2) Try trusted-IP mode: GET /v1/alerts (no auth)
        status, body = await asyncio.to_thread(
            self._http_request, f"{test_url}/v1/alerts", "GET", None, None, 5
        )
        log.info("CrowdSec trusted-IP test: GET /v1/alerts → %d: %s", status, body[:100])
        if status == 200:
            return {"ok": True, "message": "Connected via trusted-IP (no auth required) — decisions will be submitted automatically"}

        # 3) Try machine login
        test_id = machine_id or self._state.crowdsec_machine_id or ""
        test_pw = password or self._state.crowdsec_machine_password or ""
        if not test_id:
            return {"ok": False, "error": "Trusted-IP mode failed and Machine ID not configured"}
        if not test_pw:
            return {"ok": False, "error": "Trusted-IP mode failed — enter Machine ID and Password for login mode"}

        tok, err = await self._login(test_url, test_id, test_pw)
        if tok:
            return {"ok": True, "message": f"Connected via machine login as '{test_id}'"}
        return {"ok": False, "error": f"Login failed: {err}"}


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


STARTUP_LOG_RE = re.compile(r"^addon_([a-z0-9_]+)\.log$", re.IGNORECASE)


def _extract_addon_slug_from_path(path: str) -> Optional[str]:
    """Extract the addon slug from addon_configs path or startup log filename."""
    p = Path(path)
    parts = p.parts
    # /addon_configs/{slug}/... paths
    if "addon_configs" in parts:
        idx = parts.index("addon_configs")
        if idx + 1 < len(parts):
            return parts[idx + 1]
    # /config/startup/logs/addon_{slug}.log or /config/logs/addon_{slug}.log
    m = STARTUP_LOG_RE.match(p.name)
    if m:
        return m.group(1)
    return None


# Map well-known log filenames to addon slugs (for logs outside /addon_configs/).
# Keys are lowercase filename stems, values are partial slug matches.
_FILENAME_TO_ADDON_HINT = {
    "npm": "nginxproxymanager",
    "2fauth": "2fauth",
    "nextcloud": "nextcloud",
    "vaultwarden": "bitwarden",
    "heimdall": "heimdall",
    "dokuwiki": "dokuwiki",
}


def _guess_addon_slug(path: str, known_slugs: list) -> Optional[str]:
    """Try to match a log file to an addon by filename heuristics.
    known_slugs: list of all discovered addon slugs.
    """
    # Files inside a crowdsec directory belong to the Crowdsec addon,
    # NOT to whatever the filename might suggest (e.g. npm.log, 2fauth.log).
    parts_lower = [p.lower() for p in Path(path).parts]
    if "crowdsec" in parts_lower:
        for slug in known_slugs:
            if "crowdsec" in slug.lower() and "bouncer" not in slug.lower() and "dashboard" not in slug.lower():
                return slug

    stem = Path(path).stem.lower()
    # Direct match in hint table
    for key, hint in _FILENAME_TO_ADDON_HINT.items():
        if key in stem:
            for slug in known_slugs:
                if hint in slug.lower():
                    return slug
    # Also try matching parent directory names
    for part in Path(path).parts:
        part_lower = part.lower()
        for key, hint in _FILENAME_TO_ADDON_HINT.items():
            if key in part_lower:
                for slug in known_slugs:
                    if hint in slug.lower():
                        return slug
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
                log.debug("Loaded %d log source(s) from disk", len(self._sources))
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
                        log.debug("Fetched %d addons from Supervisor API", len(addon_map))
                    else:
                        body = await resp.text()
                        log.warning("Supervisor API /addons returned %d: %s", resp.status, body[:200])
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
            # Never remove manually-added custom sources
            if s.get("custom"):
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
            log.debug("Removed stale/duplicate source: %s", name)

        # Disable orphaned file sources: enabled but no addon association,
        # not the HA core log, and not a custom source. These were likely
        # auto-enabled in a previous version and should only be active if
        # their addon is enabled.
        for sid, s in self._sources.items():
            if s["type"] != "file" or not s.get("enabled"):
                continue
            if s.get("custom"):
                continue
            if s.get("path") == self.config.log_file:
                continue
            slug = s.get("addon_slug") or _extract_addon_slug_from_path(s.get("path", ""))
            if not slug:
                slug = _guess_addon_slug(s.get("path", ""), list(addon_map.keys()))
                if slug:
                    s["addon_slug"] = slug
            if slug:
                # Has an addon — keep its enabled state
                continue
            # Orphaned: no addon, not core, not custom → disable
            s["enabled"] = False
            log.debug("Disabled orphaned source: %s", s.get("name", sid))

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
                    # Don't overwrite manually assigned addon_slug
                    if not self._sources[sid].get("manual_addon_slug"):
                        slug = _extract_addon_slug_from_path(path)
                        if not slug:
                            slug = _guess_addon_slug(path, list(addon_map.keys()))
                        if slug:
                            self._sources[sid]["addon_slug"] = slug
                            if slug in addon_map:
                                self._sources[sid]["name"] = f"{addon_map[slug]}: {Path(path).name}"
                    continue

                name = _friendly_name(path, addon_map)
                # Auto-enable if it's the HA core log or belongs to an already-enabled addon
                slug = _extract_addon_slug_from_path(path)
                if not slug:
                    slug = _guess_addon_slug(path, list(addon_map.keys()))
                enabled = (path == self.config.log_file)
                if not enabled and slug:
                    enabled = self._is_addon_enabled(slug)

                source_entry = {
                    "id": sid,
                    "name": name,
                    "type": "file",
                    "path": path,
                    "enabled": enabled,
                    "last_modified": mtime_iso,
                    "size": size,
                }
                if slug:
                    source_entry["addon_slug"] = slug

                self._sources[sid] = source_entry
                discovered += 1
                log.debug("Discovered log: %s (%s, modified %s)", name, path, mtime_iso)

        # 2) Discover HA addon docker logs via Supervisor API
        for slug, display_name in addon_map.items():
            if "ha_guardian" in slug:
                continue
            sid = "addon:" + slug
            state = getattr(self, "_addon_states", {}).get(slug, "")
            if sid not in self._sources:
                # Auto-enable if addon already has enabled file sources
                enabled = self._is_addon_enabled(slug)
                self._sources[sid] = {
                    "id": sid,
                    "name": f"Docker: {display_name}",
                    "type": "addon",
                    "slug": slug,
                    "state": state,
                    "enabled": enabled,
                }
                discovered += 1
                log.debug("Discovered addon docker log: %s (%s)%s",
                          display_name, slug, " [auto-enabled]" if enabled else "")
            else:
                self._sources[sid]["state"] = state
                self._sources[sid]["name"] = f"Docker: {display_name}"

        # HA Core log is covered by the file source /config/home-assistant.log.
        # The Supervisor API endpoint /core/logs returns 404 on many setups,
        # so we skip creating a redundant addon:core docker source entirely.
        # Clean up legacy addon:core if it exists from a previous version.
        if "addon:core" in self._sources:
            del self._sources["addon:core"]
            log.debug("Removed legacy addon:core source (use file source instead)")

        if discovered:
            log.debug("Discovered %d new source(s) — total: %d", discovered, len(self._sources))
        self._save()

    def _is_addon_enabled(self, addon_slug: str) -> bool:
        """Check if any source belonging to this addon is already enabled."""
        for src in self._sources.values():
            if not src.get("enabled"):
                continue
            if src["type"] == "addon" and src.get("slug") == addon_slug:
                return True
            if src["type"] == "file":
                s = src.get("addon_slug") or _extract_addon_slug_from_path(src.get("path", ""))
                if s == addon_slug:
                    return True
        return False

    def _refresh_file_mtimes(self):
        """Re-read mtime and size from disk for all file sources."""
        for src in self._sources.values():
            if src.get("type") == "file":
                try:
                    st = os.stat(src.get("path", ""))
                    src["last_modified"] = datetime.fromtimestamp(st.st_mtime).isoformat()
                    src["size"] = st.st_size
                except OSError:
                    pass

    def get_all(self) -> list:
        self._refresh_file_mtimes()
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

    def get_addons(self) -> list:
        """Return addon-level grouped view. Each addon aggregates its sources."""
        self._refresh_file_mtimes()

        groups: dict = {}  # addon_id -> {name, sources, enabled, ...}

        for src in self._sources.values():
            # Determine which addon this source belongs to
            addon_id = None
            if src["type"] == "addon":
                addon_id = src.get("slug", "")
                # Map the special "core" docker source to __core__ group
                if addon_id == "core":
                    addon_id = "__core__"
            elif src["type"] == "file":
                addon_id = src.get("addon_slug") or _extract_addon_slug_from_path(src.get("path", ""))
                # Update addon_slug on the source if we found one
                if addon_id and not src.get("addon_slug"):
                    src["addon_slug"] = addon_id

            # HA core log: path matches config log_file and no addon slug
            if not addon_id and src.get("path") == self.config.log_file:
                addon_id = "__core__"

            # Ungrouped auto-discovered sources → skip
            # Manually-added (custom=True) sources each get their own group (keyed by sid)
            if not addon_id:
                if src.get("custom"):
                    addon_id = src["id"]  # unique per file
                else:
                    continue

            if addon_id not in groups:
                groups[addon_id] = {
                    "id": addon_id,
                    "name": "",
                    "state": "",
                    "enabled": False,
                    "source_count": 0,
                    "file_count": 0,
                    "docker_log": False,
                    "custom": src.get("custom", False),
                    "last_modified": None,
                    "total_size": 0,
                    "sources": [],
                    "files": [],
                }

            g = groups[addon_id]
            g["sources"].append(src["id"])
            g["source_count"] += 1

            if src.get("enabled"):
                g["enabled"] = True

            if src["type"] == "addon":
                g["docker_log"] = True
                g["state"] = src.get("state", "")
                # Use addon docker name as the primary name
                docker_name = src.get("name", "").replace("Docker: ", "")
                if docker_name:
                    g["name"] = docker_name
            elif src["type"] == "file":
                g["file_count"] += 1
                g["total_size"] += src.get("size", 0)
                g["files"].append({
                    "source_id": src["id"],
                    "name": Path(src.get("path", "")).name,
                    "path": src.get("path", ""),
                    "size": src.get("size", 0),
                    "last_modified": src.get("last_modified"),
                    "manual": src.get("manual_addon_slug", False),
                })
                # Track most recent modification
                lm = src.get("last_modified")
                if lm and (not g["last_modified"] or lm > g["last_modified"]):
                    g["last_modified"] = lm

            # Fallback name from file source if no docker name
            if not g["name"]:
                if addon_id == "__core__":
                    g["name"] = "Home Assistant Core"
                elif addon_id == "__unused__":
                    g["name"] = "Unused"
                elif src.get("custom"):
                    g["name"] = Path(src.get("path", src["id"])).name
                else:
                    # Try to get clean name from the source name
                    sname = src.get("name", addon_id)
                    # Strip filename part like ": laravel-2026-03-27.log"
                    if ": " in sname:
                        sname = sname.split(": ")[0]
                    g["name"] = sname

        # Build result list
        result = []
        for addon_id, g in groups.items():
            result.append({
                "id": addon_id,
                "name": g["name"],
                "state": g["state"],
                "enabled": g["enabled"],
                "source_count": g["source_count"],
                "file_count": g["file_count"],
                "docker_log": g["docker_log"],
                "last_modified": g["last_modified"],
                "total_size": g["total_size"],
                "custom": g.get("custom", False),
                "files": g.get("files", []),
            })

        # Sort: enabled first, then by name; __unused__ always last
        result.sort(key=lambda a: (a["id"] == "__unused__", not a["enabled"], a["name"].lower()))
        return result

    def toggle_addon(self, addon_id: str, enabled: bool,
                     scanner: Optional["LogScanner"] = None) -> bool:
        """Toggle all sources belonging to an addon on or off."""
        found = False
        toggled = []
        for src in self._sources.values():
            src_addon = None
            if src["type"] == "addon":
                src_addon = src.get("slug", "")
                # Map "core" docker source to __core__ group
                if src_addon == "core":
                    src_addon = "__core__"
            elif src["type"] == "file":
                if addon_id == "__core__" and src.get("path") == self.config.log_file:
                    src_addon = "__core__"
                else:
                    extracted = src.get("addon_slug") or _extract_addon_slug_from_path(src.get("path", ""))
                    src_addon = extracted if extracted else (src["id"] if src.get("custom") else None)
            if src_addon == addon_id:
                src["enabled"] = enabled
                toggled.append(src)
                found = True
        if found:
            self._save()
            # Clean up scanner state for disabled sources immediately
            if not enabled and scanner:
                for src in toggled:
                    if src["type"] == "file":
                        path = src.get("path", "")
                        if path in scanner._file_state:
                            del scanner._file_state[path]
                    elif src["type"] == "addon":
                        slug = src.get("slug", "")
                        if slug in scanner._addon_state:
                            del scanner._addon_state[slug]
            toggled_ids = [s["id"] for s in toggled]
            log.info("Toggled addon %s → %s (%d sources: %s)",
                     addon_id, "ON" if enabled else "OFF", len(toggled_ids),
                     ", ".join(toggled_ids[:5]))
        else:
            log.warning("Toggle failed: addon_id=%s not found in %d sources",
                        addon_id, len(self._sources))
        return found

    def add_custom_source(self, path: str) -> tuple:
        """Manually add a file path as a custom source. Returns (ok, error)."""
        p = Path(path)
        if not p.exists():
            return False, f"File not found: {path}"
        if not p.is_file():
            return False, f"Not a file: {path}"
        sid = "file:" + path
        if sid in self._sources:
            return False, "Source already exists"
        try:
            st = p.stat()
        except OSError as e:
            return False, str(e)
        self._sources[sid] = {
            "id": sid,
            "name": p.name,
            "type": "file",
            "path": path,
            "enabled": True,
            "custom": True,  # manually added — show in __custom__ group
            "last_modified": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
            "size": st.st_size,
        }
        self._save()
        log.info("Manually added custom source: %s", path)
        return True, ""

    async def health_check(self) -> dict:
        """Check each enabled source for recent activity (entries within last 7 days).
        Returns {addon_id: {"status": "ok"|"stale"|"empty", "newest": iso|None}}
        """
        HEALTH_DAYS = 7
        cutoff = datetime.now(timezone.utc) - timedelta(days=HEALTH_DAYS)
        results = {}

        # Group sources by addon (same logic as get_addons)
        addon_sources: dict = {}  # addon_id -> [src, ...]
        for src in self._sources.values():
            if not src.get("enabled"):
                continue
            addon_id = None
            if src["type"] == "addon":
                addon_id = src.get("slug", "")
                if addon_id == "core":
                    addon_id = "__core__"
            elif src["type"] == "file":
                addon_id = src.get("addon_slug") or _extract_addon_slug_from_path(src.get("path", ""))
                if not addon_id and src.get("path") == self.config.log_file:
                    addon_id = "__core__"
                if not addon_id and src.get("custom"):
                    addon_id = src["id"]
            if not addon_id:
                continue
            addon_sources.setdefault(addon_id, []).append(src)

        for addon_id, sources in addon_sources.items():
            newest_ts = None
            for src in sources:
                lines = await self.preview_source(src["id"], 200)
                for line in reversed(lines):
                    ts = _parse_line_timestamp(line)
                    if ts and (newest_ts is None or ts > newest_ts):
                        newest_ts = ts
                        break  # newest line with timestamp found for this source

            if newest_ts is None:
                results[addon_id] = {"status": "empty", "newest": None}
            elif newest_ts < cutoff:
                results[addon_id] = {"status": "stale", "newest": newest_ts.isoformat()}
            else:
                results[addon_id] = {"status": "ok", "newest": newest_ts.isoformat()}

        return results

    def preview_addon(self, addon_id: str) -> Optional[str]:
        """Find the best source ID for previewing an addon's logs.
        Prefers the most recently modified file, falls back to docker log.
        """
        best_file = None
        best_mtime = ""
        docker_id = None

        for src in self._sources.values():
            src_addon = None
            if src["type"] == "addon":
                src_addon = src.get("slug", "")
                if src_addon == "core":
                    src_addon = "__core__"
            elif src["type"] == "file":
                if addon_id == "__core__" and src.get("path") == self.config.log_file:
                    src_addon = "__core__"
                elif src.get("custom"):
                    src_addon = src["id"]  # custom files: match by own sid
                else:
                    src_addon = src.get("addon_slug") or _extract_addon_slug_from_path(src.get("path", ""))
            if src_addon != addon_id:
                continue
            if src["type"] == "addon":
                docker_id = src["id"]
            elif src["type"] == "file":
                lm = src.get("last_modified", "")
                if not best_file or lm > best_mtime:
                    best_file = src["id"]
                    best_mtime = lm

        return best_file or docker_id

    def remove_source(self, source_id: str, delete_file: bool = False) -> bool:
        """Remove a source from tracking. If delete_file=True, also delete the file."""
        src = self._sources.get(source_id)
        if not src:
            return False
        if delete_file and src.get("type") == "file":
            path = src.get("path", "")
            if path:
                try:
                    Path(path).unlink(missing_ok=True)
                    log.info("Deleted log file: %s", path)
                except Exception as e:
                    log.warning("Could not delete file %s: %s", path, e)
        del self._sources[source_id]
        self._save()
        log.info("Removed source: %s", source_id)
        return True

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
    # iptables chain name — all Guardian rules go here for easy flush
    _CHAIN = "GUARDIAN"
    # nftables table/set/chain names
    _NFT_TABLE = "guardian"
    _NFT_SET   = "blocklist"
    _NFT_CHAIN = "input"

    def __init__(self, config: Config, crowdsec: "CrowdSecManager" = None):
        self.config = config
        self._crowdsec = crowdsec
        self._bans: dict = {}
        self._evidence: dict = {}   # ip -> list of event dicts
        self._lock = asyncio.Lock()
        self._ipt_bin, self._use_nft = self._detect_firewall_backend()
        self._iptables_available = self._ipt_bin is not None or self._use_nft
        self._load()

    # ------------------------------------------------------------------
    # Firewall backend detection
    # ------------------------------------------------------------------
    @staticmethod
    def _detect_firewall_backend() -> tuple:
        """Return (ipt_binary_or_None, use_nft_bool).
        Tries iptables-nft first (works on nftables kernels like HassOS),
        then iptables legacy, then native nft."""
        # Try iptables variants (prefer nft-backed so it works on HassOS)
        for binary in ["iptables-nft", "iptables", "iptables-legacy"]:
            try:
                r = subprocess.run(
                    [binary, "-L", "INPUT", "-n"],
                    capture_output=True, timeout=3
                )
                if r.returncode == 0:
                    log.info("Firewall backend: %s — enforcement active", binary)
                    return binary, False
                err = r.stderr.decode(errors="replace").strip()
                log.warning("Firewall candidate %s failed (rc=%d): %s", binary, r.returncode, err)
            except FileNotFoundError:
                log.warning("Firewall candidate %s: not found in PATH", binary)
            except Exception as e:
                log.warning("Firewall candidate %s: %s", binary, e)
        # Fall back to native nftables
        try:
            r = subprocess.run(["nft", "list", "tables"], capture_output=True, timeout=3)
            if r.returncode == 0:
                log.info("Firewall backend: nft (nftables) — enforcement active")
                return None, True
            err = r.stderr.decode(errors="replace").strip()
            log.warning("Firewall candidate nft failed (rc=%d): %s", r.returncode, err)
        except FileNotFoundError:
            log.warning("Firewall candidate nft: not found in PATH")
        except Exception as e:
            log.warning("Firewall candidate nft: %s", e)
        log.warning("No working firewall backend found — firewall enforcement disabled")
        return None, False

    # ------------------------------------------------------------------
    # iptables helpers
    # ------------------------------------------------------------------
    def _ensure_chain(self):
        """Create GUARDIAN chain and hook it into INPUT if not present."""
        try:
            subprocess.run([self._ipt_bin, "-N", self._CHAIN],
                           capture_output=True, timeout=3)
            r = subprocess.run(
                [self._ipt_bin, "-C", "INPUT", "-j", self._CHAIN],
                capture_output=True, timeout=3
            )
            if r.returncode != 0:
                subprocess.run(
                    [self._ipt_bin, "-I", "INPUT", "1", "-j", self._CHAIN],
                    check=True, timeout=3
                )
        except Exception as e:
            log.warning("iptables chain setup failed: %s", e)

    def _ipt_ban(self, ip: str):
        try:
            self._ensure_chain()
            r = subprocess.run(
                [self._ipt_bin, "-C", self._CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=3
            )
            if r.returncode != 0:
                subprocess.run(
                    [self._ipt_bin, "-A", self._CHAIN, "-s", ip, "-j", "DROP"],
                    check=True, timeout=3
                )
            log.debug("iptables: blocked %s", ip)
        except Exception as e:
            log.warning("iptables ban failed for %s: %s", ip, e)

    def _ipt_unban(self, ip: str):
        try:
            subprocess.run(
                [self._ipt_bin, "-D", self._CHAIN, "-s", ip, "-j", "DROP"],
                capture_output=True, timeout=3
            )
            log.debug("iptables: unblocked %s", ip)
        except Exception as e:
            log.warning("iptables unban failed for %s: %s", ip, e)

    # ------------------------------------------------------------------
    # nftables helpers (used when HassOS has no legacy iptables kernel module)
    # ------------------------------------------------------------------
    def _nft_run(self, script: str) -> bool:
        """Run an nft script passed via stdin. Returns True on success."""
        try:
            r = subprocess.run(
                ["nft", "-f", "-"],
                input=script.encode(),
                capture_output=True, timeout=3
            )
            if r.returncode != 0:
                log.debug("nft script failed (rc=%d): %s", r.returncode,
                          r.stderr.decode(errors="replace").strip())
            return r.returncode == 0
        except Exception as e:
            log.warning("nft run error: %s", e)
            return False

    def _nft_setup(self):
        """Ensure nftables table, set, and drop rule exist."""
        t, s, c = self._NFT_TABLE, self._NFT_SET, self._NFT_CHAIN
        # Check if set already has the drop rule wired up
        r = subprocess.run(
            ["nft", "list", "table", "inet", t],
            capture_output=True, timeout=3
        )
        if r.returncode == 0 and f"saddr @{s} drop" in r.stdout.decode(errors="replace"):
            return  # already set up
        self._nft_run(
            f"add table inet {t}\n"
            f"add set inet {t} {s} {{ type ipv4_addr; }}\n"
            f"add chain inet {t} {c} {{ type filter hook input priority -10; }}\n"
            f"add rule inet {t} {c} ip saddr @{s} drop\n"
        )

    def _nft_ban(self, ip: str):
        try:
            self._nft_setup()
            self._nft_run(
                f"add element inet {self._NFT_TABLE} {self._NFT_SET} {{ {ip} }}\n"
            )
            log.debug("nft: blocked %s", ip)
        except Exception as e:
            log.warning("nft ban failed for %s: %s", ip, e)

    def _nft_unban(self, ip: str):
        try:
            self._nft_run(
                f"delete element inet {self._NFT_TABLE} {self._NFT_SET} {{ {ip} }}\n"
            )
            log.debug("nft: unblocked %s", ip)
        except Exception as e:
            log.warning("nft unban failed for %s: %s", ip, e)

    # ------------------------------------------------------------------
    # Public ban/unban (backend-agnostic)
    # ------------------------------------------------------------------
    def _fw_ban(self, ip: str):
        if not self._iptables_available:
            return
        if self._use_nft:
            self._nft_ban(ip)
        else:
            self._ipt_ban(ip)

    def _fw_unban(self, ip: str):
        if not self._iptables_available:
            return
        if self._use_nft:
            self._nft_unban(ip)
        else:
            self._ipt_unban(ip)

    def restore_iptables(self):
        """Re-apply firewall rules for all currently active bans (called on startup)."""
        if not self._iptables_available:
            log.info("No firewall backend — skipping firewall rules")
            return
        if self._use_nft:
            self._nft_setup()
        else:
            self._ensure_chain()
        count = 0
        for ip in self._bans:
            self._fw_ban(ip)
            count += 1
        if count:
            log.info("Firewall: restored %d ban rule(s)", count)

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
        if not self.config._state.ban_to_ipbans:
            return
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
                  duration_minutes=None, source="", evidence=None,
                  skip_crowdsec=False) -> bool:
        if self.config.is_whitelisted(ip):
            log.debug("IP %s is whitelisted — skipping ban", ip)
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
            if evidence is not None:
                self._evidence[ip] = evidence
            await self._flush()
        self._fw_ban(ip)
        log.info("Banned %s for %d min — %s", ip, dur, reason)
        if self._crowdsec and not skip_crowdsec and self.config._state.ban_to_crowdsec:
            asyncio.create_task(self._crowdsec.submit_ban(ip, dur, reason))
        return True

    def get_evidence(self, ip: str) -> list:
        return self._evidence.get(ip, [])

    async def unban(self, ip: str, skip_crowdsec: bool = False) -> bool:
        async with self._lock:
            if ip not in self._bans:
                return False
            del self._bans[ip]
            self._evidence.pop(ip, None)
            await self._flush()
        self._fw_unban(ip)
        log.info("Unbanned %s", ip)
        if self._crowdsec and not skip_crowdsec and self.config._state.ban_to_crowdsec:
            asyncio.create_task(self._crowdsec.delete_ban(ip))
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
                            log.debug("Ban expired for %s", ip)
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
        self._ip_events: dict = defaultdict(lambda: deque(maxlen=50))
        self._events: deque = deque(maxlen=500)
        self._total_attempts = 0
        self._total_bans = 0
        self._whitelisted_skips = 0
        self._last_whitelisted_ip = ""
        self._started = datetime.now(timezone.utc)

    async def record(self, ip, source_id, source_name, url="", pattern="",
                     line="", log_time=None):
        if self.config.is_whitelisted(ip):
            self._whitelisted_skips += 1
            self._last_whitelisted_ip = ip
            log.debug("Skipped whitelisted IP %s (source=%s, pattern=%s)",
                      ip, source_name, pattern)
            # Still show skipped events in the dashboard so the user sees
            # that the pattern DID match — just wasn't counted.
            event_time = log_time if log_time else datetime.now(timezone.utc)
            skip_event = {
                "time": event_time.isoformat(), "ip": ip,
                "source_id": source_id, "source_name": source_name,
                "url": url, "pattern": pattern, "line": line,
                "count": 0, "banned": False, "skipped": True,
            }
            self._events.appendleft(skip_event)
            return
        now = datetime.now(timezone.utc)
        # Use the timestamp from the log line for display only.
        # For the sliding window (ban counting), always use now — otherwise
        # historical log_times (e.g. 10:39) would be older than the cutoff
        # (now - window_minutes) and get immediately removed, keeping count at 1.
        event_time = log_time if log_time else now
        cutoff = now - timedelta(minutes=self.config.window_minutes)
        dq = self._windows[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)  # always use now for window counting, not log_time
        self._total_attempts += 1
        self.alerts.record(source_id, source_name, ip)
        banned_now = False

        event = {
            "time": event_time.isoformat(), "ip": ip,
            "source_id": source_id, "source_name": source_name,
            "url": url, "pattern": pattern, "line": line,
        }
        self._ip_events[ip].appendleft(event)

        if len(dq) >= self.config.max_attempts and not self.bans.is_banned(ip):
            evidence = list(self._ip_events[ip])
            ok = await self.bans.ban(ip, reason="auto", attempts=len(dq),
                                     source=source_id, evidence=evidence)
            if ok:
                self._total_bans += 1
                banned_now = True
                dq.clear()

        full_event = dict(event)
        full_event["count"] = len(dq) if not banned_now else self.config.max_attempts
        full_event["banned"] = banned_now
        self._events.appendleft(full_event)
        if banned_now:
            log.warning("BANNED %s (%d attempts via %s)", ip, self.config.max_attempts, source_name)
        else:
            log.debug(
                "Failed login from %s via %s (%d/%d)",
                ip, source_name, len(dq), self.config.max_attempts,
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
            "iptables_available": self.bans._iptables_available,
        }

    def events(self) -> list:
        return list(self._events)

    def clear_window(self, ip: str):
        """Clear the sliding window for an IP so counting restarts from 0."""
        self._windows.pop(ip, None)
        self._ip_events.pop(ip, None)

    def get_ip_events(self, ip: str) -> list:
        """Return last matched log lines for a given IP."""
        return list(self._ip_events.get(ip, []))

    async def cleanup_windows_loop(self):
        """Periodically remove expired IP entries from the tracking window."""
        while True:
            await asyncio.sleep(60)
            cutoff = datetime.now(timezone.utc) - timedelta(minutes=self.config.window_minutes)
            stale = [ip for ip, dq in self._windows.items() if not dq or dq[-1] < cutoff]
            for ip in stale:
                del self._windows[ip]
            if stale:
                log.debug("Cleaned up %d stale IP windows", len(stale))


# ---------------------------------------------------------------------------
# Log Scanner — tails files + polls addon docker logs
# ---------------------------------------------------------------------------
class LogScanner:
    def __init__(self, source_mgr: SourceManager, detector: Detector, config: Config):
        self.source_mgr = source_mgr
        self.detector = detector
        self.config = config
        self._file_state: dict = {}   # path -> {"inode": int, "pos": int}
        self._addon_state: dict = {}  # slug -> last_length (for debug display)
        self._addon_tail: dict = {}   # slug -> list of last N lines (for dedup)
        # Buffer of recent unmatched auth-related lines (for debugging)
        self.unmatched_lines: deque = deque(maxlen=200)
        self._last_status_log: float = 0  # timestamp of last periodic status log

    async def run(self):
        await self.source_mgr.discover()
        enabled = self.source_mgr.get_enabled()
        log.info("Log scanner started — %d source(s) enabled out of %d total",
                 len(enabled), len(self.source_mgr.get_all()))
        for s in enabled:
            log.info("  Active: [%s] %s (%s)", s.get("type"), s.get("name"),
                     s.get("path", s.get("slug", "")))
        self._last_status_log = datetime.now().timestamp()

        _addon_tick = 0
        _cleanup_tick = 0
        while True:
            # Periodically clean up state for disabled sources (every 60 ticks)
            _cleanup_tick += 1
            if _cleanup_tick >= 60:
                _cleanup_tick = 0
                enabled_paths = {s["path"] for s in self.source_mgr.get_enabled("file")}
                enabled_slugs = {s.get("slug", "") for s in self.source_mgr.get_enabled("addon")}
                stale_files = [p for p in self._file_state if p not in enabled_paths]
                stale_addons = [s for s in self._addon_state if s not in enabled_slugs]
                for p in stale_files:
                    del self._file_state[p]
                for s in stale_addons:
                    del self._addon_state[s]
                if stale_files or stale_addons:
                    log.debug("Cleaned scanner state: %d file(s), %d addon(s)",
                              len(stale_files), len(stale_addons))

            for src in self.source_mgr.get_enabled("file"):
                await self._scan_file(src)
            _addon_tick += 1
            if _addon_tick >= self.config.addon_poll_interval:
                _addon_tick = 0
                for src in self.source_mgr.get_enabled("addon"):
                    await self._poll_addon(src)
            # Periodic status log (controlled by log_interval_minutes)
            now = datetime.now().timestamp()
            if now - self._last_status_log >= self.config.log_interval_minutes * 60:
                self._last_status_log = now
                stats = self.detector.stats()
                log.info(
                    "Status: %d attempts, %d bans, %d tracked IPs, %d sources",
                    stats["total_attempts"], stats["total_bans"],
                    stats["tracked_ips"], len(self.source_mgr.get_enabled()),
                )
            await asyncio.sleep(self.config.scan_interval_seconds)

    def _calc_initial_pos(self, path: str, stat_result) -> int:
        """Calculate where to start reading a file on first scan.

        Uses the configured alert_window_hours to estimate how far back to read.
        If the file is younger than the window, read from the beginning.
        Otherwise, estimate the position proportionally based on file age.
        """
        size = stat_result.st_size
        if size == 0:
            return 0
        mtime = stat_result.st_mtime
        # Use birth time if available, otherwise fall back to ctime
        ctime = getattr(stat_result, "st_birthtime", stat_result.st_ctime)
        now = datetime.now().timestamp()
        file_age_seconds = max(1, now - ctime)
        window_seconds = self.config.alert_window_hours * 3600

        if file_age_seconds <= window_seconds:
            # File is younger than window — read from start
            return 0

        # Estimate: assume log grows linearly over time
        fraction_to_read = min(1.0, window_seconds / file_age_seconds)
        pos = max(0, int(size * (1.0 - fraction_to_read)))
        # Cap at reasonable maximum (5MB) to avoid reading huge files on first scan
        pos = max(pos, size - 5 * 1024 * 1024)
        return max(0, pos)

    async def _scan_file(self, src: dict):
        path = src["path"]
        try:
            if not Path(path).exists():
                return
            stat = os.stat(path)
            inode, size = stat.st_ino, stat.st_size
            state = self._file_state.get(path)

            first_read = False
            if state is None:
                # First scan: estimate how much to read based on alert_window_hours.
                # Use file mtime and ctime to guess the portion within the time window.
                initial_pos = self._calc_initial_pos(path, stat)
                self._file_state[path] = {"inode": inode, "pos": initial_pos}
                log.debug("First scan of %s — reading from pos %d/%d (window=%dh)",
                         path, initial_pos, size, self.config.alert_window_hours)
                state = self._file_state[path]
                first_read = True

            if inode != state["inode"] or size < state["pos"]:
                # File rotated or truncated — re-read from calculated position
                new_pos = self._calc_initial_pos(path, stat)
                state["inode"] = inode
                state["pos"] = new_pos
                first_read = True
                if size > MAX_INITIAL_READ_BYTES:
                    log.info("Large rotated file %s (%d MB), reading last %d MB",
                             path, size // (1024*1024), MAX_INITIAL_READ_BYTES // (1024*1024))
                log.debug("Log rotated: %s", path)

            if state["pos"] >= size:
                return

            with open(path, errors="replace") as f:
                f.seek(state["pos"])
                for line in f:
                    await self._process_line(line, src, first_read=first_read)
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
                        log.debug("Addon %s logs returned %d", slug, resp.status)
                        return
                    text = await resp.text()

            lines = text.splitlines()
            if not lines:
                return

            last_tail = self._addon_tail.get(slug)

            if last_tail is None:
                # First poll: process recent lines with first_read filter
                cap = min(len(lines), 10000)  # cap at 10k lines
                log.debug("First poll of addon %s — %d lines (processing last %d)", slug, len(lines), cap)
                for line in lines[-cap:]:
                    await self._process_line(line, src, first_read=True)
            else:
                # Find where we left off by matching the last known tail lines.
                # Docker logs rotate (old lines removed from start), so
                # length-based tracking is unreliable.
                tail_len = len(last_tail)
                found_at = -1
                # Search for the sequence of tail lines in the current lines
                for i in range(len(lines) - tail_len + 1):
                    if lines[i:i + tail_len] == last_tail:
                        found_at = i + tail_len
                        break
                if found_at >= 0:
                    # Process everything after the matched tail
                    new_lines = lines[found_at:]
                else:
                    # Tail not found — log was fully rotated.
                    # Process all with first_read filter to avoid duplicates.
                    log.debug("Addon %s — tail not found, processing all %d lines", slug, len(lines))
                    new_lines = lines
                for line in new_lines:
                    first_read = (found_at < 0)
                    await self._process_line(line, src, first_read=first_read)

            # Store last N lines as fingerprint for next poll
            tail_size = min(5, len(lines))
            self._addon_tail[slug] = lines[-tail_size:]
            # Also update addon_state for debug display
            self._addon_state[slug] = len(text)
        except Exception as e:
            log.debug("Error polling addon %s: %s", slug, e)

    async def _process_line(self, line: str, src: dict, first_read: bool = False):
        line = line.strip()
        if not line:
            return
        # On first read of a source, skip lines outside the alert window to avoid
        # re-triggering old events. During normal tailing, process all new lines
        # regardless of age (they are genuinely new data from the file/addon).
        if first_read:
            ts = _parse_line_timestamp(line)
            if ts is not None:
                age_seconds = (datetime.now(timezone.utc) - ts).total_seconds()
                # Skip logs older than the detection window to avoid counting
                # old login attempts as if they happened just now
                if age_seconds > self.config.window_minutes * 60:
                    log.debug("Skipped old log line (%dmin old): %s", int(age_seconds/60), line[:100])
                    return
        result = extract_ip(line)
        if result:
            ip, pattern_name = result
            url = ""
            um = URL_RE.search(line)
            if um:
                url = um.group(1)
            # Parse log line timestamp for accurate event time
            log_time = _parse_line_timestamp(line)
            await self.detector.record(
                ip=ip, source_id=src["id"],
                source_name=src.get("name", src["id"]),
                url=url, pattern=pattern_name, line=line,
                log_time=log_time,
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
            interval = max(60, self.config.discover_interval_minutes * 60)
            await asyncio.sleep(interval)
            log.info("Periodic log source discovery (interval=%d min)",
                     self.config.discover_interval_minutes)
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


def build_app(config, bans, detector, source_mgr, alerts, scanner=None,  # noqa: PLR0915
              rules_mgr=None, crowdsec_mgr=None) -> web.Application:
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
            ok = await bans.ban(ip, reason=reason, manual=True, duration_minutes=dur,
                               skip_crowdsec=True)
            if ok:
                # Await CrowdSec directly so we can return its result
                cs_result = None
                if crowdsec_mgr and config._state.ban_to_crowdsec:
                    cs_result = await crowdsec_mgr.submit_ban(ip, dur, reason)
                return web.json_response({"ok": True, "crowdsec": cs_result})
            return web.json_response({"ok": False, "error": "IP is whitelisted"}, status=400)
        except (ValueError, TypeError) as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def handle_delete_ban(req):
        ip = req.match_info["ip"]
        ok = await bans.unban(ip, skip_crowdsec=True)
        if ok:
            # Clear the detector window so counter restarts from 0
            detector.clear_window(ip)
            cs_result = None
            if crowdsec_mgr and config._state.ban_to_crowdsec:
                cs_result = await crowdsec_mgr.delete_ban(ip)
            return web.json_response({"ok": True, "crowdsec": cs_result})
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
        # Support both path param and JSON body (CIDR entries contain '/')
        try:
            d = await req.json()
            entry = d.get("entry", "").strip()
        except Exception:
            entry = req.match_info.get("entry", "")
        wl = list(config.whitelist)
        if entry in wl:
            wl.remove(entry)
            config.whitelist = wl
            return web.json_response({"ok": True})
        return web.json_response({"ok": False, "error": "not found"}, status=404)

    async def handle_get_my_ip(req):
        ip = config._state.my_ip
        return web.json_response({"ip": ip, "enabled": ip is not None})

    async def handle_post_my_ip(req):
        d = await req.json()
        ip = d.get("ip", "").strip()
        if not ip:
            return web.json_response({"ok": False, "error": "empty ip"}, status=400)
        config._state.my_ip = ip
        return web.json_response({"ok": True})

    async def handle_delete_my_ip(req):
        config._state.my_ip = None
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

    async def handle_add_custom_source(req):
        d = await req.json()
        path = (d.get("path") or "").strip()
        if not path:
            return web.json_response({"ok": False, "error": "path required"}, status=400)
        ok, err = source_mgr.add_custom_source(path)
        if not ok:
            return web.json_response({"ok": False, "error": err}, status=400)
        return web.json_response({"ok": True})

    async def handle_get_addons(req):
        return web.json_response(source_mgr.get_addons())

    async def handle_toggle_addon(req):
        d = await req.json()
        addon_id = d.get("id", "")
        enabled = bool(d.get("enabled", False))
        ok = source_mgr.toggle_addon(addon_id, enabled, scanner=scanner)
        if ok:
            return web.json_response({"ok": True})
        return web.json_response({"ok": False, "error": "addon not found"}, status=404)

    async def handle_preview_addon(req):
        d = await req.json()
        addon_id = d.get("id", "")
        n = min(int(d.get("lines", 100)), 200)
        source_id = source_mgr.preview_addon(addon_id)
        if not source_id:
            return web.json_response({"lines": ["No log sources found for this addon"]})
        lines = await source_mgr.preview_source(source_id, n)
        return web.json_response({"lines": lines, "source_id": source_id})

    async def handle_health_check(req):
        result = await source_mgr.health_check()
        return web.json_response(result)

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
        if "scan_interval_seconds" in d:
            config.scan_interval_seconds = max(1, int(d["scan_interval_seconds"]))
        if "addon_poll_interval" in d:
            config.addon_poll_interval = max(5, int(d["addon_poll_interval"]))
        if "log_interval_minutes" in d:
            config.log_interval_minutes = max(1, int(d["log_interval_minutes"]))
        if "discover_interval_minutes" in d:
            config.discover_interval_minutes = max(1, int(d["discover_interval_minutes"]))
        if "trusted_domains" in d:
            config.trusted_domains = [s.strip() for s in d["trusted_domains"] if s.strip()]
        # CrowdSec settings (stored in persistent state, not in options.json)
        if "crowdsec_enabled" in d:
            config._state.crowdsec_enabled = bool(d["crowdsec_enabled"])
        if "crowdsec_lapi_url" in d:
            config._state.crowdsec_lapi_url = str(d["crowdsec_lapi_url"]).strip()
        if "crowdsec_machine_id" in d:
            config._state.crowdsec_machine_id = str(d["crowdsec_machine_id"]).strip()
        if "crowdsec_machine_password" in d and d["crowdsec_machine_password"]:
            config._state.crowdsec_machine_password = str(d["crowdsec_machine_password"])
        # Ban targets
        if "ban_to_ipbans" in d:
            config._state.ban_to_ipbans = bool(d["ban_to_ipbans"])
        if "ban_to_crowdsec" in d:
            config._state.ban_to_crowdsec = bool(d["ban_to_crowdsec"])
        config.save()
        return web.json_response({"ok": True})

    async def handle_health(req):
        return web.json_response({"status": "ok", "version": VERSION})

    async def handle_crowdsec_test(req):
        if crowdsec_mgr is None:
            return web.json_response({"ok": False, "error": "CrowdSec manager not initialized"})
        try:
            d = await req.json()
        except Exception:
            d = {}
        result = await crowdsec_mgr.test_connection(
            url=d.get("url") or None,
            machine_id=d.get("machine_id") or None,
            password=d.get("password") or None,
        )
        return web.json_response(result)

    # --- System status: protected mode + iptables ---
    async def handle_get_system(req):
        """Return system-level info: protected mode, iptables availability."""
        protected = None  # unknown
        token = source_mgr.get_supervisor_token()
        slug = os.environ.get("HOSTNAME", "")
        # Try to determine our own addon slug
        addon_slug = None
        if token:
            try:
                async with aiohttp_client.ClientSession() as session:
                    headers = {"Authorization": f"Bearer {token}"}
                    # /addons/self/info works for the current addon
                    async with session.get(
                        f"{SUPERVISOR_URL}/addons/self/info",
                        headers=headers,
                        timeout=aiohttp_client.ClientTimeout(total=10),
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            info = data.get("data", {})
                            protected = info.get("protected", None)
                            addon_slug = info.get("slug", slug)
            except Exception as e:
                log.debug("Could not fetch addon self info: %s", e)
        if bans._use_nft:
            fw_backend = "nft"
        elif bans._ipt_bin:
            fw_backend = bans._ipt_bin
        else:
            fw_backend = None
        return web.json_response({
            "protected_mode": protected,
            "iptables_available": bans._iptables_available,
            "firewall_backend": fw_backend,
            "addon_slug": addon_slug,
            "host_network": True,
        })

    async def handle_set_protection(req):
        """Toggle protected mode for this addon via Supervisor API."""
        try:
            d = await req.json()
            enable = d.get("protected", True)
        except Exception:
            return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)
        token = source_mgr.get_supervisor_token()
        if not token:
            return web.json_response(
                {"ok": False, "error": "No Supervisor token available"},
                status=500,
            )
        try:
            async with aiohttp_client.ClientSession() as session:
                headers = {
                    "Authorization": f"Bearer {token}",
                    "Content-Type": "application/json",
                }
                async with session.post(
                    f"{SUPERVISOR_URL}/addons/self/security",
                    headers=headers,
                    json={"protected": enable},
                    timeout=aiohttp_client.ClientTimeout(total=10),
                ) as resp:
                    if resp.status == 200:
                        result = await resp.json()
                        if result.get("result") == "ok":
                            # Re-detect firewall backend after toggling
                            bans._ipt_bin, bans._use_nft = bans._detect_firewall_backend()
                            bans._iptables_available = bans._ipt_bin is not None or bans._use_nft
                            if bans._iptables_available:
                                bans.restore_iptables()
                            log.info(
                                "Protected mode %s — firewall %s",
                                "enabled" if enable else "disabled",
                                "available" if bans._iptables_available else "NOT available",
                            )
                            return web.json_response({
                                "ok": True,
                                "protected": enable,
                                "iptables_available": bans._iptables_available,
                                "restart_required": True,
                            })
                        err_msg = result.get("message", "unknown error")
                        return web.json_response(
                            {"ok": False, "error": err_msg}, status=500
                        )
                    body = await resp.text()
                    return web.json_response(
                        {"ok": False, "error": f"Supervisor returned {resp.status}: {body}"},
                        status=resp.status,
                    )
        except Exception as e:
            log.warning("Failed to set protected mode: %s", e)
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def handle_restart_addon(req):
        """Restart this addon via Supervisor API (needed after changing protected mode)."""
        token = source_mgr.get_supervisor_token()
        if not token:
            return web.json_response({"ok": False, "error": "No Supervisor token"}, status=500)
        try:
            async with aiohttp_client.ClientSession() as session:
                headers = {"Authorization": f"Bearer {token}"}
                async with session.post(
                    f"{SUPERVISOR_URL}/addons/self/restart",
                    headers=headers,
                    timeout=aiohttp_client.ClientTimeout(total=30),
                ) as resp:
                    if resp.status == 200:
                        return web.json_response({"ok": True})
                    return web.json_response(
                        {"ok": False, "error": f"Supervisor returned {resp.status}"},
                        status=resp.status,
                    )
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=500)

    async def handle_debug(req):
        """Return diagnostic info about sources, scanner state, and recent events."""
        all_src = source_mgr.get_all()
        enabled = [s for s in all_src if s.get("enabled")]
        disabled_with_slug = [
            {"id": s["id"], "name": s.get("name", "?"), "type": s["type"],
             "path": s.get("path", ""), "addon_slug": s.get("addon_slug", s.get("slug", "")),
             "enabled": False}
            for s in all_src if not s.get("enabled") and (s.get("addon_slug") or s.get("slug"))
        ]
        scanner_state = {}
        if scanner:
            scanner_state = {
                "file_state": {k: v for k, v in scanner._file_state.items()},
                "addon_state": dict(scanner._addon_state),
                "unmatched_count": len(scanner.unmatched_lines),
            }
        return web.json_response({
            "version": VERSION,
            "total_sources": len(all_src),
            "enabled_sources": [
                {"id": s["id"], "name": s.get("name", "?"), "type": s["type"],
                 "path": s.get("path", ""), "addon_slug": s.get("addon_slug", s.get("slug", ""))}
                for s in enabled
            ],
            "disabled_addon_sources": disabled_with_slug[:30],
            "scanner": scanner_state,
            "whitelist": {
                "my_ip": config._state.my_ip,
                "whitelist_entries": config.whitelist,
                "whitelisted_skips": detector._whitelisted_skips,
                "last_whitelisted_ip": detector._last_whitelisted_ip,
            },
            "recent_events": list(detector._events)[:20],
            "recent_unmatched": list(scanner.unmatched_lines)[:20] if scanner else [],
        })

    # --- Reassign file source to a different addon ---
    async def handle_reassign_source(req):
        d = await req.json()
        source_id = d.get("source_id", "")
        target_addon = d.get("addon_id", "").strip()
        src = source_mgr.get_source(source_id)
        if not src:
            return web.json_response({"ok": False, "error": "source not found"}, status=404)
        if src["type"] != "file":
            return web.json_response({"ok": False, "error": "only file sources can be reassigned"}, status=400)
        if not target_addon:
            # Clear manual assignment
            src.pop("manual_addon_slug", None)
            src.pop("addon_slug", None)
            source_mgr._save()
            return web.json_response({"ok": True})
        src["addon_slug"] = target_addon
        src["manual_addon_slug"] = True
        # Special "unused" marker: disable the source so it's not scanned
        if target_addon == "__unused__":
            src["enabled"] = False
        source_mgr._save()
        log.info("Reassigned source %s → addon %s", source_id, target_addon)
        return web.json_response({"ok": True})

    # --- Source Preview (last N lines of a log) ---
    async def handle_preview_source(req):
        d = await req.json()
        sid = d.get("id", "")
        n = min(int(d.get("lines", 50)), 200)
        # If sid looks like an absolute path and is not a known source ID,
        # read the file directly (used by file-search preview).
        if sid.startswith("/") and sid not in source_mgr._sources:
            p = Path(sid)
            if not p.exists():
                return web.json_response({"lines": ["(file not found)"]})
            try:
                with open(p, errors="replace") as f:
                    all_lines = f.readlines()
                return web.json_response({"lines": [l.rstrip() for l in all_lines[-n:]]})
            except Exception as e:
                return web.json_response({"lines": [f"Error: {e}"]})
        lines = await source_mgr.preview_source(sid, n)
        return web.json_response({"lines": lines})

    # --- Unmatched auth lines (for debugging patterns) ---
    async def handle_unmatched(req):
        if scanner:
            return web.json_response(list(scanner.unmatched_lines))
        return web.json_response([])

    # --- File search across all Guardian-accessible directories ---
    _SEARCH_ROOTS = ["/config", "/share", "/addon_configs", "/media", "/data"]

    async def handle_find_file(req):
        pattern = req.rel_url.query.get("pattern", "").strip()
        if not pattern or len(pattern) < 2:
            return web.json_response({"error": "pattern too short"}, status=400)
        results = []
        # If user entered an absolute path, look it up directly
        if pattern.startswith("/"):
            p = Path(pattern)
            if p.is_file():
                try:
                    st = p.stat()
                    results.append({
                        "path": pattern,
                        "size": st.st_size,
                        "mtime": datetime.fromtimestamp(st.st_mtime, tz=timezone.utc).isoformat(),
                    })
                except OSError:
                    results.append({"path": pattern, "size": None, "mtime": None})
            return web.json_response({"results": results})
        # Glob pattern — only allow safe filename characters
        safe = re.compile(r'^[\w\-.*?]+$')
        if not safe.match(pattern):
            return web.json_response({"error": "invalid pattern"}, status=400)
        pat_re = re.compile(fnmatch_translate(pattern), re.IGNORECASE)
        for root in _SEARCH_ROOTS:
            if not Path(root).exists():
                continue
            for dirpath, _dirs, files in os.walk(root, followlinks=False):
                for fname in files:
                    if pat_re.match(fname):
                        full = os.path.join(dirpath, fname)
                        try:
                            st = os.stat(full)
                            results.append({
                                "path": full,
                                "size": st.st_size,
                                "mtime": datetime.fromtimestamp(st.st_mtime,
                                                                tz=timezone.utc).isoformat(),
                            })
                        except OSError:
                            results.append({"path": full, "size": None, "mtime": None})
                if len(results) >= 200:
                    break
        results.sort(key=lambda x: x.get("mtime") or "", reverse=True)
        return web.json_response(results)

    # --- Ban evidence ---
    async def handle_ban_evidence(req):
        ip = req.match_info["ip"]
        return web.json_response(bans.get_evidence(ip))

    # --- Rules management ---
    async def handle_get_rules(req):
        if rules_mgr is None:
            return web.json_response([])
        return web.json_response(rules_mgr.get_all())

    async def handle_post_rule(req):
        if rules_mgr is None:
            return web.json_response({"ok": False, "error": "rules_mgr not available"}, status=500)
        try:
            data = await req.json()
            ok, err = rules_mgr.upsert(data)
            if ok:
                return web.json_response({"ok": True})
            return web.json_response({"ok": False, "error": err}, status=400)
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def handle_put_rule(req):
        if rules_mgr is None:
            return web.json_response({"ok": False, "error": "rules_mgr not available"}, status=500)
        try:
            data = await req.json()
            data["id"] = req.match_info["id"]
            ok, err = rules_mgr.upsert(data)
            if ok:
                return web.json_response({"ok": True})
            return web.json_response({"ok": False, "error": err}, status=400)
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def handle_delete_rule(req):
        if rules_mgr is None:
            return web.json_response({"ok": False, "error": "rules_mgr not available"}, status=500)
        rule_id = req.match_info["id"]
        ok = rules_mgr.delete(rule_id)
        if ok:
            return web.json_response({"ok": True})
        return web.json_response({"ok": False, "error": "rule not found"}, status=404)

    async def handle_reset_rules(req):
        if rules_mgr is None:
            return web.json_response({"ok": False, "error": "rules_mgr not available"}, status=500)
        rules_mgr.reset()
        return web.json_response({"ok": True, "rules": rules_mgr.get_all()})

    async def handle_test_rule(req):
        """Test a regex pattern against a sample log line."""
        try:
            data = await req.json()
            pattern_str = data.get("pattern", "")
            flags_str = data.get("flags", "")
            line = data.get("line", "")
            flags = 0
            for f in flags_str.split("|"):
                f = f.strip().upper()
                if f == "IGNORECASE":
                    flags |= re.IGNORECASE
                elif f == "MULTILINE":
                    flags |= re.MULTILINE
            compiled = re.compile(pattern_str, flags)
            m = compiled.search(line)
            if m:
                return web.json_response({"match": True, "groups": list(m.groups())})
            return web.json_response({"match": False, "groups": []})
        except re.error as e:
            return web.json_response({"ok": False, "error": f"Invalid regex: {e}"}, status=400)
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def handle_ip_events(req):
        """Return recent matched log lines for a specific IP."""
        ip = req.match_info["ip"]
        events = detector.get_ip_events(ip)
        return web.json_response(events[:20])

    async def handle_generate_regex(req):
        """Generate a regex pattern from a sample log line and keywords."""
        try:
            data = await req.json()
            sample = data.get("sample", "")
            keywords = data.get("keywords", "").strip()
            if not sample or not keywords:
                return web.json_response(
                    {"ok": False, "error": "sample and keywords required"}, status=400
                )
            # Split keywords by whitespace or comma
            kw_list = [k.strip() for k in re.split(r"[\s,]+", keywords) if k.strip()]
            # Build regex: escape each keyword, join with .*?, capture IP
            parts = []
            for kw in kw_list:
                parts.append(re.escape(kw))
            keyword_pattern = r".*?".join(parts)
            # Determine if the IP likely appears before or after the keywords in the sample
            ip_re = re.compile(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}")
            ip_match = ip_re.search(sample)
            kw_first_pos = len(sample)
            for kw in kw_list:
                pos = sample.lower().find(kw.lower())
                if pos >= 0 and pos < kw_first_pos:
                    kw_first_pos = pos
            ip_capture = r"(\d{1,3}(?:\.\d{1,3}){3})"
            if ip_match and ip_match.start() < kw_first_pos:
                # IP comes before keywords
                pattern = ip_capture + r".*?" + keyword_pattern
            else:
                # IP comes after keywords (or inside [Client IP])
                # Check for [Client IP] pattern
                if "[Client" in sample or "[client" in sample:
                    pattern = keyword_pattern + r".*?\[Client\s+" + ip_capture + r"\]"
                else:
                    pattern = keyword_pattern + r".*?" + ip_capture
            # Verify it matches the sample
            try:
                m = re.search(pattern, sample, re.IGNORECASE)
                matched = bool(m)
                captured_ip = m.group(1) if m else None
            except re.error:
                matched = False
                captured_ip = None
            return web.json_response({
                "ok": True,
                "pattern": pattern,
                "flags": "IGNORECASE",
                "matched": matched,
                "captured_ip": captured_ip,
            })
        except Exception as e:
            return web.json_response({"ok": False, "error": str(e)}, status=400)

    async def handle_delete_source(req):
        """Remove a source from tracking; optionally delete the file.
        Accepts POST body {id, delete_file} to avoid URL-encoding issues with IDs
        that contain colons/slashes (e.g. file:/path/to/file)."""
        try:
            d = await req.json()
        except Exception:
            return web.json_response({"ok": False, "error": "invalid JSON"}, status=400)
        source_id = d.get("id", "")
        delete_file = bool(d.get("delete_file", False))
        if not source_id:
            return web.json_response({"ok": False, "error": "id required"}, status=400)
        ok = source_mgr.remove_source(source_id, delete_file=delete_file)
        if ok:
            return web.json_response({"ok": True})
        return web.json_response({"ok": False, "error": "source not found"}, status=404)


    app.router.add_get("/", handle_index)
    app.router.add_get("/api/stats", handle_stats)
    app.router.add_get("/api/events", handle_events)
    app.router.add_get("/api/bans", handle_get_bans)
    app.router.add_post("/api/bans", handle_post_ban)
    app.router.add_delete("/api/bans/{ip}", handle_delete_ban)
    app.router.add_get("/api/whitelist", handle_get_whitelist)
    app.router.add_post("/api/whitelist", handle_post_whitelist)
    app.router.add_delete("/api/whitelist/{entry}", handle_delete_whitelist)
    app.router.add_post("/api/whitelist/delete", handle_delete_whitelist)
    app.router.add_get("/api/my-ip", handle_get_my_ip)
    app.router.add_post("/api/my-ip", handle_post_my_ip)
    app.router.add_delete("/api/my-ip", handle_delete_my_ip)
    app.router.add_get("/api/sources", handle_get_sources)
    app.router.add_post("/api/sources/toggle", handle_toggle_source)
    app.router.add_post("/api/sources/discover", handle_discover_sources)
    app.router.add_post("/api/sources/add", handle_add_custom_source)
    app.router.add_post("/api/sources/preview", handle_preview_source)
    app.router.add_post("/api/sources/reassign", handle_reassign_source)
    app.router.add_post("/api/sources/delete", handle_delete_source)
    app.router.add_get("/api/addons", handle_get_addons)
    app.router.add_post("/api/addons/toggle", handle_toggle_addon)
    app.router.add_post("/api/addons/preview", handle_preview_addon)
    app.router.add_post("/api/addons/health", handle_health_check)
    app.router.add_get("/api/unmatched", handle_unmatched)
    app.router.add_get("/api/find", handle_find_file)
    app.router.add_get("/api/alerts", handle_get_alerts)
    app.router.add_get("/api/config", handle_get_config)
    app.router.add_post("/api/config", handle_post_config)
    app.router.add_get("/api/health", handle_health)
    app.router.add_post("/api/crowdsec/test", handle_crowdsec_test)
    app.router.add_get("/api/system", handle_get_system)
    app.router.add_post("/api/system/protection", handle_set_protection)
    app.router.add_post("/api/system/restart", handle_restart_addon)
    app.router.add_get("/api/debug", handle_debug)
    app.router.add_get("/api/bans/{ip}/evidence", handle_ban_evidence)
    app.router.add_get("/api/rules", handle_get_rules)
    app.router.add_post("/api/rules", handle_post_rule)
    app.router.add_put("/api/rules/{id}", handle_put_rule)
    app.router.add_delete("/api/rules/{id}", handle_delete_rule)
    app.router.add_post("/api/rules/reset", handle_reset_rules)
    app.router.add_post("/api/rules/test", handle_test_rule)
    app.router.add_get("/api/events/{ip}", handle_ip_events)
    app.router.add_post("/api/rules/generate", handle_generate_regex)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main():
    rules_mgr = RulesManager()
    state = PersistentState()
    config = Config(state)
    crowdsec_mgr = CrowdSecManager(state)
    bans = BanManager(config, crowdsec=crowdsec_mgr)
    bans.restore_iptables()
    alert_tracker = AlertTracker(config)
    detector = Detector(config, bans, alert_tracker)
    source_mgr = SourceManager(config)
    scanner = LogScanner(source_mgr, detector, config)

    log.info("HA Guardian %s starting on port %d", VERSION, PORT)

    app = build_app(config, bans, detector, source_mgr, alert_tracker, scanner,
                    rules_mgr=rules_mgr, crowdsec_mgr=crowdsec_mgr)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    # Optional direct-access port for debugging (accessible without ingress)
    # Defaults to PORT+1 so it stays consistent when ingress_port is changed.
    debug_port = int(os.environ.get("GUARDIAN_DEBUG_PORT", PORT + 1))
    try:
        site2 = web.TCPSite(runner, "0.0.0.0", debug_port)
        await site2.start()
        log.info("Web server ready on ports %d (ingress) and %d (direct)", PORT, debug_port)
    except Exception:
        log.info("Web server ready on port %d (ingress only)", PORT)

    await asyncio.gather(
        scanner.run(),
        scanner.rediscover_loop(),
        bans.expire_loop(),
        detector.cleanup_windows_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())
