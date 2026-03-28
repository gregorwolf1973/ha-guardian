#!/usr/bin/env python3
"""HA Guardian - Brute-Force Protection for Home Assistant (Multi-Source)"""

import asyncio
import json
import logging
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from glob import glob
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
BANS_FILE = "/config/ip_bans.yaml"
SOURCES_FILE = "/data/guardian_sources.json"
LOG_FILE_DEFAULT = "/config/home-assistant.log"
SUPERVISOR_URL = "http://supervisor"
VERSION = "1.1.0"
PORT = 8099

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("guardian")

# ---------------------------------------------------------------------------
# Detection patterns — each returns an IP from group(1) or group(2)
# ---------------------------------------------------------------------------
PATTERNS = {
    "ha_ban": re.compile(
        r"\[homeassistant\.components\.http\.ban\]"
        r".*?(?:from\s+\S+\s+\(([0-9a-fA-F:.]+)\)|from\s+([0-9a-fA-F:.]+))"
    ),
    "nginx_auth": re.compile(
        r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}).*\"(?:GET|POST|PUT|DELETE|HEAD|OPTIONS)\s.*\"\s+(?:401|403)\s"
    ),
    "generic_fail": re.compile(
        r"(?:authentication fail|login fail|invalid password|unauthorized|"
        r"access denied|bad password|failed login|invalid credential)"
        r".*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
        re.IGNORECASE,
    ),
    "ssh_fail": re.compile(
        r"[Ff]ailed password for.*?from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    ),
}

URL_RE = re.compile(r"URL:\s*'([^']*)'")


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


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
class Config:
    def __init__(self):
        self.max_attempts: int = 5
        self.window_minutes: int = 5
        self.ban_duration_minutes: int = 240
        self.alert_window_hours: int = 24
        self.log_file: str = LOG_FILE_DEFAULT
        self.whitelist: list = []
        self.trusted_domains: list = []
        self._load()

    def _load(self):
        try:
            with open(OPTIONS_FILE) as f:
                d = json.load(f)
            self.max_attempts = max(1, int(d.get("max_attempts", 5)))
            self.window_minutes = max(1, int(d.get("window_minutes", 5)))
            self.ban_duration_minutes = max(0, int(d.get("ban_duration_minutes", 240)))
            self.alert_window_hours = max(1, int(d.get("alert_window_hours", 24)))
            self.log_file = d.get("log_file", LOG_FILE_DEFAULT)
            self.whitelist = list(d.get("whitelist", []))
            self.trusted_domains = list(d.get("trusted_domains", []))
        except Exception as e:
            log.warning("Could not load options.json: %s — using defaults", e)

    def save(self):
        try:
            with open(OPTIONS_FILE, "w") as f:
                json.dump(self.to_dict(), f, indent=2)
        except Exception as e:
            log.error("Could not save options: %s", e)

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
class SourceManager:
    def __init__(self, config: Config):
        self.config = config
        self._sources: dict = {}  # id -> source dict
        self._supervisor_token = os.environ.get("SUPERVISOR_TOKEN", "")
        self._load()

    def _default_sources(self) -> list:
        """Create default file source for HA core log."""
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
            with open(SOURCES_FILE, "w") as f:
                json.dump({"sources": list(self._sources.values())}, f, indent=2)
        except Exception as e:
            log.error("Could not save sources: %s", e)

    async def discover(self):
        """Discover log files and addon sources."""
        discovered = 0

        # 1) Scan /config for log files
        for path in sorted(glob("/config/*.log")) + sorted(glob("/config/logs/*.log")):
            sid = "file:" + path
            if sid not in self._sources:
                name = Path(path).stem.replace("-", " ").replace("_", " ").title()
                self._sources[sid] = {
                    "id": sid,
                    "name": name,
                    "type": "file",
                    "path": path,
                    "enabled": path == self.config.log_file,
                }
                discovered += 1

        # 2) Discover HA addons via Supervisor API
        if self._supervisor_token:
            try:
                async with aiohttp_client.ClientSession() as session:
                    headers = {
                        "Authorization": f"Bearer {self._supervisor_token}",
                        "Content-Type": "application/json",
                    }
                    async with session.get(
                        f"{SUPERVISOR_URL}/addons", headers=headers, timeout=aiohttp_client.ClientTimeout(total=10)
                    ) as resp:
                        if resp.status == 200:
                            data = await resp.json()
                            addons = data.get("data", {}).get("addons", [])
                            for addon in addons:
                                slug = addon.get("slug", "")
                                state = addon.get("state", "")
                                name = addon.get("name", slug)
                                # Skip ourselves
                                if "ha_guardian" in slug:
                                    continue
                                sid = "addon:" + slug
                                if sid not in self._sources:
                                    self._sources[sid] = {
                                        "id": sid,
                                        "name": f"Addon: {name}",
                                        "type": "addon",
                                        "slug": slug,
                                        "state": state,
                                        "enabled": False,
                                    }
                                    discovered += 1
                                else:
                                    self._sources[sid]["state"] = state
                                    self._sources[sid]["name"] = f"Addon: {name}"
            except Exception as e:
                log.warning("Could not discover addons: %s", e)

        if discovered:
            log.info("Discovered %d new log source(s)", discovered)
            self._save()

    def get_all(self) -> list:
        return list(self._sources.values())

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
        # source_id -> deque of {"time": datetime, "ip": str}
        self._records: dict = defaultdict(lambda: deque(maxlen=5000))

    def record(self, source_id: str, source_name: str, ip: str):
        self._records[source_id].append({
            "time": datetime.now(timezone.utc),
            "ip": ip,
            "source_name": source_name,
        })

    def get_alerts(self) -> list:
        """Return per-source alert summaries for the configured window."""
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
# Detector — processes parsed log lines
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

    async def record(self, ip: str, source_id: str, source_name: str, url: str = "", pattern: str = ""):
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
            ok = await self.bans.ban(
                ip, reason="auto", attempts=len(dq), source=source_id
            )
            if ok:
                self._total_bans += 1
                banned_now = True
                dq.clear()

        self._events.appendleft({
            "time": now.isoformat(),
            "ip": ip,
            "source_id": source_id,
            "source_name": source_name,
            "url": url,
            "pattern": pattern,
            "count": len(dq) if not banned_now else self.config.max_attempts,
            "banned": banned_now,
        })
        log.warning(
            "Failed login from %s via %s (%d/%d)%s",
            ip, source_name, len(dq) if not banned_now else self.config.max_attempts,
            self.config.max_attempts, " — BANNED" if banned_now else "",
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
# Log Scanner — tails files + polls addon logs
# ---------------------------------------------------------------------------
class LogScanner:
    def __init__(self, source_mgr: SourceManager, detector: Detector):
        self.source_mgr = source_mgr
        self.detector = detector
        self._file_state: dict = {}   # path -> {"inode": int, "pos": int}
        self._addon_state: dict = {}  # slug -> last_length

    async def run(self):
        # Initial discovery
        await self.source_mgr.discover()

        log.info("Log scanner started — %d source(s) enabled",
                 len(self.source_mgr.get_enabled()))

        while True:
            # Scan enabled file sources
            for src in self.source_mgr.get_enabled("file"):
                await self._scan_file(src)

            # Poll enabled addon sources
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
                # First time — seek to end
                self._file_state[path] = {"inode": inode, "pos": size}
                return

            if inode != state["inode"] or size < state["pos"]:
                # File rotated
                state["inode"] = inode
                state["pos"] = 0
                log.info("Log rotated: %s", path)

            if state["pos"] >= size:
                return

            with open(path) as f:
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
                # First poll — skip existing logs
                self._addon_state[slug] = len(text)
                return

            if len(text) < last_len:
                # Logs were cleared/rotated
                last_len = 0

            if len(text) > last_len:
                new_content = text[last_len:]
                for line in new_content.splitlines():
                    await self._process_line(line, src)
            self._addon_state[slug] = len(text)
        except Exception as e:
            log.debug("Error polling addon %s: %s", slug, e)

    async def _process_line(self, line: str, src: dict):
        result = extract_ip(line)
        if not result:
            return
        ip, pattern_name = result
        url = ""
        um = URL_RE.search(line)
        if um:
            url = um.group(1)
        await self.detector.record(
            ip=ip,
            source_id=src["id"],
            source_name=src.get("name", src["id"]),
            url=url,
            pattern=pattern_name,
        )

    async def rediscover_loop(self):
        """Re-discover sources every 5 minutes."""
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


def build_app(config, bans, detector, source_mgr, alerts) -> web.Application:
    app = web.Application()

    # --- HTML ---
    async def handle_index(req):
        base = req.headers.get("X-Ingress-Path", "").rstrip("/") + "/"
        html = _index_html().replace("__BASE_HREF__", base)
        return web.Response(text=html, content_type="text/html")

    # --- Stats / Events ---
    async def handle_stats(req):
        return web.json_response(detector.stats())

    async def handle_events(req):
        return web.json_response(detector.events())

    # --- Bans ---
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

    # --- Whitelist ---
    async def handle_get_whitelist(req):
        return web.json_response(config.whitelist)

    async def handle_post_whitelist(req):
        d = await req.json()
        entry = d.get("entry", "").strip()
        if not entry:
            return web.json_response({"ok": False, "error": "empty entry"}, status=400)
        if entry not in config.whitelist:
            config.whitelist.append(entry)
            config.save()
        return web.json_response({"ok": True})

    async def handle_delete_whitelist(req):
        entry = req.match_info["entry"]
        if entry in config.whitelist:
            config.whitelist.remove(entry)
            config.save()
        return web.json_response({"ok": True})

    # --- Log Sources ---
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

    # --- Alerts ---
    async def handle_get_alerts(req):
        return web.json_response(alerts.get_alerts())

    # --- Config ---
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
    app.router.add_get("/api/alerts", handle_get_alerts)
    app.router.add_get("/api/config", handle_get_config)
    app.router.add_post("/api/config", handle_post_config)
    app.router.add_get("/api/health", handle_health)

    return app


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
async def main():
    config = Config()
    bans = BanManager(config)
    alert_tracker = AlertTracker(config)
    detector = Detector(config, bans, alert_tracker)
    source_mgr = SourceManager(config)
    scanner = LogScanner(source_mgr, detector)

    log.info("HA Guardian %s starting on port %d", VERSION, PORT)

    app = build_app(config, bans, detector, source_mgr, alert_tracker)
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
