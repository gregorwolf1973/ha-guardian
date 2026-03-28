#!/usr/bin/env python3
"""HA Guardian - Brute-Force Protection for Home Assistant"""

import asyncio
import json
import logging
import os
import re
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
from pathlib import Path
from typing import Optional

from aiohttp import web
import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
OPTIONS_FILE = "/data/options.json"
BANS_FILE = "/config/ip_bans.yaml"
LOG_FILE_DEFAULT = "/config/home-assistant.log"
VERSION = "1.0.0"
PORT = 8099

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("guardian")

# Matches both log formats:
#   ... from 1.2.3.4.
#   ... from hostname (1.2.3.4).
LOG_RE = re.compile(
    r"\[homeassistant\.components\.http\.ban\]"
    r".*?(?:from\s+\S+\s+\(([0-9a-fA-F:.]+)\)|from\s+([0-9a-fA-F:.]+))"
)
URL_RE = re.compile(r"URL:\s*'([^']*)'")


# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------
class Config:
    def __init__(self):
        self.max_attempts: int = 5
        self.window_minutes: int = 5
        self.ban_duration_minutes: int = 240
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
                }
            log.info("Loaded %d existing ban(s) from ip_bans.yaml", len(self._bans))
        except Exception as e:
            log.error("Error loading ip_bans.yaml: %s", e)

    async def _flush(self):
        """Atomically write bans to ip_bans.yaml."""
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

    async def ban(
        self,
        ip: str,
        reason: str = "auto",
        manual: bool = False,
        attempts: int = 0,
        duration_minutes: Optional[int] = None,
    ) -> bool:
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
            }
            await self._flush()
        log.info("Banned %s for %d min. Reason: %s", ip, dur, reason)
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
        """Background task: remove expired bans every 60 seconds."""
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
# Attack Detector
# ---------------------------------------------------------------------------
class Detector:
    def __init__(self, config: Config, bans: BanManager):
        self.config = config
        self.bans = bans
        self._windows: dict = defaultdict(deque)
        self._events: deque = deque(maxlen=200)
        self._total_attempts = 0
        self._total_bans = 0
        self._started = datetime.now(timezone.utc)

    async def record(self, ip: str, url: str = ""):
        if self.config.is_whitelisted(ip):
            return
        now = datetime.now(timezone.utc)
        cutoff = now - timedelta(minutes=self.config.window_minutes)
        dq = self._windows[ip]
        while dq and dq[0] < cutoff:
            dq.popleft()
        dq.append(now)
        self._total_attempts += 1
        banned_now = False

        if len(dq) >= self.config.max_attempts and not self.bans.is_banned(ip):
            ok = await self.bans.ban(ip, reason="auto", attempts=len(dq))
            if ok:
                self._total_bans += 1
                banned_now = True
                dq.clear()

        self._events.appendleft({
            "time": now.isoformat(),
            "ip": ip,
            "url": url,
            "count": len(dq) if not banned_now else self.config.max_attempts,
            "banned": banned_now,
        })
        log.warning(
            "Failed login from %s (%d/%d)%s",
            ip,
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
# Log Tailer
# ---------------------------------------------------------------------------
class LogTailer:
    def __init__(self, detector: Detector):
        self.detector = detector

    async def run(self, path: str):
        log.info("Waiting for log file: %s", path)
        while not Path(path).exists():
            await asyncio.sleep(5)

        log.info("Tailing: %s", path)
        last_inode: Optional[int] = None
        last_pos = 0

        while True:
            try:
                stat = os.stat(path)
                inode, size = stat.st_ino, stat.st_size

                if last_inode is None:
                    last_pos = size  # start from EOF on first open
                    last_inode = inode
                elif inode != last_inode or size < last_pos:
                    last_pos = 0
                    last_inode = inode
                    log.info("Log file rotated — rewinding")

                if last_pos < size:
                    with open(path) as f:
                        f.seek(last_pos)
                        for line in f:
                            await self._process(line)
                        last_pos = f.tell()
            except FileNotFoundError:
                last_inode = None
                last_pos = 0
            except Exception as e:
                log.error("Log tail error: %s", e)

            await asyncio.sleep(0.5)

    async def _process(self, line: str):
        if "homeassistant.components.http.ban" not in line:
            return
        m = LOG_RE.search(line)
        if not m:
            return
        ip = m.group(1) or m.group(2)
        if not ip:
            return
        url = ""
        um = URL_RE.search(line)
        if um:
            url = um.group(1)
        await self.detector.record(ip, url)


# ---------------------------------------------------------------------------
# Web Server
# ---------------------------------------------------------------------------
_INDEX_HTML: Optional[str] = None


def _index_html() -> str:
    global _INDEX_HTML
    if _INDEX_HTML is None:
        _INDEX_HTML = (Path(__file__).parent / "www" / "index.html").read_text()
    return _INDEX_HTML


def build_app(config: Config, bans: BanManager, detector: Detector) -> web.Application:
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
            ip_address(ip)  # validate
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
    detector = Detector(config, bans)
    tailer = LogTailer(detector)

    log.info("HA Guardian %s starting on port %d", VERSION, PORT)

    app = build_app(config, bans, detector)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "0.0.0.0", PORT)
    await site.start()
    log.info("Web server ready")

    await asyncio.gather(
        tailer.run(config.log_file),
        bans.expire_loop(),
    )


if __name__ == "__main__":
    asyncio.run(main())
