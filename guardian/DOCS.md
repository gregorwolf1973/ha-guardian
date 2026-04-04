# HA Guardian – Documentation

Brute-force protection for Home Assistant: monitors logs of all installed addons, detects failed login attempts and automatically bans attacking IPs via `ip_bans.yaml` (Application Layer) and optionally via **CrowdSec LAPI** (Network Layer).

---

## Quick Start

1. Start the addon and open via **Open Web UI**
2. In the **Addons** tab, enable desired log sources via toggle
3. In the **Whitelist** tab, protect your own IP (auto-whitelist is offered on first open)
4. Done – Guardian monitors the enabled sources

---

## Configuration

| Option | Default | Description |
|---|---|---|
| `max_attempts` | `5` | Failed attempts before ban |
| `window_minutes` | `5` | Detection time window (minutes) |
| `ban_duration_minutes` | `240` | Ban duration in minutes (`0` = permanent) |
| `alert_window_hours` | `24` | Time range for dashboard display (hours) |
| `log_file` | `/config/home-assistant.log` | Path to HA Core log file |

> All settings can also be changed in the **Settings tab** of the Web UI.

---

## Compatibility with HA's Built-in Ban Mechanism

Guardian and HA's `ip_ban_enabled` work independently and can be active simultaneously. HA only protects its own web interface, Guardian additionally protects all monitored addons. No conflict, no action needed.

---

## Addons Tab – Which Log Sources to Enable?

### ⚡ Nginx Proxy Manager – Most Important Source

Since all external traffic passes through HA's internal proxy (`172.30.32.1`), the Docker log of most addons does **not** contain the real attacker IP. Nginx Proxy Manager (NPM) sits in front of this proxy and logs the real client IP:

```
[Client 91.42.192.232]  ← real IP, only visible in NPM
```

**Enable NPM logging:** NPM Web UI → Settings → Default Site → Access Log ✓

### Which Source for Which Service?

| Service | Recommended Source |
|---|---|
| Home Assistant Core | File `/config/home-assistant.log` (active by default) |
| Nginx Proxy Manager | `Docker: Nginx Proxy Manager` ← most important source |
| 2FAuth | NPM (external access) + `Docker: 2FAuth` |
| Vaultwarden | `Docker: Vaultwarden` + NPM |
| DokuWiki | `Docker: DokuWiki` + optionally `auth.log` file |
| Nextcloud | `Docker: Nextcloud` |
| Webtrees | NPM (Webtrees returns HTTP 200 on failed login) |

> **Rule of thumb:** If an addon only logs `172.30.32.1` as client IP → enable NPM.

### Log File Search

The Addons tab has a **file search**: enter a filename (e.g. `auth.log`) → finds all matching logs across all addon directories.

---

## Bans Take Effect in Real Time

Home Assistant monitors `ip_bans.yaml` for changes. New bans from Guardian become active **immediately** without restart.

---

## Ban Targets

Under **Ban Targets** in the Settings tab you can choose where bans are written:

- **ip_bans.yaml** (default: on) – HA's native ban mechanism
- **CrowdSec** (default: on) – sends bans to CrowdSec LAPI for network-layer blocking

Both targets can be toggled independently.

---

## CrowdSec LAPI Integration

Guardian can send bans directly to the CrowdSec Local API. Prerequisites:

1. CrowdSec addon installed and running
2. Create machine account: `cscli machines add ha-guardian --password <password>`
3. In Guardian Settings: enter LAPI URL, Machine ID and password (plaintext)
4. **Test Connection** → on success the integration is active

On every ban/unban a decision is automatically created or removed in CrowdSec. Ban duration is passed 1:1 (0 = permanent → 10 years in CrowdSec).

---

## Health Check

The **Health Check** button in the Addons tab checks all enabled sources for freshness:
- **ok** (green) – entries within the last 7 days
- **stale** (red) – no recent entries
- **empty** (grey) – source empty or unreadable

---

## Unused Sources

Discovered but unneeded log files can be marked as unused via **Reassign → Unused**. They appear greyed out and are not monitored.

---

## Rules Tab

All detection rules can be managed here:

- **Toggle** – enable/disable rule
- **Edit** – modify pattern and description (with live tester)
- **Copy** – use as basis for new rule
- **Delete** – remove rule
- **Factory Reset** – reset all rules to defaults

### Creating Custom Rules

Regex pattern with capture group for the IP address:
```
Login failed.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```

---

## Whitelist Tab

- **Auto-whitelist**: your public IP is automatically detected and added when opening the UI. Updated automatically on IP change.
- **Manual**: single IPs (`1.2.3.4`) or CIDR ranges (`192.168.178.0/24`)
- Internal addresses (`127.0.0.1`, `172.30.32.0/24`, `192.168.0.0/16`) are protected by default

---

## FAQ

**Ban appears in the list but IP isn't blocked?**
→ HA monitors `ip_bans.yaml` in real time, no restart needed. Check that the IP is actually in `ip_bans.yaml` in the config directory.

**No alerts even though failed logins are happening?**
→ Check the Addons tab to see if the correct source is enabled. For external access: enable NPM.

**How do I find the log file of an addon?**
→ Addons tab → Log File Search → enter filename.

**How does the CrowdSec integration work?**
→ Guardian sends bans directly to the CrowdSec LAPI as a machine watcher. See CrowdSec LAPI Integration above for setup.

**Can I run Guardian alongside CrowdSec?**
→ Yes! Guardian registers as a machine and sends bans to the LAPI. CrowdSec's own scenarios and Guardian bans complement each other.

---

Full documentation and source code: [github.com/gregorwolf1973/ha-guardian](https://github.com/gregorwolf1973/ha-guardian)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/gregorwolf1973)
