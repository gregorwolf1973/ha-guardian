🌐 **English** · [Deutsch](README.de.md)

# HA Guardian

<p align="center">
  <img src="guardian/logo.png" alt="HA Guardian Logo" width="400">
</p>

<p align="center">
  <a href="https://my.home-assistant.io/redirect/supervisor_add_addon_repository/?repository_url=https%3A%2F%2Fgithub.com%2Fgregorwolf1973%2Fha-guardian">
    <img src="https://my.home-assistant.io/badges/supervisor_add_addon_repository.svg" alt="Add Repository to Home Assistant">
  </a>
</p>

<p align="center">
  <a href="https://buymeacoffee.com/gregorwolf1973">
    <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee">
  </a>
</p>

**Brute-force protection for Home Assistant** – monitors logs of all installed addons, detects failed login attempts and automatically bans attacking IPs via `ip_bans.yaml` (Application Layer) and optionally via **CrowdSec LAPI** (Network Layer).

---

## Table of Contents

1. [What does HA Guardian do?](#what-does-ha-guardian-do)
2. [Features](#features)
3. [Installation](#installation)
4. [Quick Start](#quick-start)
5. [Configuration](#configuration)
6. [Ban Targets](#ban-targets)
7. [CrowdSec Integration](#crowdsec-integration)
8. [Addons Tab – Which Log Sources to Enable?](#addons-tab--which-log-sources-to-enable)
9. [Rules Tab](#rules-tab)
10. [Whitelist Tab](#whitelist-tab)
11. [Dashboard](#dashboard)
12. [Blocked IPs](#blocked-ips)
13. [Architecture Notes](#architecture-notes)
14. [FAQ](#faq)

---

## What does HA Guardian do?

HA Guardian continuously reads the log files and Docker logs of your Home Assistant addons. When it detects too many failed login attempts from an IP address within a configurable time window, the IP is automatically banned – either in `ip_bans.yaml` (HA-native), via **CrowdSec LAPI** (Network Layer), or both.

```
Attacker → Nginx Proxy Manager → Addon (2FAuth, Vaultwarden…)
                ↓                        ↓
          NPM log (real IP)       Docker log (proxy IP 172.30.32.1)
                ↓
           HA Guardian detects attack
                ↓
         ┌─────────────────────────────────┐
         │  ip_bans.yaml (Application Layer) │
         │  CrowdSec LAPI (Network Layer)    │
         └─────────────────────────────────┘
```

---

## Features

- 🔍 **Multi-addon monitoring** – Docker logs and files of all installed addons
- 🛡️ **Automatic banning** – writes directly to HA's native `ip_bans.yaml`
- 🌐 **CrowdSec LAPI integration** – optional network-layer blocking via CrowdSec
- 🎯 **Ban Targets** – ip_bans.yaml and CrowdSec independently toggleable
- ⏱️ **Time window filtering** – only log entries within the configured window count
- 🌐 **Nginx Proxy Manager integration** – detects real client IPs behind the HA proxy
- 📋 **15+ detection rules** – preconfigured for common services
- ✏️ **Rules editor** – edit, add, disable or reset rules to factory defaults
- 🔒 **Whitelist** – permanently protect IPs and CIDR ranges, auto-whitelist your own IP
- 🩺 **Health Check** – verifies log sources are active (entries within last 7 days)
- 🗑️ **Unused Sources** – mark irrelevant log files as "Unused"
- 📊 **Dashboard** – all events at a glance with full log line and details button
- 💾 **Persistent** – settings, rules and whitelist survive restarts

---

## Installation

1. In Home Assistant go to **Settings → Add-ons → Add-on Store**
2. **⋮ Menu → Repositories**
3. Add URL: `https://github.com/gregorwolf1973/ha-guardian`
4. Search for **HA Guardian** and install
5. Start the addon and open via the **Ingress button** (Open Web UI)

---

## Quick Start

1. Install and start the addon
2. Open the Web UI
3. In the **Addons** tab, enable desired log sources via toggle
4. In the **Whitelist** tab, whitelist your own IP (auto-whitelist is offered on first open)
5. Done – Guardian now monitors the enabled sources

---

## Configuration

Settings are configured in the **Settings tab** of the Web UI and stored persistently.
Values on the HA addon configuration page only serve as initial defaults.

| Setting | Default | Description |
|---|---|---|
| **Max. Attempts** | `5` | Failed logins before the IP gets banned |
| **Time Window (min)** | `5` | Rolling detection window in minutes |
| **Ban Duration (min)** | `240` | Ban duration (`0` = permanent) |
| **Alert Window (hrs)** | `24` | How far back events are shown on the dashboard |
| **Log File** | `/config/home-assistant.log` | Path to the HA Core log file |

> **Note:** HA's built-in ban mechanism (`ip_ban_enabled`) and Guardian work independently and can run simultaneously. HA only protects its own web interface, Guardian protects all monitored addons.

---

## Ban Targets

Under **Ban Targets** in the Settings tab you can choose where bans are written:

| Target | Default | Description |
|---|---|---|
| **ip_bans.yaml** | ✅ On | Writes bans to HA's native `ip_bans.yaml` (Application Layer) |
| **CrowdSec** | ✅ On | Sends bans to the CrowdSec LAPI (Network Layer) |

Both targets can be toggled independently. For example, you can use only CrowdSec without writing to `ip_bans.yaml`.

---

## CrowdSec Integration

Guardian can send bans directly to the [CrowdSec Local API](https://docs.crowdsec.net/docs/local_api/intro). CrowdSec can then enforce these bans at the network level (e.g. via a firewall bouncer).

### Prerequisites

1. **CrowdSec addon** installed and running in Home Assistant
2. **Machine account** for Guardian (one-time setup in CrowdSec terminal):
   ```bash
   cscli machines add ha-guardian --password <your_password>
   ```

### Setup in Guardian

1. Open the **Settings tab**
2. Under **CrowdSec LAPI** fill in:
   - **LAPI URL**: e.g. `http://a0d7b816-crowdsec:8080` (internal Docker hostname of the CrowdSec addon)
   - **Machine ID**: `ha-guardian` (as specified in `cscli machines add`)
   - **Password**: the chosen password (plaintext, **not** the SHA256 hash)
3. Click **Test Connection** → a green toast appears on success
4. Under **Ban Targets** enable the **CrowdSec** toggle

### How it works

- On every automatic or manual ban, Guardian sends an alert to `/v1/alerts` with an embedded ban decision
- On every unban, the decision is removed via `DELETE /v1/decisions?ip=X.X.X.X`
- Ban duration is passed 1:1 to CrowdSec (`0` = permanent → 10 years in CrowdSec)
- Guardian authenticates as a machine watcher using JWT tokens with automatic renewal

### Verify bans in CrowdSec

```bash
cscli decisions list
```

---

## Addons Tab – Which Log Sources to Enable?

The Addons tab shows all detected log sources with a toggle to enable/disable each one.

### ⚡ Nginx Proxy Manager – Most Important Source

**Enable this if you use NPM as a reverse proxy.**

Since all addon traffic passes through HA's internal proxy (`172.30.32.1`), the Docker log of most addons does **not** contain the real attacker IP. NPM is the only point where the real client IP is visible:

```
[01/Apr/2026:16:04:02 +0200] - 500 500 - POST https 2fa.example.com
"/user/login" [Client 91.42.192.232] ...
                               ↑ real IP here
```

**Enable NPM logging:**
1. NPM Web UI → Settings → Default Site
2. Enable "Access Log"
3. In Guardian Addons tab: enable `Docker: Nginx Proxy Manager`

---

### Which Source for Which Service?

| Service | Recommended Source | Note |
|---|---|---|
| **Home Assistant Core** | `/config/home-assistant.log` (file) | Active by default — sufficient, no Docker entry needed |
| **Nginx Proxy Manager** | `Docker: Nginx Proxy Manager` | Most important source for external access – real IPs |
| **2FAuth** | NPM (preferred) + `Docker: 2FAuth` | Docker log only shows `172.30.32.1`; NPM detects failed logins via HTTP 500 |
| **Vaultwarden** | `Docker: Vaultwarden` + NPM | Vaultwarden logs directly, but external access comes via NPM |
| **DokuWiki** | `Docker: DokuWiki` + `auth.log` file | DokuWiki writes failed logins to `data/log/auth.log` (find via File Search) |
| **Nextcloud** | `Docker: Nextcloud` | Nextcloud logs failed logins to stdout |
| **Webtrees** | NPM | Webtrees returns HTTP 200 on failed login; NPM pattern detects the login redirect |
| **SSH** | File: `/config/home-assistant.log` | SSH patterns are included in the default rules |

> **Rule of thumb:** If an addon only logs `172.30.32.1` as client IP → enable NPM instead of (or in addition to) the addon's Docker log.

### Log File Search

The Addons tab has a **file search** to find log files across all addon directories:
- Enter e.g. `auth.log` to find all auth.log files
- **Preview** shows the last lines of the file
- Found paths can be added as manual sources

### Health Check

The **Health Check** button in the Addons tab checks all enabled log sources:
- **Green (ok)** – source has recent log entries (last 7 days)
- **Red (stale)** – source has no recent entries → row is highlighted red
- **Grey (empty)** – source is empty or unreadable

This lets you quickly identify whether an enabled source is actually delivering data.

### Unused Sources

Log files discovered by Guardian but not needed can be marked as unused via **Reassign → Unused**. They appear greyed out in a separate group and are not monitored. This prevents irrelevant sources from cluttering the overview.

---

## Rules Tab

### Preconfigured Rules

| Rule ID | Detects |
|---|---|
| `ha_ban` | HA's own ban entries |
| `nginx_auth` | Nginx 401/403 authentication errors |
| `generic_fail` | Generic failed login patterns |
| `ssh_fail` | SSH failed logins |
| `nextcloud` | Nextcloud failed logins |
| `vaultwarden` | Vaultwarden/Bitwarden failed logins |
| `dovecot_postfix` | Dovecot/Postfix mail failed logins |
| `laravel_auth` | Laravel applications |
| `webtrees_fail` | Webtrees (HTTP 200 on login redirect) |
| `dokuwiki_auth` | DokuWiki auth.log |
| `2fauth_login` | 2FAuth direct access |
| `ha_core_invalid_auth` | HA Core invalid_auth events |
| `http_login_fail` | Generic HTTP 4xx/5xx login endpoints |
| `npm_proxy` | Nginx Proxy Manager – real client IP via `[Client X.X.X.X]` |

### Managing Rules

- **Toggle** – enable/disable a rule without deleting it
- **Edit** – modify pattern, description and flags; with live tester
- **Copy** – use as basis for a new rule
- **Delete** – remove rule
- **🔧 Factory Reset** – reset all rules to defaults

### Creating Custom Rules

1. Click **+ New Rule**
2. Choose a unique ID (snake_case, e.g. `my_app_fail`)
3. Regex pattern with capture group for the IP:
   ```
   Login failed.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
   ```
4. **Test** against a sample log line
5. Save – rule is active immediately

### Unmatched Auth Lines

Below the rules, log lines containing auth keywords that no rule matched are displayed. Useful as a basis for developing new rules.

---

## Whitelist Tab

### Auto-Whitelist

On first opening the Guardian UI, your public IP (via ipinfo.io) is automatically detected and added to the whitelist. If your IP changes, the new IP is added and the old one removed on next visit.

- **Disable** → click "Disable" + confirm
- **Re-enable** → click "Enable Auto-whitelist"

> ⚠️ Removing your own IP shows a warning – without a whitelist entry you could lock yourself out.

### Whitelisted by Default

- `127.0.0.1` – localhost
- `172.30.32.0/24` – HA internal network
- `192.168.0.0/16` – local home network

### Manual Entries

- Single IP: `91.42.192.232`
- CIDR range: `192.168.178.0/24`

---

## Dashboard

Shows all detected failed login attempts within the configured time window.

| Column | Meaning |
|---|---|
| Time | Timestamp of detection |
| IP Address | The attacking IP |
| Source | Log source |
| Attempts | Failed attempt count for this IP |
| Status | `ATTEMPT` or `BANNED` |
| Log Line | Original log line |
| Details | Full line in modal |

---

## Blocked IPs

Overview of all banned IPs.

- **Details** – shows which log entries triggered the ban
- **Unban** – lifts the ban immediately
- **Ban IP** – manual ban with optional duration and reason

> Home Assistant reads `ip_bans.yaml` on restart and enforces all listed bans.

---

## Architecture Notes

### Why do many addons only show 172.30.32.1 as client IP?

HA routes external traffic through an internal proxy. Addons therefore always see `172.30.32.1` as the client IP instead of the real external IP. Nginx Proxy Manager sits **in front of** this proxy and sees the real IP – that's why NPM is the most important log source.

### Cross-source counting

Failed logins from different addons are **counted together**:
> 2× 2FAuth + 2× Webtrees + 1× Vaultwarden = 5 → Ban

This is intentional: an attacker probing multiple services simultaneously should be banned faster.

---

## FAQ

**Q: The ban appears in the list but the IP isn't actually blocked?**
→ HA monitors `ip_bans.yaml` in real time – no restart needed. Check that the IP is actually in `ip_bans.yaml` in the config directory.

**Q: No alerts even though failed logins are happening?**
→ Check the Addons tab to see if the relevant source is enabled. For external access: enable the NPM log.

**Q: How do I find the log file of an addon?**
→ Addons tab → **Log File Search** → enter filename (e.g. `auth.log`).

**Q: How does the CrowdSec integration work?**
→ Guardian sends bans directly to the CrowdSec LAPI. See [CrowdSec Integration](#crowdsec-integration) for setup. Bans and unbans are automatically synchronized.

**Q: Can I run Guardian alongside CrowdSec?**
→ Yes! Guardian registers as a CrowdSec machine and sends bans directly to the LAPI. CrowdSec's own scenarios and Guardian bans complement each other.

**Q: How do I create a rule for a custom app?**
→ Rules tab → **+ New Rule** → Regex with capture group `(\d{1,3}(?:\.\d{1,3}){3})` for the IP address.

**Q: What happens if CrowdSec is unreachable?**
→ The ban is still written to `ip_bans.yaml` (if enabled). CrowdSec errors are logged but don't block the ban process.

---

## License

MIT License

## Links

- [GitHub Repository](https://github.com/gregorwolf1973/ha-guardian)
- [Issues & Feature Requests](https://github.com/gregorwolf1973/ha-guardian/issues)
