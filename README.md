# HA Guardian

Not finished jet, i'm working on it!!!

A brute-force protection addon for Home Assistant, similar to CrowdSec/fail2ban.

## Features

- **Automatic detection** – monitors `home-assistant.log` for failed login attempts
- **Auto-banning** – blocks attacking IPs by writing to HA's native `ip_bans.yaml`
- **Configurable thresholds** – set max attempts, detection window, and ban duration
- **Web UI** – dashboard with recent events, blocked IPs list, whitelist manager, and settings
- **Manual control** – add or remove bans manually from the UI
- **Whitelist** – protect individual IPs or CIDR ranges from being banned
- **Trusted domains** – exempt specific domains from banning
- **Auto-expiry** – bans automatically expire after the configured duration

## Installation

1. In Home Assistant, go to **Settings → Add-ons → Add-on Store**
2. Click the **⋮** menu → **Repositories**
3. Add: `https://github.com/gregorwolf1973/ha-guardian`
4. Find **HA Guardian** in the store and install it

## Configuration

| Option | Default | Description |
|---|---|---|
| `max_attempts` | `5` | Failed logins before banning |
| `window_minutes` | `5` | Rolling detection window in minutes |
| `ban_duration_minutes` | `240` | Ban duration in minutes (0 = permanent) |
| `log_file` | `/config/home-assistant.log` | Path to HA log file |
| `whitelist` | `[]` | IPs or CIDRs never to ban |
| `trusted_domains` | `[]` | Domain names exempt from banning |

## Recommendation

Disable Home Assistant's built-in IP banning to avoid conflicts:

```yaml
# configuration.yaml
http:
  ip_ban_enabled: false
```

HA Guardian writes directly to `ip_bans.yaml` and manages bans itself.
