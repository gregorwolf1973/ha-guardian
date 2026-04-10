# Changelog

## 1.26.0 – 2026-04-10

### Added
- **Configurable log discovery interval**: Guardian now periodically searches for new log files and addon sources. Interval is configurable in minutes via the Settings tab (default: 15 minutes, previously hardcoded to 5 minutes).

## 1.25.0 – 2026-04-04

### Changed
- All documentation (README, DOCS, CHANGELOG) translated to English
- German README available as README.de.md

## 1.24.8 – 2026-04-04

### Fixed
- CrowdSec: canonical Go duration format (`Xh Ym0s`) + payload logging for debugging

## 1.24.7 – 2026-04-04

### Fixed
- CrowdSec: `decision.duration` is the only field controlling ban expiry — `stop_at` is just alert metadata

## 1.24.5 – 2026-04-03

### Added
- **Unused Sources**: Log-Dateien können über Reassign → Unused als ungenutzt markiert werden
- **Ban Targets**: Separate Toggles für ip_bans.yaml und CrowdSec im Settings-Tab

### Fixed
- Redundantes "Enable CrowdSec integration" Checkbox entfernt (doppelt mit Ban Target Toggle)
- CrowdSec Ban-Dauer-Verdopplung behoben

## 1.24.3 – 2026-04-02

### Fixed
- `events_count` Pflichtfeld im CrowdSec Alert-Payload ergänzt

## 1.24.2 – 2026-04-02

### Added
- Manuelle Bans und Unbans werden an CrowdSec synchronisiert
- CrowdSec-Ergebnis wird im UI-Toast angezeigt

## 1.24.0 – 2026-04-01

### Changed
- **CrowdSec HTTP-Client**: aiohttp durch `urllib.request` (stdlib) ersetzt — behebt persistente 401-Fehler

## 1.23.0 – 2026-03-31

### Added
- **CrowdSec LAPI Integration**: Bans werden als Decisions an CrowdSec gesendet
- Machine-Watcher-Authentifizierung mit JWT-Token und automatischer Erneuerung
- Test Connection Button im Settings-Tab
- SHA256-Erkennung: gespeicherte Hashes werden automatisch als ungültig erkannt

## 1.22.4 – 2026-03-31

### Fixed
- Addon Delete/Remove Button repariert

### Removed
- Erste CrowdSec-Implementierung (via docker exec) entfernt zugunsten der LAPI-Integration

## 1.22.0 – 1.22.3 – 2026-03-31

### Added
- Erster CrowdSec-Integrationsversuch via Docker Socket / cscli

## 1.21.0 – 1.21.9 – 2026-03-30

### Added
- **nftables-Support** für Firewall-Blocking auf HassOS
- Rule-Spalte im Dashboard
- Domain-Chips in der UI
- Source-Delete-Button
- Details-Gruppierung nach Source

### Fixed
- Firewall-Erkennung auf HassOS (iptables → nftables Fallback)
- ip_bans.yaml als ausreichender Mechanismus akzeptiert

## 1.20.0 – 1.20.4 – 2026-03-30

### Added
- Loading-Spinner und Auto-Refresh im Dashboard
- Per-File Details-Ansicht
- Regex-Generator für neue Regeln

### Fixed
- False Bans durch alte Docker-Logs beim ersten Poll
- Spinner-Bug bei langen Ladezeiten
- iptables in Container installiert (fehlte im Alpine-Image)

## 1.19.0 – 2026-03-30

### Added
- **Protected Mode** Toggle für zusätzlichen Schutz
- Firewall-Status in der UI

## 1.18.0 – 1.18.9 – 2026-03-29

### Added
- **Health Check**: prüft ob Log-Quellen aktive Einträge haben (letzte 7 Tage)
- **My-IP Protection**: eigene IP wird serverseitig gespeichert und dynamisch aktualisiert
- Konfigurierbare Scan-Intervalle
- Reassign-Modal für Source-Zuordnung
- host_network für iptables-Zugriff
- Whitelisted Events als SKIPPED anzeigen

### Fixed
- Docker Log Polling: Content-basierte Deduplizierung statt Längen-Tracking
- Ban-Counter-Reset durch historische Log-Timestamps
- Events-Deduplizierung

## 1.17.0 – 1.17.2 – 2026-03-29

### Added
- **Custom File Sources**: eigene Log-Dateien hinzufügen
- Ungrouped Sources im Addons-Tab

### Fixed
- Custom-File-Sources: eigene Zeile pro Datei, Persist durch Discover
- File Search für absolute Pfade

## 1.16.0 – 1.16.8 – 2026-03-28

### Added
- **Rules-Editor**: Regeln bearbeiten, hinzufügen, kopieren, löschen
- Ban-Evidence (welche Log-Zeilen den Ban ausgelöst haben)
- Per-Event Alerts
- File Search im Debug-Tab
- Auto-Whitelist der eigenen IP beim Seitenaufruf
- Webtrees-, DokuWiki-, NPM-Erkennungsregeln
- Zeitfenster-Filterung für Log-Zeilen

### Changed
- Alerts in Dashboard integriert
- Debug-Tab entfernt, Log-Verbosity reduziert

### Fixed
- Preview-Modal außerhalb Rules-Tab
- Timezone-aware Log-Filterung
- Supervisor-Log-Spam reduziert

## 1.15.0 – 2026-03-28

### Added
- Webtrees Failed-Login-Erkennung

## 1.14.0 – 2026-03-28

### Added
- DokuWiki auth.log Erkennung

## 1.13.0 – 2026-03-28

### Added
- Nginx Proxy Manager Log-Pattern

## 1.12.0 – 2026-03-28

### Added
- Log-Zeilen außerhalb des Monitoring-Fensters werden gefiltert

## 1.10.0 – 2026-03-28

### Fixed
- Supervisor API Zugriff (hassio_role: admin)
- Zeitbasiertes Log-Lesen

## 1.9.0 – 2026-03-28

### Fixed
- Docker Addon Sources aktivieren sich nicht
- HA Core Log Polling hinzugefügt

## 1.8.0 – 2026-03-28

### Added
- Auto-Whitelist für HA-interne IPs
- Port 8098

### Fixed
- Source Auto-Enable

## 1.7.0 – 1.7.3 – 2026-03-28

### Added
- Addon-Level Monitoring
- HTTP Login Failure Detection
- Auto-Enable neuer Log-Sources für aktive Addons

### Fixed
- Whitelist CIDR-Löschung
- Scan bei Startup

## 1.5.0 – 2026-03-28

### Added
- Laravel/2FAuth Patterns

### Fixed
- Deduplizierung, Stale Source Cleanup

## 1.4.0 – 2026-03-28

### Added
- Log Preview
- Debug-Tab für Unmatched Auth Lines

## 1.3.0 – 2026-03-28

### Added
- Smart Log Discovery (nur aktuelle Dateien, Addon-Name-Mapping)

## 1.2.0 – 2026-03-28

### Added
- Persistente Einstellungen
- Deep Log Discovery
- Weitere Erkennungsmuster

## 1.1.0 – 2026-03-28

### Added
- Multi-Source Log Scanning
- Alerts
- Addon Log Support

## 1.0.0 – 2026-03-28

### Added
- Initial Release
- Automatische Brute-Force-Erkennung aus Home-Assistant-Logs
- IP-Banning via `ip_bans.yaml`
- Konfigurierbare Schwellwerte
- Web-UI mit Dashboard, Blocked IPs, Whitelist und Settings
- Manuelles Ban/Unban
- Whitelist für IPs und CIDR-Bereiche
- Automatisches Ban-Ablauf
- HA Ingress Support
