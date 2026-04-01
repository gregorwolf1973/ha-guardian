# HA Guardian

<p align="center">
  <img src="guardian/logo.png" alt="HA Guardian Logo" width="400">
</p>

<p align="center">
  <a href="https://buymeacoffee.com/gregorwolf1973">
    <img src="https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png" alt="Buy Me A Coffee">
  </a>
</p>

**Brute-force-Schutz für Home Assistant** – überwacht Logs aller installierten Addons, erkennt fehlgeschlagene Anmeldeversuche und sperrt angreifende IPs automatisch.

---

## Inhaltsverzeichnis

1. [Was macht HA Guardian?](#was-macht-ha-guardian)
2. [Funktionen](#funktionen)
3. [Installation](#installation)
4. [Schnellstart](#schnellstart)
5. [Konfiguration](#konfiguration)
6. [Addons-Tab – welche Log-Quellen aktivieren?](#addons-tab--welche-log-quellen-aktivieren)
7. [Rules-Tab](#rules-tab)
8. [Whitelist-Tab](#whitelist-tab)
9. [Dashboard](#dashboard)
10. [Blocked IPs](#blocked-ips)
11. [Hinweise zur Architektur](#hinweise-zur-architektur)
12. [Häufige Fragen](#häufige-fragen)

---

## Was macht HA Guardian?

HA Guardian liest kontinuierlich die Log-Dateien und Docker-Logs deiner Home-Assistant-Addons. Erkennt es zu viele fehlgeschlagene Anmeldeversuche von einer IP-Adresse innerhalb eines konfigurierbaren Zeitfensters, wird die IP automatisch in `ip_bans.yaml` eingetragen – dem nativen Sperrmechanismus von Home Assistant.

```
Angreifer → Nginx Proxy Manager → Addon (2FAuth, Vaultwarden…)
                ↓                        ↓
          NPM-Log (echte IP)      Docker-Log (Proxy-IP 172.30.32.1)
                ↓
           HA Guardian erkennt Angriff
                ↓
         IP wird in ip_bans.yaml eingetragen
```

---

## Funktionen

- 🔍 **Multi-Addon-Überwachung** – Docker-Logs und Dateien aller installierten Addons
- 🛡️ **Automatisches Bannen** – schreibt direkt in HA's native `ip_bans.yaml`
- ⏱️ **Zeitfenster-Filterung** – nur Log-Einträge innerhalb des konfigurierten Fensters zählen
- 🌐 **Nginx Proxy Manager Integration** – erkennt echte Client-IPs hinter dem HA-Proxy
- 📋 **15+ Erkennungsregeln** – vorkonfiguriert für gängige Dienste
- ✏️ **Rules-Editor** – Regeln bearbeiten, hinzufügen, deaktivieren oder auf Werkseinstellungen zurücksetzen
- 🔒 **Whitelist** – IPs und CIDR-Bereiche dauerhaft schützen, Auto-Whitelist der eigenen IP
- 📊 **Dashboard** – alle Ereignisse auf einen Blick mit vollständiger Log-Zeile und Details-Button
- 💾 **Persistent** – Einstellungen, Regeln und Whitelist bleiben nach Neustart erhalten

---

## Installation

1. In Home Assistant zu **Einstellungen → Add-ons → Add-on Store**
2. **⋮ Menü → Repositories**
3. URL hinzufügen: `https://github.com/gregorwolf1973/ha-guardian`
4. **HA Guardian** im Store suchen und installieren
5. Addon starten und über den **Ingress-Button** (Web-UI öffnen) aufrufen

---

## Schnellstart

1. Addon installieren und starten
2. Web-UI öffnen
3. Im Tab **Addons** die gewünschten Log-Quellen mit dem Toggle **aktivieren**
4. Im Tab **Whitelist** die eigene IP whitelisten (Auto-Whitelist wird beim ersten Öffnen angeboten)
5. Fertig – Guardian überwacht nun die aktivierten Quellen

---

## Konfiguration

Die Einstellungen werden im **Settings-Tab** der Web-UI vorgenommen und persistent gespeichert.
Die Werte in der HA-Addon-Konfigurationsseite dienen nur als initiale Standardwerte.

| Einstellung | Standard | Beschreibung |
|---|---|---|
| **Max. Versuche** | `5` | Anzahl fehlgeschlagener Logins bevor die IP gesperrt wird |
| **Zeitfenster (Min.)** | `5` | Rollierendes Erkennungsfenster in Minuten |
| **Sperrdauer (Min.)** | `240` | Ban-Dauer (`0` = dauerhaft) |
| **Alert-Fenster (Std.)** | `24` | Wie weit zurück Ereignisse im Dashboard angezeigt werden |
| **Log-Datei** | `/config/home-assistant.log` | Pfad zur HA-Core-Log-Datei |

> **Hinweis:** HA's eingebauter Bann-Mechanismus (`ip_ban_enabled`) und Guardian arbeiten unabhängig voneinander und können problemlos gleichzeitig aktiv sein. HA schützt nur die eigene Weboberfläche, Guardian zusätzlich alle anderen Addons.

---

## Addons-Tab – welche Log-Quellen aktivieren?

Im Addons-Tab siehst du alle erkannten Log-Quellen mit Toggle zum Aktivieren/Deaktivieren.

### ⚡ Nginx Proxy Manager – Wichtigste Quelle

**Aktivieren wenn du NPM als Reverse-Proxy verwendest.**

Da der gesamte Addon-Traffic über den HA-internen Proxy (`172.30.32.1`) läuft, enthält der Docker-Log der meisten Addons **nicht** die echte Angreifer-IP. NPM ist der einzige Punkt, an dem die echte Client-IP sichtbar ist:

```
[01/Apr/2026:16:04:02 +0200] - 500 500 - POST https 2fa.example.com
"/user/login" [Client 91.42.192.232] ...
                               ↑ echte IP hier
```

**NPM-Logging aktivieren:**
1. NPM Web-UI öffnen → Settings → Default Site
2. „Access Log" aktivieren
3. Im Guardian Addons-Tab: `Docker: Nginx Proxy Manager` einschalten

---

### Welche Quelle für welchen Dienst?

| Dienst | Empfohlene Quelle | Hinweis |
|---|---|---|
| **Home Assistant Core** | `Docker: Home Assistant Core` + `/config/home-assistant.log` | Standardmäßig aktiv, immer aktiviert lassen |
| **Nginx Proxy Manager** | `Docker: Nginx Proxy Manager` | Wichtigste Quelle für externe Zugriffe – echte IPs |
| **2FAuth** | NPM (bevorzugt) + `Docker: 2FAuth` | Docker-Log zeigt nur `172.30.32.1`; NPM erkennt Fehllogins via HTTP 500 |
| **Vaultwarden** | `Docker: Vaultwarden` + NPM | Vaultwarden loggt direkt, aber externe Zugriffe kommen über NPM |
| **DokuWiki** | `Docker: DokuWiki` + ggf. `auth.log`-Datei | DokuWiki schreibt Fehllogins in `data/log/auth.log` (Datei per File Search finden) |
| **Nextcloud** | `Docker: Nextcloud` | Nextcloud loggt Fehllogins in stdout |
| **Webtrees** | NPM | Webtrees gibt bei Fehllogin HTTP 200 zurück; NPM-Pattern erkennt den Login-Redirect |
| **SnappyMail** | ❌ Nicht unterstützt | SnappyMail gibt bei Fehllogin HTTP 200 ohne erkennbares Merkmal |
| **SSH** | Datei: `/config/home-assistant.log` | SSH-Muster sind in den Standardregeln enthalten |

> **Faustregel:** Wenn ein Addon seinen Docker-Log nur mit `172.30.32.1` befüllt → NPM aktivieren statt (oder zusätzlich zu) dem Docker-Log des Addons.

### Log File Search

Im Addons-Tab gibt es eine **Dateisuche** um Log-Dateien in allen Addon-Verzeichnissen zu finden:
- Eingabe z. B. `auth.log` findet alle auth.log-Dateien
- **Preview** zeigt die letzten Zeilen der Datei
- Gefundene Pfade können als manuelle Quellen hinzugefügt werden

---

## Rules-Tab

### Vorkonfigurierte Regeln

| Regel-ID | Erkennt |
|---|---|
| `ha_ban` | HA-eigene Ban-Einträge |
| `nginx_auth` | Nginx 401/403 Authentifizierungsfehler |
| `generic_fail` | Allgemeine Fehllogin-Muster |
| `ssh_fail` | SSH-Fehllogins |
| `nextcloud` | Nextcloud-Fehllogins |
| `vaultwarden` | Vaultwarden/Bitwarden-Fehllogins |
| `dovecot_postfix` | Dovecot/Postfix Mail-Fehllogins |
| `laravel_auth` | Laravel-Applikationen |
| `webtrees_fail` | Webtrees (HTTP 200 auf Login-Redirect) |
| `dokuwiki_auth` | DokuWiki auth.log |
| `2fauth_login` | 2FAuth direkter Zugriff |
| `ha_core_invalid_auth` | HA Core invalid_auth Ereignisse |
| `http_login_fail` | Generische HTTP 4xx/5xx Login-Endpoints |
| `npm_proxy` | Nginx Proxy Manager – echte Client-IP via `[Client X.X.X.X]` |

### Regeln verwalten

- **Toggle** – Regel ein-/ausschalten ohne sie zu löschen
- **Edit** – Pattern, Beschreibung und Flags anpassen; mit Live-Tester
- **Copy** – als Basis für eine neue Regel verwenden
- **Delete** – Regel löschen
- **🔧 Werkseinstellungen** – alle Regeln auf Standard zurücksetzen

### Eigene Regel erstellen

1. **+ New Rule** klicken
2. Eindeutige ID (snake_case, z. B. `meine_app_fail`)
3. Regex-Pattern mit Capture-Group für die IP:
   ```
   Login failed.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
   ```
4. Mit **Test** gegen eine Beispiel-Log-Zeile testen
5. Speichern – Regel ist sofort aktiv

### Unmatched Auth Lines

Unter den Regeln erscheinen Log-Zeilen mit auth-Schlüsselwörtern, die von keiner Regel erkannt wurden. Hilfreiche Basis um neue Regeln zu entwickeln.

---

## Whitelist-Tab

### Auto-Whitelist

Beim ersten Öffnen der Guardian-UI wird die eigene öffentliche IP (via ipinfo.io) automatisch erkannt und zur Whitelist hinzugefügt. Ändert sich die IP, wird beim nächsten Öffnen die neue IP hinzugefügt und die alte entfernt.

- **Deaktivieren** → Klick auf „Disable" + Bestätigung
- **Reaktivieren** → Klick auf „Enable Auto-whitelist"

> ⚠️ Beim Entfernen der eigenen IP erscheint eine Warnung – ohne Whitelist-Eintrag kann man sich selbst aussperren.

### Standardmäßig whitelisted

- `127.0.0.1` – Localhost
- `172.30.32.0/24` – HA-internes Netzwerk
- `192.168.0.0/16` – Lokales Heimnetzwerk

### Manuelle Einträge

- Einzelne IP: `91.42.192.232`
- CIDR-Bereich: `192.168.178.0/24`

---

## Dashboard

Zeigt alle erkannten Login-Fehlversuche im konfigurierten Zeitfenster.

| Spalte | Bedeutung |
|---|---|
| Time | Zeitpunkt der Erkennung |
| IP Address | Die angreifende IP |
| Source | Log-Quelle |
| Attempts | Zähler der Fehlversuche dieser IP |
| Status | `ATTEMPT` oder `BANNED` |
| Log Line | Originale Log-Zeile |
| Details | Vollständige Zeile im Modal |

---

## Blocked IPs

Übersicht aller gesperrten IPs.

- **Details** – zeigt welche Log-Einträge den Ban ausgelöst haben
- **Unban** – hebt die Sperre sofort auf
- **Ban IP** – manuelle Sperre mit optionaler Dauer und Begründung

> Home Assistant überwacht `ip_bans.yaml` auf Änderungen und wendet neue Bans **in Echtzeit** an. Ein Neustart ist nicht erforderlich.

---

## Hinweise zur Architektur

### Warum zeigen viele Addons nur 172.30.32.1 als Client-IP?

HA leitet externen Traffic über einen internen Proxy weiter. Addons sehen daher als Client-IP immer `172.30.32.1` statt der echten externen IP. Nginx Proxy Manager liegt **vor** diesem Proxy und sieht die echte IP – deshalb ist NPM die wichtigste Log-Quelle.

### Zähler über mehrere Quellen

Fehllogins verschiedener Addons werden **zusammengezählt**:
> 2× 2FAuth + 2× Webtrees + 1× Vaultwarden = 5 → Ban

Das ist gewollt: Ein Angreifer der mehrere Dienste gleichzeitig attackiert soll schneller gesperrt werden.

---

## Häufige Fragen

**Q: Der Ban erscheint in der Liste, aber die IP ist nicht wirklich gesperrt?**
→ HA überwacht `ip_bans.yaml` in Echtzeit — kein Neustart nötig. Prüfe ob die IP wirklich in `ip_bans.yaml` steht (Datei im Konfigurationsverzeichnis).

**Q: Keine Alerts obwohl Fehllogins stattfinden?**
→ Im Addons-Tab prüfen ob die relevante Quelle aktiviert ist. Bei externen Zugriffen: NPM-Log aktivieren.

**Q: Wie finde ich die Log-Datei eines Addons?**
→ Addons-Tab → **Log File Search** → Dateiname eingeben (z. B. `auth.log`).

**Q: Kann ich Guardian parallel zu CrowdSec betreiben?**
→ Grundsätzlich ja, aber CrowdSec könnte Guardian-Anfragen blockieren. Empfehlung: erst testen wenn CrowdSec pausiert ist.

**Q: Wie erstelle ich eine Regel für eine eigene App?**
→ Rules-Tab → **+ New Rule** → Regex mit Capture-Group `(\d{1,3}(?:\.\d{1,3}){3})` für die IP-Adresse.

---

## Lizenz

MIT License

## Links

- [GitHub Repository](https://github.com/gregorwolf1973/ha-guardian)
- [Issues & Feature Requests](https://github.com/gregorwolf1973/ha-guardian/issues)
