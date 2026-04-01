# HA Guardian – Dokumentation

Brute-force-Schutz für Home Assistant: überwacht Logs aller installierten Addons, erkennt fehlgeschlagene Anmeldeversuche und sperrt angreifende IPs automatisch über `ip_bans.yaml`.

---

## Schnellstart

1. Addon starten und über **Web-UI öffnen** aufrufen
2. Im Tab **Addons** die gewünschten Log-Quellen per Toggle **aktivieren**
3. Im Tab **Whitelist** die eigene IP schützen (Auto-Whitelist wird beim ersten Öffnen angeboten)
4. Fertig – Guardian überwacht die aktivierten Quellen

---

## Konfigurationsoptionen

| Option | Standard | Beschreibung |
|---|---|---|
| `max_attempts` | `5` | Fehlversuche vor dem Bann |
| `window_minutes` | `5` | Zeitfenster für die Erkennung (Minuten) |
| `ban_duration_minutes` | `240` | Sperrdauer in Minuten (`0` = dauerhaft) |
| `alert_window_hours` | `24` | Zeitraum für die Dashboard-Anzeige (Stunden) |
| `log_file` | `/config/home-assistant.log` | Pfad zur HA-Core-Log-Datei |

> Alle Einstellungen können auch komfortabel im **Settings-Tab** der Web-UI geändert werden.

---

## Kompatibilität mit HA's eingebautem Bann-Mechanismus

Guardian und HA's `ip_ban_enabled` arbeiten unabhängig und können gleichzeitig aktiv sein. HA schützt nur die eigene Weboberfläche, Guardian zusätzlich alle überwachten Addons. Kein Konflikt, kein Handlungsbedarf.

---

## Addons-Tab – welche Log-Quellen aktivieren?

### ⚡ Nginx Proxy Manager – wichtigste Quelle

Da aller externer Traffic über den HA-internen Proxy (`172.30.32.1`) läuft, enthält der Docker-Log der meisten Addons **nicht** die echte Angreifer-IP. Nginx Proxy Manager (NPM) liegt vor diesem Proxy und schreibt die echte Client-IP in seinen Log:

```
[Client 91.42.192.232]  ← echte IP, nur in NPM sichtbar
```

**NPM-Logging aktivieren:** NPM Web-UI → Settings → Default Site → Access Log ✓

### Welche Quelle für welchen Dienst?

| Dienst | Empfohlene Quelle |
|---|---|
| Home Assistant Core | `Docker: Home Assistant Core` (immer aktiv lassen) |
| Nginx Proxy Manager | `Docker: Nginx Proxy Manager` ← wichtigste Quelle |
| 2FAuth | NPM (externe Zugriffe) + `Docker: 2FAuth` |
| Vaultwarden | `Docker: Vaultwarden` + NPM |
| DokuWiki | `Docker: DokuWiki` + ggf. `auth.log`-Datei |
| Nextcloud | `Docker: Nextcloud` |
| Webtrees | NPM (Webtrees gibt HTTP 200 bei Fehllogin) |

> **Faustregel:** Wenn ein Addon nur `172.30.32.1` als Client-IP loggt → NPM aktivieren.

### Log File Search

Im Addons-Tab gibt es eine **Dateisuche**: Dateiname eingeben (z. B. `auth.log`) → findet alle passenden Logs in allen Addon-Verzeichnissen.

---

## Bans wirken in Echtzeit

Home Assistant überwacht `ip_bans.yaml` auf Änderungen. Neue Bans von Guardian werden **sofort** ohne Neustart aktiv.

---

## Rules-Tab

Alle Erkennungsregeln können hier verwaltet werden:

- **Toggle** – Regel ein-/ausschalten
- **Edit** – Pattern und Beschreibung anpassen (mit Live-Tester)
- **Copy** – als Basis für neue Regel verwenden
- **Delete** – Regel entfernen
- **Werkseinstellungen** – alle Regeln zurücksetzen

### Eigene Regel erstellen

Regex-Pattern mit Capture-Group für die IP-Adresse:
```
Login failed.*from\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
```

---

## Whitelist-Tab

- **Auto-Whitelist**: eigene öffentliche IP wird automatisch beim Öffnen der UI erkannt und eingetragen. Bei IP-Wechsel wird automatisch aktualisiert.
- **Manuell**: einzelne IPs (`1.2.3.4`) oder CIDR-Bereiche (`192.168.178.0/24`)
- Interne Adressen (`127.0.0.1`, `172.30.32.0/24`, `192.168.0.0/16`) sind standardmäßig geschützt

---

## Häufige Fragen

**Ban erscheint in der Liste, IP ist aber nicht gesperrt?**
→ HA überwacht `ip_bans.yaml` in Echtzeit, kein Neustart nötig. Prüfe ob die IP wirklich in `ip_bans.yaml` im Konfigurationsverzeichnis eingetragen ist.

**Keine Alerts obwohl Fehllogins passieren?**
→ Im Addons-Tab prüfen ob die richtige Quelle aktiviert ist. Bei externen Zugriffen: NPM aktivieren.

**Wie finde ich die Log-Datei eines Addons?**
→ Addons-Tab → Log File Search → Dateiname eingeben.

**Kann ich Guardian parallel zu CrowdSec betreiben?**
→ Ja, aber CrowdSec könnte Guardian-Anfragen blockieren. Empfehlung: erst ohne CrowdSec testen.

---

Vollständige Dokumentation und Quellcode: [github.com/gregorwolf1973/ha-guardian](https://github.com/gregorwolf1973/ha-guardian)

[!["Buy Me A Coffee"](https://www.buymeacoffee.com/assets/img/custom_images/orange_img.png)](https://buymeacoffee.com/gregorwolf1973)
