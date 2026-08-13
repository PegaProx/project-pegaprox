#!/usr/bin/env python3
"""
Bootstrap Polish language support for PegaProx.

This helper makes the first safe, testable localization pass:
- adds `pl` to the frontend supported-language allowlist,
- adds Polish to the language switcher,
- allows saved Polish preference to be restored,
- creates `translations.pl` by copying the English map and replacing a starter set
  of common/operator-facing strings with Polish translations.

It intentionally leaves many strings in English for the first pass so the UI can be
validated before a full 3800+ key translation is prepared.

Run from the repository root:

    python3 scripts/add_polish_translation_bootstrap.py
    web/Dev/build.sh
"""
from __future__ import annotations

from pathlib import Path
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CONTEXTS = ROOT / "web" / "src" / "contexts.js"
TRANSLATIONS = ROOT / "web" / "src" / "translations.js"

TRANSLATED_KEYS = {
    "languageSimplifiedChinese": "Chiński uproszczony",
    "setupFailedHttp": "Konfiguracja nie powiodła się (HTTP {status})",
    "loading": "Ładowanie...",
    "save": "Zapisz",
    "cancel": "Anuluj",
    "delete": "Usuń",
    "edit": "Edytuj",
    "add": "Dodaj",
    "close": "Zamknij",
    "yes": "Tak",
    "no": "Nie",
    "ok": "OK",
    "enabled": "Włączone",
    "disabled": "Wyłączone",
    "enable": "Włącz",
    "disable": "Wyłącz",
    "actions": "Akcje",
    "status": "Status",
    "name": "Nazwa",
    "type": "Typ",
    "online": "Online",
    "offline": "Offline",
    "running": "Uruchomiona",
    "stopped": "Zatrzymana",
    "active": "Aktywne",
    "all": "Wszystkie",
    "found": "znaleziono",
    "search": "Szukaj",
    "results": "wyniki",
    "noResults": "Brak wyników",
    "target": "Cel",
    "source": "Źródło",
    "rules": "Reguły",
    "default": "Domyślne",
    "none": "Brak",
    "of": "z",
    "since": "Od",
    "uptime": "Czas pracy",
    "osVersion": "Wersja systemu",
    "guestAgentNotInstalled": "QEMU Guest Agent nie jest zainstalowany",
    "guestAgentInstallHint": "Zainstaluj qemu-guest-agent, aby wyświetlać nazwę hosta, system i jądro",

    "login": "Logowanie",
    "logout": "Wyloguj",
    "loginTitle": "Zaloguj do PegaProx",
    "loginSubtitle": "Zarządzanie klastrami Proxmox VE w PegaProx",
    "usernameLabel": "Nazwa użytkownika",
    "passwordLabel": "Hasło",
    "passwordPolicyHint": "Min. 8 znaków, wymagana wielka litera, mała litera i cyfra",
    "minChars": "Min.",
    "characters": "znaków",
    "uppercase": "wielka litera",
    "lowercase": "mała litera",
    "numbers": "cyfra",
    "specialChar": "znak specjalny",
    "loginButton": "Zaloguj",
    "rememberMe": "Zapamiętaj mnie",
    "loggingIn": "Logowanie...",
    "loginError": "Logowanie nie powiodło się",
    "invalidCredentials": "Nieprawidłowe dane logowania",
    "sessionExpired": "Sesja wygasła",
    "welcomeBack": "Witamy ponownie",
    "changePassword": "Zmień hasło",
    "currentPassword": "Aktualne hasło",
    "newPassword": "Nowe hasło",
    "confirmPassword": "Potwierdź hasło",
    "passwordChanged": "Hasło zmienione",
    "passwordMismatch": "Hasła nie są zgodne",
    "userManagement": "Zarządzanie użytkownikami",
    "users": "Użytkownicy",
    "addUser": "Dodaj użytkownika",
    "editUser": "Edytuj użytkownika",
    "deleteUser": "Usuń użytkownika",
    "deleteUserConfirm": "Na pewno usunąć tego użytkownika?",
    "role": "Rola",
    "roleAdmin": "Administrator",
    "roleUser": "Użytkownik",
    "roleViewer": "Obserwator",
    "displayName": "Nazwa wyświetlana",
    "profile": "Profil",
    "myProfile": "Mój profil",
    "languagePreference": "Język",
    "languagePreferenceDesc": "Język interfejsu i menu",
    "never": "Nigdy",

    "pegaproxSettings": "Ustawienia PegaProx",
    "serverSettings": "Serwer",
    "networkSettings": "Ustawienia sieci",
    "domain": "Domena",
    "port": "Port",
    "sslSettings": "Certyfikat SSL/TLS",
    "enableSsl": "Włącz SSL",
    "sslCertificate": "Certyfikat SSL",
    "sslKey": "Klucz prywatny",
    "reverseProxy": "Reverse proxy",
    "saveSettings": "Zapisz ustawienia",
    "serverSettingsSaved": "Ustawienia serwera zapisane",
    "restartRequired": "Wymagany restart serwera, aby zastosować zmiany",
    "restartServer": "Uruchom serwer ponownie",
    "restartNow": "Uruchom ponownie teraz",
    "confirmRestart": "Uruchomić serwer ponownie?",

    "overview": "Przegląd",
    "resources": "Zasoby",
    "datacenter": "Datacenter",
    "settings": "Ustawienia",
    "summary": "Podsumowanie",
    "clusters": "Klastry",
    "cluster": "Klaster",
    "addCluster": "Dodaj klaster",
    "clusterOverview": "Przegląd klastra",
    "clusterHealth": "Stan klastra",
    "clustersConnected": "Połączone klastry",
    "noClustersConfigured": "Brak skonfigurowanych klastrów",
    "addClusterToStart": "Dodaj klaster, aby rozpocząć",
    "connectCluster": "Połącz klaster Proxmox z PegaProx",
    "clusterName": "Nazwa klastra",
    "host": "Host",
    "passwordOrToken": "Hasło / token",
    "sslVerification": "Weryfikacja SSL",
    "testConnection": "Testuj połączenie",
    "reconfigureCluster": "Skonfiguruj klaster ponownie",
    "excellent": "Doskonały",
    "good": "Dobry",
    "warning": "Ostrzeżenie",
    "critical": "Krytyczny",
    "nodesOnline": "Węzły online",

    "nodes": "Węzły",
    "node": "Węzeł",
    "nodeSettings": "Ustawienia węzła",
    "nodeShell": "Shell węzła",
    "loadingMetrics": "Ładowanie metryk...",
    "connectionError": "Błąd połączenia",
    "retry": "Spróbuj ponownie",
    "maintenance": "Konserwacja",
    "enterMaintenance": "Włącz tryb konserwacji",
    "exitMaintenance": "Wyłącz tryb konserwacji",
    "maintenanceMode": "Tryb konserwacji",
    "update": "Aktualizacja",
    "startUpdate": "Rozpocznij aktualizację",
    "cpuHistory": "Historia CPU",
    "ramHistory": "Historia RAM",
    "ramUsage": "Użycie RAM",
    "cpuUsage": "Użycie CPU",
    "diskUsage": "Użycie dysku",
    "showMore": "Pokaż więcej",
    "showLess": "Pokaż mniej",

    "virtualMachines": "Maszyny wirtualne",
    "containers": "Kontenery",
    "vm": "VM",
    "lxc": "LXC",
    "lxcContainer": "Kontener LXC",
    "container": "Kontener",
    "guests": "Goście",
    "start": "Uruchom",
    "stop": "Zatrzymaj",
    "shutdown": "Zamknij system",
    "reboot": "Uruchom ponownie",
    "forceStop": "Wymuś zatrzymanie",
    "migrate": "Migruj",
    "migrateVm": "Migruj VM",
    "snapshot": "Migawka",
    "snapshots": "Migawki",
    "createVm": "Utwórz nową VM",
    "createContainer": "Utwórz nowy kontener",
    "newVm": "Nowa VM",
    "newContainer": "Nowy kontener",
    "power": "Zasilanie",
    "console": "Konsola",
    "openConsole": "Otwórz konsolę",
    "configure": "Konfiguruj",
    "configuration": "Konfiguracja",
    "metrics": "Metryki",
    "hardware": "Sprzęt",
    "network": "Sieć",
    "disk": "Dysk",
    "memory": "Pamięć",
    "cpu": "CPU",
    "ram": "RAM",

    "storage": "Magazyn",
    "storages": "Magazyny",
    "addStorage": "Dodaj magazyn",
    "storageId": "ID magazynu",
    "storageType": "Typ magazynu",
    "directory": "Katalog",
    "path": "Ścieżka",
    "server": "Serwer",
    "content": "Zawartość",
    "shared": "Współdzielony",
    "datastore": "Datastore",
    "datastores": "Datastore'y",
    "upload": "Prześlij",
    "uploadIso": "Prześlij ISO",
    "downloadFromUrl": "Pobierz z URL",
    "fromUrl": "Z URL",
    "rescan": "Skanuj ponownie",
    "rescanStorage": "Skanuj magazyn ponownie",

    "backup": "Kopia zapasowa",
    "backups": "Kopie zapasowe",
    "backupJobs": "Zadania kopii zapasowych",
    "noBackups": "Nie znaleziono kopii zapasowych",
    "noBackupJobs": "Brak zadań kopii zapasowych",
    "createBackup": "Utwórz kopię zapasową",
    "createBackupJob": "Utwórz zadanie kopii zapasowej",
    "restoreBackup": "Przywróć kopię zapasową",
    "backupStarted": "Kopia zapasowa uruchomiona",
    "restoreStarted": "Przywracanie uruchomione",
    "confirmRestore": "Na pewno przywrócić kopię zapasową?",
    "confirmDeleteBackup": "Na pewno usunąć kopię zapasową?",
    "backupDeleted": "Kopia zapasowa usunięta",
    "verifyBackup": "Zweryfikuj kopię zapasową",
    "verificationStarted": "Weryfikacja kopii zapasowej uruchomiona",
    "verificationPassed": "✓ Kopia zweryfikowana — przywracanie + start OK",
    "verificationFailed": "✗ Weryfikacja nie powiodła się",

    "ceph": "Ceph",
    "cephStatus": "Status Ceph",
    "cephHealth": "Stan klastra",
    "cephCapacity": "Pojemność",
    "cephOsds": "OSD",
    "cephMons": "Monitory",
    "cephPools": "Pule",
    "cephFs": "CephFS",

    "updateManager": "Menedżer aktualizacji",
    "updateManagerDesc": "Sprawdź i zainstaluj aktualizacje na wszystkich węzłach klastra",
    "checkForUpdates": "Sprawdź aktualizacje",
    "checkingUpdates": "Sprawdzanie aktualizacji...",
    "updatesAvailable": "Dostępne aktualizacje",
    "noUpdatesAvailable": "Brak dostępnych aktualizacji",
    "packagesAvailable": "Dostępne pakiety",
    "securityUpdates": "Aktualizacje bezpieczeństwa",
    "startRollingUpdate": "Rozpocznij rolling update",
    "rebootRequired": "Wymagany restart dla jądra",
    "package": "Pakiet",
    "currentVersion": "Aktualna",
    "newVersion": "Nowa",
    "rollingUpdateInProgress": "Rolling update w toku",
    "rollingUpdateCompleted": "Rolling update zakończony",
    "rollingUpdateFailed": "Rolling update nie powiódł się",
    "rollingUpdateCancelled": "Rolling update anulowany",
    "nodesUpdated": "Zaktualizowane węzły",
    "includeReboot": "Restart po aktualizacji",
    "skipEvacuation": "Pomiń ewakuację VM",
    "evacuationTimeout": "Timeout ewakuacji",
    "rebootTimeout": "Timeout restartu / powrotu online",

    "hardwareMonitoring": "Monitoring sprzętu",
    "hardwareMonitoringDisabledDesc": "Monitoring sprzętu in-band (IPMI) nie jest włączony. Odczytuje sensory, pobór mocy, inwentarz i dziennik zdarzeń sprzętowych bezpośrednio na węźle — bez poświadczeń, tylko do odczytu.",
    "enableHardwareMonitoring": "Włącz monitoring sprzętu",
    "hwEnabled": "Monitoring sprzętu włączony",
    "hwReadFailed": "Nie udało się odczytać sprzętu",
    "hwIpmitoolMissing": "ipmitool nie jest zainstalowany na tym węźle.",
    "hwInstallIpmitool": "Zainstaluj ipmitool",
    "hwNoData": "Brak danych sprzętowych",
    "hwSystemInfo": "Informacje systemowe",
    "hwSensors": "Sensory",
    "hwEventLog": "Dziennik zdarzeń sprzętowych (SEL)",
    "powerDraw": "Pobór mocy",
    "hardwareHealth": "Stan sprzętu",
    "degradedHardware": "Sprzęt w stanie obniżonym",

    "tasks": "Zadania",
    "taskFailed": "Zadanie nie powiodło się",
    "taskCancelled": "Zadanie anulowane",
    "allTasks": "Wszystkie zadania",
    "runningTasks": "Uruchomione zadania",
    "failedTasks": "Nieudane zadania",
    "todaysTasks": "Dzisiejsze zadania",
    "taskOutput": "Wynik zadania",
    "duration": "Czas trwania",
    "description": "Opis",
    "completed": "zakończone",
    "success": "Sukces",
    "error": "Błąd",
    "unsavedChanges": "Niezapisane zmiany",
    "confirmAction": "Potwierdź akcję",
}


def js_quote(value: str) -> str:
    return "'" + value.replace("\\", "\\\\").replace("'", "\\'").replace("\n", "\\n") + "'"


def replace_js_string_value(block: str, key: str, value: str) -> tuple[str, bool]:
    pattern = re.compile(rf"(^\s*{re.escape(key)}\s*:\s*)('(?:\\.|[^'\\])*'|\"(?:\\.|[^\"\\])*\")", re.MULTILINE)
    replacement = rf"\g<1>{js_quote(value)}"
    new_block, count = pattern.subn(replacement, block, count=1)
    return new_block, count > 0


def find_object_block(text: str, object_name: str) -> tuple[int, int]:
    marker = re.search(rf"\n\s*{re.escape(object_name)}\s*:\s*{{", text)
    if not marker:
        raise RuntimeError(f"Could not find object block for {object_name!r}")

    open_pos = text.find("{", marker.start())
    depth = 0
    in_string: str | None = None
    escape = False
    line_comment = False
    block_comment = False

    i = open_pos
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""

        if line_comment:
            if ch == "\n":
                line_comment = False
            i += 1
            continue

        if block_comment:
            if ch == "*" and nxt == "/":
                block_comment = False
                i += 2
                continue
            i += 1
            continue

        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == in_string:
                in_string = None
            i += 1
            continue

        if ch in ("'", '"', "`"):
            in_string = ch
            i += 1
            continue
        if ch == "/" and nxt == "/":
            line_comment = True
            i += 2
            continue
        if ch == "/" and nxt == "*":
            block_comment = True
            i += 2
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return open_pos, i
        i += 1

    raise RuntimeError(f"Could not find end of object block for {object_name!r}")


def patch_contexts() -> bool:
    text = CONTEXTS.read_text(encoding="utf-8")
    original = text

    text = text.replace(
        "const SUPPORTED_LANGS = ['de', 'en', 'it', 'fr', 'es', 'pt', 'ko', 'zh'];",
        "const SUPPORTED_LANGS = ['de', 'en', 'it', 'fr', 'es', 'pt', 'ko', 'zh', 'pl'];",
    )

    text = text.replace(
        "                { code: 'zh', flag: '🇨🇳', label: 'ZH', title: t('languageSimplifiedChinese') },\n            ];",
        "                { code: 'zh', flag: '🇨🇳', label: 'ZH', title: t('languageSimplifiedChinese') },\n"
        "                { code: 'pl', flag: '🇵🇱', label: 'PL', title: 'Polski' },\n"
        "            ];",
    )

    text = text.replace(
        "if (d.user?.language && translations[d.user.language]) {",
        "if (d.user?.language && SUPPORTED_LANGS.includes(d.user.language)) {",
    )
    text = text.replace(
        "if (data.user?.language && translations[data.user.language]) {",
        "if (data.user?.language && SUPPORTED_LANGS.includes(data.user.language)) {",
    )

    if text != original:
        CONTEXTS.write_text(text, encoding="utf-8")
        return True
    return False


def patch_translations() -> bool:
    text = TRANSLATIONS.read_text(encoding="utf-8")
    original = text

    if "\n            pl: {" in text:
        print("translations.pl already exists; not inserting a second block")
        return False

    text = text.replace("DE/EN/FR/ES/PT/KO/IT/ZH", "DE/EN/FR/ES/PT/KO/IT/ZH/PL")

    en_start, en_end = find_object_block(text, "en")
    en_body = text[en_start + 1:en_end]

    translated_count = 0
    for key, value in TRANSLATED_KEYS.items():
        en_body, changed = replace_js_string_value(en_body, key, value)
        if changed:
            translated_count += 1

    pl_block = "\n            pl: {" + en_body + "\n            },"
    text = text[:en_end + 1] + "," + pl_block + text[en_end + 2:]

    if text != original:
        TRANSLATIONS.write_text(text, encoding="utf-8")
        print(f"Inserted translations.pl with {translated_count} starter Polish strings; remaining keys inherit English text in the copied map.")
        return True
    return False


def main() -> int:
    missing = [p for p in (CONTEXTS, TRANSLATIONS) if not p.exists()]
    if missing:
        for p in missing:
            print(f"Missing required file: {p}", file=sys.stderr)
        return 1

    changed_contexts = patch_contexts()
    changed_translations = patch_translations()

    if changed_contexts:
        print("Updated web/src/contexts.js")
    else:
        print("No changes needed in web/src/contexts.js")

    if changed_translations:
        print("Updated web/src/translations.js")
    else:
        print("No changes needed in web/src/translations.js")

    print("\nNext step: run web/Dev/build.sh to regenerate web/index.html, then test the language switcher.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
