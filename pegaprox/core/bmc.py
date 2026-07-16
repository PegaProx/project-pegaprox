# -*- coding: utf-8 -*-
"""In-band BMC / hardware health via local `ipmitool` (#609).

CREDENTIAL-FREE by design: instead of storing BMC network credentials and
reaching the BMC over its management network (the "crown-jewels" path — see the
Redfish opt-in phase), we SSH to the PVE node — access PegaProx already has for
lm-sensors / fencing — and run `ipmitool` LOCALLY there. The host talks to its
own BMC over the internal KCS interface (`/dev/ipmi0`) with no username/password
and without bridging the data network to the out-of-band management plane.

Read-only: only `sdr` / `sel` / `fru` / `dcmi` / `chassis status` are issued —
no power / virtual-media / firmware commands. Availability is opportunistic:
if `ipmitool` or `/dev/ipmi0` is absent we return `available=False` and change
nothing on the host (PegaProx never auto-enables the IPMI channel — the optional
install + the compliance acknowledgement are gated at the API layer).

Parsers are pure (text -> dict) so they can be fixture-tested without hardware.
"""

import re

# Markers so the whole read is ONE SSH round-trip; the orchestrator splits on them.
_M_SENS, _M_CHAS, _M_POWER, _M_FRU, _M_SEL = (
    '__PP_SENSORS__', '__PP_CHASSIS__', '__PP_POWER__', '__PP_FRU__', '__PP_SEL__')

# Single shell script run on the node. Bails early (no host mutation) when the
# in-band interface is missing, so we never touch a hardened box that removed it.
INBAND_PROBE_CMD = (
    "if ! command -v ipmitool >/dev/null 2>&1; then echo __PP_NO_IPMITOOL__; exit 0; fi; "
    "if ! ipmitool mc info >/dev/null 2>&1; then echo __PP_NO_BMC__; exit 0; fi; "
    "echo " + _M_SENS + "; ipmitool sdr elist 2>/dev/null; "
    "echo " + _M_CHAS + "; ipmitool chassis status 2>/dev/null; "
    "echo " + _M_POWER + "; ipmitool dcmi power reading 2>/dev/null; "
    "echo " + _M_FRU + "; ipmitool fru print 0 2>/dev/null; "
    "echo " + _M_SEL + "; ipmitool sel elist last 25 2>/dev/null"
)

# ipmitool sdr status tokens -> normalized health
_SDR_STATUS = {'ok': 'ok', 'ns': 'na', 'nc': 'warning', 'cr': 'critical', 'nr': 'critical'}

# --- In-band hardware-monitoring consent (#609) --------------------------------
# The feature must be explicitly enabled with a mandatory compliance acknowledgement
# before any read/install runs. The warning text lives HERE (single source) so the
# audit record can reference an exact version — bump the version when the wording
# materially changes and a stored ack below it re-prompts. (The network-Redfish
# opt-in is a separate, sharper warning with an enforced delay — a later phase.)
#
# The VERSION spans ALL languages: every _HW_CONSENT_TEXT entry is the SAME warning,
# v1, in a different language — they must stay semantically equivalent and be bumped
# together. version + require_delay_seconds are injected by hw_consent_warning() so
# they can never drift per-language. The acknowledged language is recorded alongside
# the version at ack time (which exact text the user actually saw).
HW_CONSENT_VERSION = 1
HW_CONSENT_DELAY_SECONDS = 0   # in-band: mandatory confirm, no forced wait (Redfish will use >0)

_HW_CONSENT_TEXT = {
    'en': {
        'title': 'Enable in-band hardware monitoring (IPMI)',
        'summary': 'PegaProx will read hardware health directly on each node through its local IPMI interface.',
        'points': [
            'Reads happen on the node over its local IPMI channel (/dev/ipmi0) — no BMC network credentials are stored, and the out-of-band management network is not accessed.',
            'Only read-only IPMI commands are issued (sensors, event log, FRU inventory, power). No power, virtual-media or firmware operations.',
            'If you enable installation, PegaProx will install the "ipmitool" package and may load the IPMI kernel modules on the node.',
            'On strictly hardened systems the local IPMI interface may be intentionally disabled under a least-functionality baseline. Enabling this here does not override that — where the interface is absent, PegaProx reports no data rather than re-enabling it.',
        ],
        'compliance_note': 'Enabling this may be relevant to your least-functionality and BMC-hardening controls (e.g. CMMC / NIST 800-171 3.4.6 and 3.1.5, DISA STIG BMC/OOB guidance). Confirm with your compliance owner. This is not legal advice.',
        'confirm_label': 'I understand, and I accept responsibility for enabling this',
    },
    'de': {
        'title': 'In-Band-Hardware-Überwachung (IPMI) aktivieren',
        'summary': 'PegaProx liest den Hardware-Zustand direkt auf jedem Node über dessen lokale IPMI-Schnittstelle.',
        'points': [
            'Die Lesevorgänge erfolgen auf dem Node über dessen lokalen IPMI-Kanal (/dev/ipmi0) — es werden keine BMC-Netzwerk-Zugangsdaten gespeichert, und auf das Out-of-Band-Management-Netzwerk wird nicht zugegriffen.',
            'Es werden ausschließlich lesende IPMI-Befehle ausgeführt (Sensoren, Ereignisprotokoll, FRU-Inventar, Stromverbrauch). Keine Power-, Virtual-Media- oder Firmware-Operationen.',
            'Wenn Sie die Installation aktivieren, installiert PegaProx das Paket „ipmitool“ und lädt ggf. die IPMI-Kernelmodule auf dem Node.',
            'Auf streng gehärteten Systemen kann die lokale IPMI-Schnittstelle bewusst im Rahmen einer Least-Functionality-Baseline deaktiviert sein. Die Aktivierung hier hebt das nicht auf — wo die Schnittstelle fehlt, meldet PegaProx keine Daten, statt sie wieder zu aktivieren.',
        ],
        'compliance_note': 'Die Aktivierung kann für Ihre Least-Functionality- und BMC-Härtungs-Kontrollen relevant sein (z. B. CMMC / NIST 800-171 3.4.6 und 3.1.5, DISA STIG BMC/OOB-Vorgaben). Stimmen Sie sich mit Ihrem Compliance-Verantwortlichen ab. Dies ist keine Rechtsberatung.',
        'confirm_label': 'Ich verstehe dies und übernehme die Verantwortung für die Aktivierung',
    },
    'fr': {
        'title': "Activer la surveillance matérielle en bande (IPMI)",
        'summary': "PegaProx lira l'état du matériel directement sur chaque nœud via son interface IPMI locale.",
        'points': [
            "Les lectures s'effectuent sur le nœud via son canal IPMI local (/dev/ipmi0) — aucun identifiant réseau du BMC n'est stocké et le réseau de gestion hors bande n'est pas utilisé.",
            "Seules des commandes IPMI en lecture seule sont émises (capteurs, journal d'événements, inventaire FRU, consommation). Aucune opération d'alimentation, de média virtuel ou de micrologiciel.",
            "Si vous activez l'installation, PegaProx installera le paquet « ipmitool » et pourra charger les modules noyau IPMI sur le nœud.",
            "Sur les systèmes fortement durcis, l'interface IPMI locale peut être volontairement désactivée dans le cadre d'une base de moindre fonctionnalité. L'activer ici ne l'annule pas — là où l'interface est absente, PegaProx ne renvoie aucune donnée plutôt que de la réactiver.",
        ],
        'compliance_note': "Cette activation peut concerner vos contrôles de moindre fonctionnalité et de durcissement du BMC (par ex. CMMC / NIST 800-171 3.4.6 et 3.1.5, recommandations DISA STIG BMC/OOB). Vérifiez avec votre responsable conformité. Ceci ne constitue pas un conseil juridique.",
        'confirm_label': "Je comprends et j'accepte la responsabilité de cette activation",
    },
    'es': {
        'title': 'Activar la supervisión de hardware en banda (IPMI)',
        'summary': 'PegaProx leerá el estado del hardware directamente en cada nodo a través de su interfaz IPMI local.',
        'points': [
            'Las lecturas se realizan en el nodo a través de su canal IPMI local (/dev/ipmi0): no se almacenan credenciales de red del BMC y no se accede a la red de gestión fuera de banda.',
            'Solo se emiten comandos IPMI de solo lectura (sensores, registro de eventos, inventario FRU, consumo). Ninguna operación de alimentación, medios virtuales o firmware.',
            'Si activa la instalación, PegaProx instalará el paquete «ipmitool» y podrá cargar los módulos del kernel IPMI en el nodo.',
            'En sistemas muy reforzados, la interfaz IPMI local puede estar deshabilitada intencionadamente bajo una base de funcionalidad mínima. Activarla aquí no anula eso: donde la interfaz no existe, PegaProx no informa de ningún dato en lugar de reactivarla.',
        ],
        'compliance_note': 'Activar esto puede ser relevante para sus controles de funcionalidad mínima y de refuerzo del BMC (p. ej., CMMC / NIST 800-171 3.4.6 y 3.1.5, directrices DISA STIG BMC/OOB). Confírmelo con su responsable de cumplimiento. Esto no es asesoramiento legal.',
        'confirm_label': 'Entiendo y acepto la responsabilidad de activar esto',
    },
    'pt': {
        'title': 'Ativar a monitorização de hardware em banda (IPMI)',
        'summary': 'O PegaProx lerá o estado do hardware diretamente em cada nó através da sua interface IPMI local.',
        'points': [
            'As leituras são feitas no nó através do seu canal IPMI local (/dev/ipmi0) — não são armazenadas credenciais de rede do BMC e a rede de gestão fora de banda não é acedida.',
            'Apenas são emitidos comandos IPMI de leitura (sensores, registo de eventos, inventário FRU, consumo). Nenhuma operação de energia, media virtual ou firmware.',
            'Se ativar a instalação, o PegaProx instalará o pacote «ipmitool» e poderá carregar os módulos de kernel IPMI no nó.',
            'Em sistemas fortemente reforçados, a interface IPMI local pode estar intencionalmente desativada sob uma base de funcionalidade mínima. Ativá-la aqui não anula isso — onde a interface não existe, o PegaProx não devolve dados em vez de a reativar.',
        ],
        'compliance_note': 'Ativar isto pode ser relevante para os seus controlos de funcionalidade mínima e de reforço do BMC (por ex., CMMC / NIST 800-171 3.4.6 e 3.1.5, orientações DISA STIG BMC/OOB). Confirme com o seu responsável de conformidade. Isto não constitui aconselhamento jurídico.',
        'confirm_label': 'Compreendo e aceito a responsabilidade por ativar isto',
    },
    'ko': {
        'title': '인밴드 하드웨어 모니터링(IPMI) 활성화',
        'summary': 'PegaProx는 각 노드의 로컬 IPMI 인터페이스를 통해 하드웨어 상태를 직접 읽습니다.',
        'points': [
            '읽기는 노드의 로컬 IPMI 채널(/dev/ipmi0)을 통해 수행됩니다. BMC 네트워크 자격 증명은 저장되지 않으며, 대역 외 관리 네트워크에 접근하지 않습니다.',
            '읽기 전용 IPMI 명령만 실행됩니다(센서, 이벤트 로그, FRU 인벤토리, 전력). 전원, 가상 미디어 또는 펌웨어 작업은 수행하지 않습니다.',
            '설치를 활성화하면 PegaProx가 노드에 "ipmitool" 패키지를 설치하며, IPMI 커널 모듈을 로드할 수도 있습니다.',
            '강력하게 강화된 시스템에서는 최소 기능 기준에 따라 로컬 IPMI 인터페이스가 의도적으로 비활성화되어 있을 수 있습니다. 여기서 활성화하더라도 이를 무효화하지 않습니다. 인터페이스가 없는 경우 PegaProx는 이를 다시 활성화하지 않고 데이터를 보고하지 않습니다.',
        ],
        'compliance_note': '이 기능을 활성화하는 것은 최소 기능 및 BMC 강화 통제(예: CMMC / NIST 800-171 3.4.6 및 3.1.5, DISA STIG BMC/OOB 지침)와 관련될 수 있습니다. 규정 준수 책임자와 확인하십시오. 이것은 법률 자문이 아닙니다.',
        'confirm_label': '이해했으며 이 기능을 활성화하는 것에 대한 책임을 수락합니다',
    },
    'it': {
        'title': "Abilitare il monitoraggio hardware in banda (IPMI)",
        'summary': "PegaProx leggerà lo stato dell'hardware direttamente su ogni nodo tramite la sua interfaccia IPMI locale.",
        'points': [
            "Le letture avvengono sul nodo tramite il suo canale IPMI locale (/dev/ipmi0): non vengono memorizzate credenziali di rete del BMC e la rete di gestione fuori banda non viene utilizzata.",
            "Vengono emessi solo comandi IPMI di sola lettura (sensori, registro eventi, inventario FRU, consumo). Nessuna operazione di alimentazione, supporti virtuali o firmware.",
            "Se abiliti l'installazione, PegaProx installerà il pacchetto « ipmitool » e potrà caricare i moduli kernel IPMI sul nodo.",
            "Su sistemi fortemente irrobustiti, l'interfaccia IPMI locale può essere disattivata intenzionalmente secondo una baseline di funzionalità minima. Abilitarla qui non annulla questo — dove l'interfaccia è assente, PegaProx non restituisce dati anziché riattivarla.",
        ],
        'compliance_note': "L'abilitazione può essere rilevante per i tuoi controlli di funzionalità minima e di irrobustimento del BMC (ad es. CMMC / NIST 800-171 3.4.6 e 3.1.5, linee guida DISA STIG BMC/OOB). Verifica con il tuo responsabile della conformità. Questo non è un parere legale.",
        'confirm_label': "Comprendo e accetto la responsabilità di abilitare questa funzione",
    },
}


def hw_consent_warning(lang=None):
    """The consent warning for `lang` (falls back to English), with the shared
    version + delay injected so they can never drift per-language."""
    base = (lang or 'en').split('-')[0].lower()
    text = _HW_CONSENT_TEXT.get(base) or _HW_CONSENT_TEXT['en']
    return {'version': HW_CONSENT_VERSION, 'require_delay_seconds': HW_CONSENT_DELAY_SECONDS, **text}


# Backward-compat English alias for callers/tests that referenced the old constant.
HW_CONSENT_WARNING = hw_consent_warning('en')


# --- Out-of-band Redfish consent (#609 phase 3) --------------------------------
# A SEPARATE, sharper opt-in from the in-band one: Redfish crosses onto the
# management network and uses STORED CREDENTIALS, so it carries an enforced
# 5-second delay before the confirm button can be pressed (require_delay_seconds).
# Same versioning contract: one v1 warning in 7 languages, bumped together.
REDFISH_CONSENT_VERSION = 1
REDFISH_CONSENT_DELAY_SECONDS = 5   # out-of-band: sharper warning, enforced wait

_REDFISH_CONSENT_TEXT = {
    'en': {
        'title': "Enable out-of-band hardware monitoring (Redfish)",
        'summary': "PegaProx will read hardware health over the management network using the BMC Redfish API, with credentials you store per node.",
        'points': [
            "This is out-of-band and CREDENTIALED: PegaProx stores a BMC username and password per node and connects to the BMC over its management network — unlike in-band IPMI, which uses no credentials.",
            "Only read-only Redfish requests are made (system status, thermal, power, event log). No power, virtual-media, BIOS or firmware operations.",
            "Connecting the data plane to the out-of-band management network widens your attack surface. Ensure this crossing is acceptable under your network-segmentation and boundary-protection controls.",
            "BMC credentials are stored encrypted, but a compromise of PegaProx would expose management-plane access. Use a dedicated read-only BMC account where your BMC supports it.",
        ],
        'compliance_note': "Out-of-band monitoring may be relevant to your boundary-protection and least-privilege controls (e.g. CMMC / NIST 800-171 3.13.1, 3.13.2 and 3.1.5, DISA STIG BMC/OOB guidance). Confirm with your compliance owner. This is not legal advice.",
        'confirm_label': "I understand the out-of-band and credential risk, and I accept responsibility for enabling this",
    },
    'de': {
        'title': "Out-of-Band-Hardware-Überwachung (Redfish) aktivieren",
        'summary': "PegaProx liest den Hardware-Zustand über das Management-Netzwerk mittels BMC-Redfish-API, mit Zugangsdaten, die Sie pro Node speichern.",
        'points': [
            "Dies ist Out-of-Band und ZUGANGSDATEN-BASIERT: PegaProx speichert pro Node BMC-Benutzername und -Passwort und verbindet sich mit dem BMC über dessen Management-Netzwerk — anders als In-Band-IPMI, das keine Zugangsdaten nutzt.",
            "Es werden ausschließlich lesende Redfish-Anfragen gestellt (Systemstatus, Thermik, Strom, Ereignisprotokoll). Keine Power-, Virtual-Media-, BIOS- oder Firmware-Operationen.",
            "Die Verbindung der Datenebene mit dem Out-of-Band-Management-Netzwerk vergrößert Ihre Angriffsfläche. Stellen Sie sicher, dass diese Überschreitung mit Ihren Netzsegmentierungs- und Boundary-Protection-Kontrollen vereinbar ist.",
            "BMC-Zugangsdaten werden verschlüsselt gespeichert, doch eine Kompromittierung von PegaProx würde Zugriff auf die Management-Ebene offenlegen. Verwenden Sie nach Möglichkeit ein dediziertes, nur-lesendes BMC-Konto.",
        ],
        'compliance_note': "Out-of-Band-Überwachung kann für Ihre Boundary-Protection- und Least-Privilege-Kontrollen relevant sein (z. B. CMMC / NIST 800-171 3.13.1, 3.13.2 und 3.1.5, DISA STIG BMC/OOB-Vorgaben). Stimmen Sie sich mit Ihrem Compliance-Verantwortlichen ab. Dies ist keine Rechtsberatung.",
        'confirm_label': "Ich verstehe das Out-of-Band- und Zugangsdaten-Risiko und übernehme die Verantwortung für die Aktivierung",
    },
    'fr': {
        'title': "Activer la surveillance matérielle hors bande (Redfish)",
        'summary': "PegaProx lira l'état du matériel via le réseau de gestion à l'aide de l'API Redfish du BMC, avec des identifiants que vous stockez par nœud.",
        'points': [
            "Ceci est hors bande et BASÉ SUR DES IDENTIFIANTS : PegaProx stocke un nom d'utilisateur et un mot de passe BMC par nœud et se connecte au BMC via son réseau de gestion — contrairement à l'IPMI en bande, qui n'utilise aucun identifiant.",
            "Seules des requêtes Redfish en lecture seule sont émises (état du système, thermique, alimentation, journal d'événements). Aucune opération d'alimentation, de média virtuel, de BIOS ou de micrologiciel.",
            "Relier le plan de données au réseau de gestion hors bande élargit votre surface d'attaque. Assurez-vous que ce franchissement est acceptable selon vos contrôles de segmentation réseau et de protection des périmètres.",
            "Les identifiants BMC sont stockés chiffrés, mais une compromission de PegaProx exposerait l'accès au plan de gestion. Utilisez un compte BMC dédié en lecture seule lorsque votre BMC le permet.",
        ],
        'compliance_note': "La surveillance hors bande peut concerner vos contrôles de protection des périmètres et de moindre privilège (par ex. CMMC / NIST 800-171 3.13.1, 3.13.2 et 3.1.5, recommandations DISA STIG BMC/OOB). Vérifiez avec votre responsable conformité. Ceci ne constitue pas un conseil juridique.",
        'confirm_label': "Je comprends le risque hors bande et lié aux identifiants, et j'accepte la responsabilité de cette activation",
    },
    'es': {
        'title': "Activar la supervisión de hardware fuera de banda (Redfish)",
        'summary': "PegaProx leerá el estado del hardware a través de la red de gestión mediante la API Redfish del BMC, con credenciales que usted almacena por nodo.",
        'points': [
            "Esto es fuera de banda y BASADO EN CREDENCIALES: PegaProx almacena un usuario y una contraseña de BMC por nodo y se conecta al BMC a través de su red de gestión, a diferencia del IPMI en banda, que no usa credenciales.",
            "Solo se realizan solicitudes Redfish de solo lectura (estado del sistema, térmica, alimentación, registro de eventos). Ninguna operación de encendido, medios virtuales, BIOS o firmware.",
            "Conectar el plano de datos con la red de gestión fuera de banda amplía su superficie de ataque. Asegúrese de que este cruce sea aceptable según sus controles de segmentación de red y de protección del perímetro.",
            "Las credenciales del BMC se almacenan cifradas, pero un compromiso de PegaProx expondría el acceso al plano de gestión. Use una cuenta de BMC dedicada de solo lectura cuando su BMC lo permita.",
        ],
        'compliance_note': "La supervisión fuera de banda puede ser relevante para sus controles de protección del perímetro y de mínimo privilegio (p. ej., CMMC / NIST 800-171 3.13.1, 3.13.2 y 3.1.5, directrices DISA STIG BMC/OOB). Confírmelo con su responsable de cumplimiento. Esto no es asesoramiento legal.",
        'confirm_label': "Entiendo el riesgo fuera de banda y de credenciales, y acepto la responsabilidad de activar esto",
    },
    'pt': {
        'title': "Ativar a monitorização de hardware fora de banda (Redfish)",
        'summary': "O PegaProx lerá o estado do hardware através da rede de gestão usando a API Redfish do BMC, com credenciais que você armazena por nó.",
        'points': [
            "Isto é fora de banda e BASEADO EM CREDENCIAIS: o PegaProx armazena um nome de utilizador e uma palavra-passe de BMC por nó e liga-se ao BMC através da sua rede de gestão, ao contrário do IPMI em banda, que não usa credenciais.",
            "Apenas são feitos pedidos Redfish de leitura (estado do sistema, térmica, energia, registo de eventos). Nenhuma operação de energia, media virtual, BIOS ou firmware.",
            "Ligar o plano de dados à rede de gestão fora de banda aumenta a sua superfície de ataque. Garanta que esta travessia é aceitável de acordo com os seus controlos de segmentação de rede e de proteção do perímetro.",
            "As credenciais do BMC são armazenadas cifradas, mas um comprometimento do PegaProx exporia o acesso ao plano de gestão. Use uma conta de BMC dedicada só de leitura quando o seu BMC o permitir.",
        ],
        'compliance_note': "A monitorização fora de banda pode ser relevante para os seus controlos de proteção do perímetro e de menor privilégio (por ex., CMMC / NIST 800-171 3.13.1, 3.13.2 e 3.1.5, orientações DISA STIG BMC/OOB). Confirme com o seu responsável de conformidade. Isto não constitui aconselhamento jurídico.",
        'confirm_label': "Compreendo o risco fora de banda e de credenciais, e aceito a responsabilidade por ativar isto",
    },
    'ko': {
        'title': "대역 외 하드웨어 모니터링(Redfish) 활성화",
        'summary': "PegaProx는 노드별로 저장한 자격 증명으로 BMC Redfish API를 사용하여 관리 네트워크를 통해 하드웨어 상태를 읽습니다.",
        'points': [
            "이것은 대역 외이며 자격 증명 기반입니다. PegaProx는 노드별로 BMC 사용자 이름과 비밀번호를 저장하고 관리 네트워크를 통해 BMC에 연결합니다. 자격 증명을 사용하지 않는 대역 내 IPMI와 다릅니다.",
            "읽기 전용 Redfish 요청만 수행됩니다(시스템 상태, 온도, 전원, 이벤트 로그). 전원, 가상 미디어, BIOS 또는 펌웨어 작업은 수행하지 않습니다.",
            "데이터 평면을 대역 외 관리 네트워크에 연결하면 공격 표면이 넓어집니다. 이 경계 통과가 네트워크 분할 및 경계 보호 통제에 부합하는지 확인하십시오.",
            "BMC 자격 증명은 암호화되어 저장되지만, PegaProx가 침해되면 관리 평면 접근이 노출됩니다. BMC가 지원하는 경우 전용 읽기 전용 BMC 계정을 사용하십시오.",
        ],
        'compliance_note': "대역 외 모니터링은 경계 보호 및 최소 권한 통제(예: CMMC / NIST 800-171 3.13.1, 3.13.2 및 3.1.5, DISA STIG BMC/OOB 지침)와 관련될 수 있습니다. 규정 준수 책임자와 확인하십시오. 이것은 법률 자문이 아닙니다.",
        'confirm_label': "대역 외 및 자격 증명 위험을 이해했으며 활성화에 대한 책임을 수락합니다",
    },
    'it': {
        'title': "Abilitare il monitoraggio hardware fuori banda (Redfish)",
        'summary': "PegaProx leggerà lo stato dell'hardware tramite la rete di gestione usando l'API Redfish del BMC, con credenziali che memorizzi per ogni nodo.",
        'points': [
            "Questo è fuori banda e BASATO SU CREDENZIALI: PegaProx memorizza nome utente e password del BMC per ogni nodo e si connette al BMC tramite la sua rete di gestione, a differenza dell'IPMI in banda, che non usa credenziali.",
            "Vengono effettuate solo richieste Redfish di sola lettura (stato del sistema, termica, alimentazione, registro eventi). Nessuna operazione di alimentazione, supporti virtuali, BIOS o firmware.",
            "Collegare il piano dati alla rete di gestione fuori banda amplia la superficie di attacco. Assicurati che questo attraversamento sia accettabile secondo i tuoi controlli di segmentazione della rete e di protezione del perimetro.",
            "Le credenziali del BMC sono memorizzate cifrate, ma una compromissione di PegaProx esporrebbe l'accesso al piano di gestione. Usa un account BMC dedicato di sola lettura quando il tuo BMC lo consente.",
        ],
        'compliance_note': "Il monitoraggio fuori banda può essere rilevante per i tuoi controlli di protezione del perimetro e di privilegio minimo (ad es. CMMC / NIST 800-171 3.13.1, 3.13.2 e 3.1.5, linee guida DISA STIG BMC/OOB). Verifica con il tuo responsabile della conformità. Questo non è un parere legale.",
        'confirm_label': "Comprendo il rischio fuori banda e legato alle credenziali, e accetto la responsabilità di abilitare questa funzione",
    },
}


def redfish_consent_warning(lang=None):
    """The out-of-band Redfish consent warning for `lang` (falls back to English),
    with the shared version + the enforced 5s delay injected."""
    base = (lang or 'en').split('-')[0].lower()
    text = _REDFISH_CONSENT_TEXT.get(base) or _REDFISH_CONSENT_TEXT['en']
    return {'version': REDFISH_CONSENT_VERSION, 'require_delay_seconds': REDFISH_CONSENT_DELAY_SECONDS, **text}


def _num(s):
    """First numeric token in a string as float, or None."""
    m = re.search(r'-?\d+(?:\.\d+)?', s or '')
    return float(m.group(0)) if m else None


def parse_sensors(text):
    """`ipmitool sdr elist` -> [{name, kind, value, unit, reading, status}].

    Line shape: ``Name | 01h | ok | 3.1 | 45 degrees C`` (pipe-separated, 5 cols).
    kind is derived from the reading unit (temp / fan / volt / power / other).
    """
    out = []
    for line in (text or '').splitlines():
        if '|' not in line:
            continue
        cols = [c.strip() for c in line.split('|')]
        if len(cols) < 5:
            continue
        name, status_tok, reading = cols[0], cols[2].lower(), cols[4]
        if not name:
            continue
        rl = reading.lower()
        if 'degrees c' in rl or rl.endswith(' c') or 'degree' in rl:
            kind, unit = 'temp', '°C'
        elif 'rpm' in rl:
            kind, unit = 'fan', 'RPM'
        elif 'volt' in rl:
            kind, unit = 'volt', 'V'
        elif 'watt' in rl:
            kind, unit = 'power', 'W'
        elif 'amp' in rl:
            kind, unit = 'current', 'A'
        else:
            kind, unit = 'discrete', ''
        out.append({
            'name': name,
            'kind': kind,
            'value': _num(reading) if kind not in ('discrete',) else None,
            'unit': unit,
            'reading': reading,
            'status': _SDR_STATUS.get(status_tok, status_tok or 'na'),
        })
    return out


def parse_chassis(text):
    """`ipmitool chassis status` -> {power, intrusion, fault, ...}."""
    d = {}
    for line in (text or '').splitlines():
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        k, v = k.strip().lower(), v.strip()
        if k == 'system power':
            d['power'] = v
        elif 'intrusion' in k:
            d['intrusion'] = v
        elif 'fault' in k and v:
            d.setdefault('faults', []).append(f"{k}: {v}")
    return d


def parse_power(text):
    """`ipmitool dcmi power reading` -> instantaneous watts (float) or None."""
    for line in (text or '').splitlines():
        if 'instantaneous power reading' in line.lower():
            return _num(line)
    return None


def parse_fru(text):
    """`ipmitool fru print 0` -> {manufacturer, product, serial, part, board_*}."""
    kv = {}
    for line in (text or '').splitlines():
        if ':' not in line:
            continue
        k, v = line.split(':', 1)
        kv[k.strip().lower()] = v.strip()
    g = lambda *keys: next((kv[k] for k in keys if kv.get(k)), '')
    return {
        'manufacturer': g('product manufacturer', 'board mfg', 'chassis manufacturer'),
        'product': g('product name', 'board product'),
        'serial': g('product serial', 'board serial', 'chassis serial'),
        'part': g('product part number', 'board part number'),
    }


def parse_sel(text, limit=25):
    """`ipmitool sel elist` -> recent hardware events (newest first).

    Line shape: ``12 | 07/14/2026 | 21:30:05 | Power Supply PSU2 | Failure detected | Asserted``
    """
    events = []
    for line in (text or '').splitlines():
        if '|' not in line:
            continue
        cols = [c.strip() for c in line.split('|')]
        if len(cols) < 4:
            continue
        # cols: id, date, time, sensor, [description], [state]
        ts = (cols[1] + ' ' + cols[2]).strip() if len(cols) >= 3 else ''
        sensor = cols[3] if len(cols) > 3 else ''
        desc = cols[4] if len(cols) > 4 else ''
        state = cols[5] if len(cols) > 5 else ''
        low = (desc + ' ' + state + ' ' + sensor).lower()
        sev = 'critical' if any(w in low for w in ('fail', 'critical', 'fault', 'error', 'lost')) \
            else 'warning' if any(w in low for w in ('warn', 'non-critical', 'degrad', 'intrusion')) \
            else 'info'
        events.append({'id': cols[0], 'time': ts, 'sensor': sensor,
                       'description': (desc + (' — ' + state if state else '')).strip(' —'),
                       'severity': sev})
    events.reverse()  # newest first
    return events[:limit]


def _health_rollup(sensors, sel, chassis):
    """Overall node hardware health from the parsed pieces: ok / warning / critical."""
    if any(s['status'] == 'critical' for s in sensors) or \
       any(e['severity'] == 'critical' for e in sel) or \
       (chassis.get('intrusion', '').lower() not in ('', 'inactive', 'not present', 'disabled')):
        return 'critical'
    if any(s['status'] == 'warning' for s in sensors) or \
       any(e['severity'] == 'warning' for e in sel):
        return 'warning'
    return 'ok'


def parse_inband(raw):
    """Split the marker-delimited SSH output and parse every section.

    Returns {'available': bool, 'reason'?: str, 'health', 'sensors', 'chassis',
    'power_w', 'fru', 'events'}.
    """
    raw = raw or ''
    if '__PP_NO_IPMITOOL__' in raw:
        return {'available': False, 'reason': 'ipmitool is not installed on this node'}
    if '__PP_NO_BMC__' in raw:
        return {'available': False, 'reason': 'no in-band BMC / IPMI interface (/dev/ipmi0) on this node'}

    def section(marker, nxt):
        try:
            body = raw.split(marker, 1)[1]
        except IndexError:
            return ''
        for m in nxt:
            if m in body:
                body = body.split(m, 1)[0]
        return body

    sensors = parse_sensors(section(_M_SENS, [_M_CHAS, _M_POWER, _M_FRU, _M_SEL]))
    chassis = parse_chassis(section(_M_CHAS, [_M_POWER, _M_FRU, _M_SEL]))
    power_w = parse_power(section(_M_POWER, [_M_FRU, _M_SEL]))
    fru = parse_fru(section(_M_FRU, [_M_SEL]))
    events = parse_sel(section(_M_SEL, []))
    if not (sensors or chassis or events or power_w is not None or any(fru.values())):
        return {'available': False, 'reason': 'in-band BMC returned no data'}
    return {
        'available': True,
        'health': _health_rollup(sensors, sel=events, chassis=chassis),
        'sensors': sensors,
        'chassis': chassis,
        'power_w': power_w,
        'fru': fru,
        'events': events,
    }


def read_node_bmc_inband(mgr, node, timeout=15):
    """Orchestrator: SSH to `node`, run the read-only ipmitool probe, parse it.

    Credential-free (in-band). Returns the parse_inband() dict, or an
    {'available': False, 'reason': ...} on any SSH/resolution failure. Never
    mutates the node. The compliance acknowledgement + optional install are
    enforced by the caller (API layer), not here.
    """
    try:
        ip = mgr._get_node_ip(node)
        if not ip:
            return {'available': False, 'reason': f'no SSH-reachable IP for node {node}'}
        user = getattr(mgr.config, 'ssh_user', None) or 'root'
        raw = mgr._ssh_run_command_output(ip, user, INBAND_PROBE_CMD, timeout=timeout)
        if raw is None or not raw.strip():
            return {'available': False, 'reason': 'no response from node (SSH unavailable?)'}
        return parse_inband(raw)
    except Exception as e:  # noqa: BLE001 — surface as unavailable, never raise into the route
        return {'available': False, 'reason': f'in-band BMC read failed: {e}'}
