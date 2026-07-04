"""Compliance framework control mappings for PegaProx hardening checks.

Maps internal hardening control IDs (e.g. 'pam_faillock') to the corresponding
control references in major compliance frameworks.

This is best-effort technical coverage mapping, NOT a substitute for a formal
compliance audit. Every audit deliverable should be reviewed by a qualified
compliance SME against the current revision of the applicable framework.

Frameworks covered:
- CMMC L1                        (FAR 52.204-21, 17 basic safeguarding requirements)
- CMMC L2 / NIST SP 800-171 R2   (110 controls, 14 families)
- NIST SP 800-53 R5 (Mod)        (federal civilian baseline)
- DISA STIG (RHEL 9 / Ubuntu 22) (where a direct rule is known; STIG rules
                                  are versioned, refs may need refresh per release)
- ISO/IEC 27001:2022 Annex A     (93 controls, 4 themes)
- BSI IT-Grundschutz Kompendium  (modules SYS / OPS / NET / DER / CON / APP)
- VS-NfD                         (largely a profile over BSI Grundschutz +
                                  PegaProx-specific informational checks)

Where a control has no direct mapping in a given framework, the entry is
omitted (do NOT fabricate refs). The PDF generator surfaces 'no direct mapping'
explicitly so reviewers see the gap rather than a fake reference.
"""

# Family code → human-readable label.
# Codes are framework-specific; NIST 800-171 and 800-53 use the same letters
# for the most part (AC, AU, CM, IA, SC, SI etc.).
FAMILY_LABELS = {
    'AC': 'Access Control',
    'AT': 'Awareness and Training',
    'AU': 'Audit and Accountability',
    'CA': 'Assessment, Authorization, and Monitoring',
    'CM': 'Configuration Management',
    'CP': 'Contingency Planning',
    'IA': 'Identification and Authentication',
    'IR': 'Incident Response',
    'MA': 'Maintenance',
    'MP': 'Media Protection',
    'PE': 'Physical Protection',
    'PL': 'Planning',
    'PS': 'Personnel Security',
    'RA': 'Risk Assessment',
    'SA': 'System and Services Acquisition',
    'SC': 'System and Communications Protection',
    'SI': 'System and Information Integrity',
    'SR': 'Supply Chain Risk Management',
    # ISO 27001:2022 Annex A themes
    'A.5': 'Organizational controls',
    'A.6': 'People controls',
    'A.7': 'Physical controls',
    'A.8': 'Technological controls',
    # BSI IT-Grundschutz layer codes (subset)
    'SYS': 'IT-Systeme',
    'OPS': 'Betrieb',
    'NET': 'Netze und Kommunikation',
    'DER': 'Detektion und Reaktion',
    'CON': 'Konzeption und Vorgehensweise',
    # ANSSI-BP-028 section codes (French) — used by Diffusion Restreinte + RGS
    'materiel': 'Configuration matérielle',
    'noyau': 'Configuration du noyau Linux',
    'partitionnement': 'Partitionnement système',
    'comptes': "Comptes d'accès",
    'controle_acces': "Contrôle d'accès",
    'fichiers': 'Fichiers et répertoires',
    'paquets': 'Gestion des paquets',
    'services': 'Configuration des services',
    'journalisation': 'Journalisation',
    'surveillance': 'Surveillance du système de fichiers',
    'APP': 'Anwendungen',
    # Catch-all
    'OTHER': 'Other / Cross-cutting',
}


# ──────────────────────────────────────────────────────────────────────────
# Per-framework: { internal_control_id: [ {ref, title, family} ... ] }
#
# An internal control may map to multiple framework controls (1:N) — the
# common case for things like ssh_crypto which covers both crypto strength
# (IA / SC) and integrity protection (SC).
# ──────────────────────────────────────────────────────────────────────────

# CMMC Level 2 = NIST SP 800-171 R2 mapping. Refs use the CMMC notation
# (e.g. AC.L2-3.1.8) which embeds the NIST 800-171 control number (3.1.8).
CMMC_L2_NIST_171 = {
    'pam_faillock': [
        {'ref': 'AC.L2-3.1.8', 'family': 'AC', 'title': 'Limit unsuccessful logon attempts'},
    ],
    'session_limit': [
        {'ref': 'AC.L2-3.1.10', 'family': 'AC', 'title': 'Use session lock with pattern-hiding displays'},
        {'ref': 'AC.L2-3.1.11', 'family': 'AC', 'title': 'Terminate user session after defined condition'},
    ],
    'shell_timeout': [
        {'ref': 'AC.L2-3.1.11', 'family': 'AC', 'title': 'Terminate user session after defined condition'},
    ],
    'login_banners': [
        {'ref': 'AC.L2-3.1.9', 'family': 'AC', 'title': 'Provide privacy and security notices consistent with applicable CUI rules'},
    ],
    'inactive_accounts': [
        {'ref': 'IA.L2-3.5.6', 'family': 'IA', 'title': 'Disable identifiers after a defined period of inactivity'},
    ],
    'pw_quality': [
        {'ref': 'IA.L2-3.5.7', 'family': 'IA', 'title': 'Enforce minimum password complexity and change of characters when new passwords are created'},
    ],
    'pw_history': [
        {'ref': 'IA.L2-3.5.8', 'family': 'IA', 'title': 'Prohibit password reuse for a specified number of generations'},
    ],
    'pw_aging': [
        {'ref': 'IA.L2-3.5.6', 'family': 'IA', 'title': 'Disable identifiers after a defined period of inactivity'},
    ],
    'pw_hash_rounds': [
        {'ref': 'IA.L2-3.5.10', 'family': 'IA', 'title': 'Store and transmit only cryptographically-protected passwords'},
    ],
    'ssh_crypto': [
        {'ref': 'IA.L2-3.5.10', 'family': 'IA', 'title': 'Store and transmit only cryptographically-protected passwords'},
        {'ref': 'SC.L2-3.13.11', 'family': 'SC', 'title': 'Employ FIPS-validated cryptography when used to protect the confidentiality of CUI'},
    ],
    'ssh_perms': [
        {'ref': 'AC.L2-3.1.5', 'family': 'AC', 'title': 'Employ the principle of least privilege'},
        {'ref': 'CM.L2-3.4.6', 'family': 'CM', 'title': 'Employ the principle of least functionality'},
    ],
    'file_perms': [
        {'ref': 'AC.L2-3.1.5', 'family': 'AC', 'title': 'Employ the principle of least privilege'},
        {'ref': 'AU.L2-3.3.8', 'family': 'AU', 'title': 'Protect audit information and audit logging tools from unauthorized access'},
    ],
    'default_umask': [
        {'ref': 'AC.L2-3.1.5', 'family': 'AC', 'title': 'Employ the principle of least privilege'},
    ],
    'apparmor': [
        {'ref': 'AC.L2-3.1.5', 'family': 'AC', 'title': 'Employ the principle of least privilege'},
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
    ],
    'fs_modules': [
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
        {'ref': 'CM.L2-3.4.6', 'family': 'CM', 'title': 'Employ the principle of least functionality'},
    ],
    'usb_storage': [
        {'ref': 'MP.L2-3.8.7', 'family': 'MP', 'title': 'Control the use of removable media on system components'},
        {'ref': 'MP.L2-3.8.8', 'family': 'MP', 'title': 'Prohibit the use of portable storage devices when such devices have no identifiable owner'},
    ],
    'mount_options': [
        {'ref': 'CM.L2-3.4.6', 'family': 'CM', 'title': 'Employ the principle of least functionality'},
        {'ref': 'SC.L2-3.13.4', 'family': 'SC', 'title': 'Prevent unauthorized and unintended information transfer via shared system resources'},
    ],
    'core_dumps': [
        {'ref': 'SC.L2-3.13.16', 'family': 'SC', 'title': 'Protect the confidentiality of CUI at rest'},
    ],
    'audit_rules': [
        {'ref': 'AU.L2-3.3.1', 'family': 'AU', 'title': 'Create and retain system audit logs and records'},
        {'ref': 'AU.L2-3.3.2', 'family': 'AU', 'title': 'Ensure that the actions of individual system users can be uniquely traced'},
    ],
    'audit_boot': [
        {'ref': 'AU.L2-3.3.4', 'family': 'AU', 'title': 'Alert in the event of an audit logging process failure'},
    ],
    'auditd_service': [
        {'ref': 'AU.L2-3.3.1', 'family': 'AU', 'title': 'Create and retain system audit logs and records'},
    ],
    'audit_immutable': [
        {'ref': 'AU.L2-3.3.8', 'family': 'AU', 'title': 'Protect audit information and audit logging tools from unauthorized access'},
        {'ref': 'AU.L2-3.3.9', 'family': 'AU', 'title': 'Limit management of audit logging functionality to a subset of privileged users'},
    ],
    'aide_audit_protect': [
        {'ref': 'AU.L2-3.3.8', 'family': 'AU', 'title': 'Protect audit information and audit logging tools from unauthorized access'},
        {'ref': 'SI.L2-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws in a timely manner'},
    ],
    'journald': [
        {'ref': 'AU.L2-3.3.1', 'family': 'AU', 'title': 'Create and retain system audit logs and records'},
    ],
    'process_acct': [
        {'ref': 'AU.L2-3.3.1', 'family': 'AU', 'title': 'Create and retain system audit logs and records'},
    ],
    'sysstat': [
        {'ref': 'AU.L2-3.3.1', 'family': 'AU', 'title': 'Create and retain system audit logs and records'},
    ],
    'file_integrity': [
        {'ref': 'SI.L2-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws in a timely manner'},
        {'ref': 'CM.L2-3.4.1', 'family': 'CM', 'title': 'Establish and maintain baseline configurations'},
    ],
    'debsums': [
        {'ref': 'SI.L2-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws in a timely manner'},
        {'ref': 'CM.L2-3.4.1', 'family': 'CM', 'title': 'Establish and maintain baseline configurations'},
    ],
    'mem_protection': [
        {'ref': 'SI.L2-3.14.7', 'family': 'SI', 'title': 'Identify unauthorized use of organizational systems'},
    ],
    'sysctl_hardening': [
        {'ref': 'CM.L2-3.4.6', 'family': 'CM', 'title': 'Employ the principle of least functionality'},
        {'ref': 'SC.L2-3.13.4', 'family': 'SC', 'title': 'Prevent unauthorized and unintended information transfer via shared system resources'},
    ],
    'pkg_cleanup': [
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
        {'ref': 'CM.L2-3.4.8', 'family': 'CM', 'title': 'Apply deny-by-exception policy to prevent unauthorized software'},
    ],
    'remove_legacy_svcs': [
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
    ],
    'disable_services': [
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
    ],
    'net_protocols': [
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
        {'ref': 'SC.L2-3.13.6', 'family': 'SC', 'title': 'Deny network communications by default; allow by exception'},
    ],
    'restrict_compilers': [
        {'ref': 'CM.L2-3.4.7', 'family': 'CM', 'title': 'Restrict, disable, prevent the use of nonessential programs, functions, ports, protocols and services'},
    ],
    'cron_hardening': [
        {'ref': 'AC.L2-3.1.5', 'family': 'AC', 'title': 'Employ the principle of least privilege'},
    ],
    'pam_tmpdir': [
        {'ref': 'SC.L2-3.13.16', 'family': 'SC', 'title': 'Protect the confidentiality of CUI at rest'},
    ],
    'pve_fail2ban': [
        {'ref': 'SI.L2-3.14.6', 'family': 'SI', 'title': 'Monitor systems including network traffic to detect attacks and indicators'},
        {'ref': 'AC.L2-3.1.8', 'family': 'AC', 'title': 'Limit unsuccessful logon attempts'},
    ],
    'apt_show_versions': [
        {'ref': 'SI.L2-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws in a timely manner'},
    ],
    'backup_dns': [
        {'ref': 'SC.L2-3.13.6', 'family': 'SC', 'title': 'Deny network communications by default; allow by exception'},
    ],
    'postfix_banner': [
        {'ref': 'SC.L2-3.13.13', 'family': 'SC', 'title': 'Control and monitor the use of mobile code'},
    ],
}


# CMMC Level 1 (FAR 52.204-21 / NIST 800-171 subset). Uses a smaller subset
# of the NIST 800-171 controls focused on basic safeguarding of FCI.
# Refs use the FAR clause numbering (b)(1) through (b)(15).
CMMC_L1 = {
    'pam_faillock': [
        {'ref': 'AC.L1-3.1.20', 'family': 'AC', 'title': 'Verify and control connections to external systems'},
    ],
    'login_banners': [
        {'ref': 'AC.L1-3.1.22', 'family': 'AC', 'title': 'Control posted information on publicly accessible systems'},
    ],
    'pw_quality': [
        {'ref': 'IA.L1-3.5.1', 'family': 'IA', 'title': 'Identify users, processes, and devices'},
        {'ref': 'IA.L1-3.5.2', 'family': 'IA', 'title': 'Authenticate identities of users, processes, devices'},
    ],
    'pw_hash_rounds': [
        {'ref': 'IA.L1-3.5.2', 'family': 'IA', 'title': 'Authenticate identities of users, processes, devices'},
    ],
    'ssh_crypto': [
        {'ref': 'IA.L1-3.5.2', 'family': 'IA', 'title': 'Authenticate identities of users, processes, devices'},
    ],
    'ssh_perms': [
        {'ref': 'AC.L1-3.1.1', 'family': 'AC', 'title': 'Limit system access to authorized users'},
    ],
    'file_perms': [
        {'ref': 'AC.L1-3.1.1', 'family': 'AC', 'title': 'Limit system access to authorized users'},
    ],
    'apparmor': [
        {'ref': 'AC.L1-3.1.1', 'family': 'AC', 'title': 'Limit system access to authorized users'},
    ],
    # NS: audit/accountability is NOT a CMMC Level 1 domain — L1 covers only
    # AC / IA / MP / PE / SC / SI (17 practices from FAR 52.204-21). audit_rules
    # and auditd_service map to AU.L2-3.3.1 at Level 2 (see CMMC_L2_NIST_171), so
    # they're intentionally absent here.
    'mem_protection': [
        {'ref': 'SI.L1-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws'},
    ],
    'file_integrity': [
        {'ref': 'SI.L1-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws'},
    ],
    'debsums': [
        {'ref': 'SI.L1-3.14.1', 'family': 'SI', 'title': 'Identify, report, and correct system flaws'},
    ],
    'sysctl_hardening': [
        {'ref': 'SC.L1-3.13.5', 'family': 'SC', 'title': 'Implement subnetworks for publicly accessible system components'},
    ],
}


# NIST SP 800-53 Revision 5 mapping (Mod baseline)
NIST_800_53 = {
    'pam_faillock': [
        {'ref': 'AC-7', 'family': 'AC', 'title': 'Unsuccessful Logon Attempts'},
    ],
    'session_limit': [
        {'ref': 'AC-12', 'family': 'AC', 'title': 'Session Termination'},
        {'ref': 'AC-11', 'family': 'AC', 'title': 'Device Lock'},
    ],
    'shell_timeout': [
        {'ref': 'AC-12', 'family': 'AC', 'title': 'Session Termination'},
    ],
    'login_banners': [
        {'ref': 'AC-8', 'family': 'AC', 'title': 'System Use Notification'},
    ],
    'inactive_accounts': [
        {'ref': 'AC-2(3)', 'family': 'AC', 'title': 'Account Management — Disable Accounts'},
    ],
    'pw_quality': [
        {'ref': 'IA-5(1)', 'family': 'IA', 'title': 'Authenticator Management — Password-Based Authentication'},
    ],
    'pw_history': [
        {'ref': 'IA-5(1)', 'family': 'IA', 'title': 'Authenticator Management — Password-Based Authentication'},
    ],
    'pw_aging': [
        {'ref': 'IA-5(1)', 'family': 'IA', 'title': 'Authenticator Management — Password-Based Authentication'},
    ],
    'pw_hash_rounds': [
        {'ref': 'IA-5(1)', 'family': 'IA', 'title': 'Authenticator Management — Password-Based Authentication'},
        {'ref': 'SC-13', 'family': 'SC', 'title': 'Cryptographic Protection'},
    ],
    'ssh_crypto': [
        {'ref': 'SC-13', 'family': 'SC', 'title': 'Cryptographic Protection'},
        {'ref': 'SC-8(1)', 'family': 'SC', 'title': 'Transmission Confidentiality and Integrity — Cryptographic Protection'},
    ],
    'ssh_perms': [
        {'ref': 'AC-3', 'family': 'AC', 'title': 'Access Enforcement'},
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
    'file_perms': [
        {'ref': 'AC-3', 'family': 'AC', 'title': 'Access Enforcement'},
        {'ref': 'AU-9', 'family': 'AU', 'title': 'Protection of Audit Information'},
    ],
    'default_umask': [
        {'ref': 'AC-3', 'family': 'AC', 'title': 'Access Enforcement'},
    ],
    'apparmor': [
        {'ref': 'AC-6', 'family': 'AC', 'title': 'Least Privilege'},
        {'ref': 'AC-3', 'family': 'AC', 'title': 'Access Enforcement'},
    ],
    'fs_modules': [
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
    'usb_storage': [
        {'ref': 'MP-7', 'family': 'MP', 'title': 'Media Use'},
        {'ref': 'AC-19', 'family': 'AC', 'title': 'Access Control for Mobile Devices'},
    ],
    'mount_options': [
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
    'core_dumps': [
        {'ref': 'SC-28', 'family': 'SC', 'title': 'Protection of Information at Rest'},
    ],
    'audit_rules': [
        {'ref': 'AU-2', 'family': 'AU', 'title': 'Event Logging'},
        {'ref': 'AU-12', 'family': 'AU', 'title': 'Audit Record Generation'},
        {'ref': 'AU-3', 'family': 'AU', 'title': 'Content of Audit Records'},
    ],
    'audit_boot': [
        {'ref': 'AU-5', 'family': 'AU', 'title': 'Response to Audit Logging Process Failures'},
    ],
    'auditd_service': [
        {'ref': 'AU-12', 'family': 'AU', 'title': 'Audit Record Generation'},
    ],
    'audit_immutable': [
        {'ref': 'AU-9', 'family': 'AU', 'title': 'Protection of Audit Information'},
        {'ref': 'AU-9(3)', 'family': 'AU', 'title': 'Cryptographic Protection of Audit Records'},
    ],
    'aide_audit_protect': [
        {'ref': 'AU-9', 'family': 'AU', 'title': 'Protection of Audit Information'},
        {'ref': 'SI-7', 'family': 'SI', 'title': 'Software, Firmware, and Information Integrity'},
    ],
    'journald': [
        {'ref': 'AU-2', 'family': 'AU', 'title': 'Event Logging'},
    ],
    'process_acct': [
        {'ref': 'AU-2', 'family': 'AU', 'title': 'Event Logging'},
    ],
    'sysstat': [
        {'ref': 'AU-2', 'family': 'AU', 'title': 'Event Logging'},
    ],
    'file_integrity': [
        {'ref': 'SI-7', 'family': 'SI', 'title': 'Software, Firmware, and Information Integrity'},
        {'ref': 'CM-3', 'family': 'CM', 'title': 'Configuration Change Control'},
    ],
    'debsums': [
        {'ref': 'SI-7', 'family': 'SI', 'title': 'Software, Firmware, and Information Integrity'},
    ],
    'mem_protection': [
        {'ref': 'SI-16', 'family': 'SI', 'title': 'Memory Protection'},
    ],
    'sysctl_hardening': [
        {'ref': 'SC-7', 'family': 'SC', 'title': 'Boundary Protection'},
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
    'pkg_cleanup': [
        {'ref': 'CM-7(5)', 'family': 'CM', 'title': 'Least Functionality — Authorized Software / Allow-by-Exception'},
    ],
    'remove_legacy_svcs': [
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
    'disable_services': [
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
    'net_protocols': [
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
        {'ref': 'SC-7', 'family': 'SC', 'title': 'Boundary Protection'},
    ],
    'pve_fail2ban': [
        {'ref': 'AC-7', 'family': 'AC', 'title': 'Unsuccessful Logon Attempts'},
        {'ref': 'SI-4', 'family': 'SI', 'title': 'System Monitoring'},
    ],
    'cron_hardening': [
        {'ref': 'AC-6', 'family': 'AC', 'title': 'Least Privilege'},
    ],
    'pam_tmpdir': [
        {'ref': 'SC-28', 'family': 'SC', 'title': 'Protection of Information at Rest'},
    ],
    'apt_show_versions': [
        {'ref': 'SI-2', 'family': 'SI', 'title': 'Flaw Remediation'},
    ],
    'restrict_compilers': [
        {'ref': 'CM-7', 'family': 'CM', 'title': 'Least Functionality'},
    ],
}


# DISA STIG (RHEL 9 / Ubuntu 22.04 — refs are RHEL 9 STIG IDs where known).
# STIG IDs change between releases, so review against the deployed STIG baseline.
DISA_STIG = {
    'pam_faillock': [
        {'ref': 'RHEL-09-411075', 'family': 'AC', 'title': 'RHEL 9 must automatically lock an account when three unsuccessful logon attempts occur during a 15-minute time period.'},
    ],
    'pw_quality': [
        {'ref': 'RHEL-09-611045', 'family': 'IA', 'title': 'RHEL 9 must ensure the password complexity module is enabled in the system-auth file.'},
        {'ref': 'RHEL-09-611040', 'family': 'IA', 'title': 'RHEL 9 must ensure the password complexity module is enabled in the password-auth file.'},
    ],
    'pw_history': [
        {'ref': 'RHEL-09-611015', 'family': 'IA', 'title': 'RHEL 9 must be configured in the password-auth file to prohibit password reuse for a minimum of five generations.'},
        {'ref': 'RHEL-09-611020', 'family': 'IA', 'title': 'RHEL 9 must be configured in the system-auth file to prohibit password reuse for a minimum of five generations.'},
    ],
    'pw_aging': [
        {'ref': 'RHEL-09-411010', 'family': 'AC', 'title': 'RHEL 9 user account passwords for new users or password changes must have a 60-day maximum password lifetime restriction in /etc/login.defs.'},
        {'ref': 'RHEL-09-611080', 'family': 'IA', 'title': 'RHEL 9 passwords must have a 24 hours minimum password lifetime restriction in /etc/shadow.'},
    ],
    'pw_hash_rounds': [
        {'ref': 'RHEL-09-611055', 'family': 'IA', 'title': 'RHEL 9 system-auth must be configured to use a sufficient number of hashing rounds'},
        {'ref': 'RHEL-09-611050', 'family': 'IA', 'title': 'RHEL 9 password-auth must be configured to use a sufficient number of hashing rounds'},
    ],
    'ssh_crypto': [
        {'ref': 'RHEL-09-255065', 'family': 'IA', 'title': 'The RHEL 9 SSH server must be configured to use only DOD-approved encryption ciphers employing FIPS 140-3 validated cryptographic hash algorithms to protect the confidentiality of SSH server connections.'},
        {'ref': 'RHEL-09-255075', 'family': 'IA', 'title': 'The RHEL 9 SSH server must be configured to use only Message Authentication Codes (MACs) employing FIPS 140-3 validated cryptographic hash algorithms.'},
    ],
    'ssh_perms': [
        {'ref': 'RHEL-09-255115', 'family': 'CM', 'title': 'RHEL 9 SSH server configuration file must have mode 0600 or less permissive'},
        {'ref': 'RHEL-09-255110', 'family': 'CM', 'title': 'RHEL 9 SSH server configuration file must be owned by root'},
        {'ref': 'RHEL-09-255105', 'family': 'CM', 'title': 'RHEL 9 SSH server configuration file must be group-owned by root'},
    ],
    'session_limit': [
        {'ref': 'RHEL-09-412040', 'family': 'AC', 'title': 'RHEL 9 must limit the number of concurrent sessions to ten for all accounts and/or account types'},
    ],
    'shell_timeout': [
        {'ref': 'RHEL-09-412035', 'family': 'AC', 'title': 'RHEL 9 must automatically exit interactive command shell user sessions after 10 minutes of inactivity'},
    ],
    'login_banners': [
        {'ref': 'RHEL-09-211020', 'family': 'AC', 'title': 'RHEL 9 must display the Standard Mandatory DOD Notice and Consent Banner before granting local or remote access to the system via a command line user logon.'},
    ],
    'inactive_accounts': [
        {'ref': 'RHEL-09-411050', 'family': 'AC', 'title': 'RHEL 9 must disable account identifiers (individuals, groups, roles, and devices) after 35 days of inactivity.'},
    ],
    'audit_rules': [
        {'ref': 'RHEL-09-654215', 'family': 'AU', 'title': 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/sudoers.'},
        {'ref': 'RHEL-09-654225', 'family': 'AU', 'title': 'RHEL 9 must generate audit records for all account creations, modifications, disabling, and termination events that affect /etc/group.'},
    ],
    'audit_boot': [
        {'ref': 'RHEL-09-212055', 'family': 'AU', 'title': 'RHEL 9 must enable auditing of processes that start prior to the audit daemon.'},
    ],
    'auditd_service': [
        {'ref': 'RHEL-09-653015', 'family': 'AU', 'title': 'RHEL 9 audit service must be enabled'},
    ],
    'audit_immutable': [
        {'ref': 'RHEL-09-654275', 'family': 'AU', 'title': 'RHEL 9 audit system must protect auditing rules from unauthorized change.'},
        {'ref': 'RHEL-09-653025', 'family': 'AU', 'title': 'RHEL 9 audit system must take appropriate action when the audit storage volume is full'},
    ],
    'aide_audit_protect': [
        {'ref': 'RHEL-09-651025', 'family': 'AU', 'title': 'RHEL 9 must use cryptographic mechanisms to protect the integrity of audit tools'},
        {'ref': 'RHEL-09-232035', 'family': 'AU', 'title': 'RHEL 9 audit tools must have a mode of 0755 or less permissive'},
    ],
    'journald': [
        {'ref': 'RHEL-09-211040', 'family': 'AU', 'title': 'RHEL 9 systemd-journald service must be enabled'},
    ],
    'apparmor': [
        {'ref': 'UBTU-22-431015', 'family': 'AC', 'title': 'Ubuntu 22.04 LTS must be configured to use AppArmor'},
        {'ref': 'RHEL-09-431010', 'family': 'AC', 'title': 'RHEL 9 must use a Linux Security Module configured to enforce limits on system services.'},
    ],
    'fs_modules': [
        {'ref': 'RHEL-09-231195', 'family': 'CM', 'title': 'RHEL 9 must disable mounting of cramfs'},
    ],
    'usb_storage': [
        {'ref': 'RHEL-09-291010', 'family': 'MP', 'title': 'RHEL 9 must be configured to disable USB mass storage'},
    ],
    'core_dumps': [
        {'ref': 'RHEL-09-213090', 'family': 'SC', 'title': 'RHEL 9 must disable storing core dumps'},
        {'ref': 'RHEL-09-213100', 'family': 'SC', 'title': 'RHEL 9 must disable acquiring, saving, and processing core dumps'},
    ],
    'mount_options': [
        {'ref': 'RHEL-09-231115', 'family': 'CM', 'title': 'RHEL 9 must mount /dev/shm with the noexec option'},
        {'ref': 'RHEL-09-231130', 'family': 'CM', 'title': 'RHEL 9 must mount /tmp with the noexec option'},
    ],
    'mem_protection': [
        {'ref': 'RHEL-09-213070', 'family': 'SC', 'title': 'RHEL 9 must implement address space layout randomization (ASLR) to protect its memory from unauthorized code execution.'},
    ],
    'file_integrity': [
        {'ref': 'RHEL-09-651010', 'family': 'SI', 'title': 'RHEL 9 must have the AIDE package installed'},
        {'ref': 'RHEL-09-651015', 'family': 'SI', 'title': 'RHEL 9 must routinely check the baseline configuration for unauthorized changes and notify the system administrator when anomalies in the operation of any security functions are discovered.'},
    ],
    'sysctl_hardening': [
        {'ref': 'RHEL-09-253015', 'family': 'SC', 'title': 'RHEL 9 must ignore Internet Protocol version 4 (IPv4) Internet Control Message Protocol (ICMP) redirect messages.'},
        {'ref': 'RHEL-09-253035', 'family': 'SC', 'title': 'RHEL 9 must use reverse path filtering on all IPv4 interfaces'},
        {'ref': 'RHEL-09-253010', 'family': 'SC', 'title': 'RHEL 9 must be configured to use TCP syncookies'},
    ],
    # NS rebuild 2026-06-15 (RHEL 9 STIG V2R8, web-verified). Intentionally unmapped:
    #  - pve_fail2ban: RHEL 9 STIG dropped the RHEL-7/8 host-based-IDS (SI-4) rule.
    # Partial coverage (real ID, partial intent): journald 211040 = "service enabled" only
    # (no STIG rule for compress/forward/persistent); fs_modules = cramfs (231195) only --
    # freevxfs/squashfs/udf/etc. are CIS, not STIG. ssh_crypto omits KEX (no server-side
    # KexAlgorithms STIG rule in V2R8; governed by the FIPS crypto-policy 671xxx range).
}


# ISO/IEC 27001:2022 Annex A controls (93 controls in 4 themes:
# A.5 Organizational, A.6 People, A.7 Physical, A.8 Technological).
ISO_27001 = {
    'pam_faillock': [
        {'ref': 'A.8.5', 'family': 'A.8', 'title': 'Secure authentication'},
    ],
    'pw_quality': [
        {'ref': 'A.5.17', 'family': 'A.5', 'title': 'Authentication information'},
    ],
    'pw_history': [
        {'ref': 'A.5.17', 'family': 'A.5', 'title': 'Authentication information'},
    ],
    'pw_aging': [
        {'ref': 'A.5.17', 'family': 'A.5', 'title': 'Authentication information'},
    ],
    'pw_hash_rounds': [
        {'ref': 'A.5.17', 'family': 'A.5', 'title': 'Authentication information'},
        {'ref': 'A.8.24', 'family': 'A.8', 'title': 'Use of cryptography'},
    ],
    'ssh_crypto': [
        {'ref': 'A.8.24', 'family': 'A.8', 'title': 'Use of cryptography'},
        {'ref': 'A.8.20', 'family': 'A.8', 'title': 'Networks security'},
    ],
    'ssh_perms': [
        {'ref': 'A.5.18', 'family': 'A.5', 'title': 'Access rights'},
    ],
    'file_perms': [
        {'ref': 'A.8.3', 'family': 'A.8', 'title': 'Information access restriction'},
    ],
    'default_umask': [
        {'ref': 'A.8.3', 'family': 'A.8', 'title': 'Information access restriction'},
    ],
    'session_limit': [
        {'ref': 'A.8.5', 'family': 'A.8', 'title': 'Secure authentication'},
    ],
    'shell_timeout': [
        {'ref': 'A.8.5', 'family': 'A.8', 'title': 'Secure authentication'},
    ],
    'login_banners': [
        {'ref': 'A.5.10', 'family': 'A.5', 'title': 'Acceptable use of information and other associated assets'},
    ],
    'inactive_accounts': [
        {'ref': 'A.5.18', 'family': 'A.5', 'title': 'Access rights'},
    ],
    'apparmor': [
        {'ref': 'A.8.2', 'family': 'A.8', 'title': 'Privileged access rights'},
        {'ref': 'A.8.18', 'family': 'A.8', 'title': 'Use of privileged utility programs'},
    ],
    'fs_modules': [
        {'ref': 'A.8.9', 'family': 'A.8', 'title': 'Configuration management'},
    ],
    'usb_storage': [
        {'ref': 'A.7.10', 'family': 'A.7', 'title': 'Storage media'},
    ],
    'mount_options': [
        {'ref': 'A.8.9', 'family': 'A.8', 'title': 'Configuration management'},
    ],
    'core_dumps': [
        {'ref': 'A.8.10', 'family': 'A.8', 'title': 'Information deletion'},
        {'ref': 'A.8.11', 'family': 'A.8', 'title': 'Data masking'},
    ],
    'audit_rules': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
    ],
    'audit_boot': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
    ],
    'auditd_service': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
    ],
    'audit_immutable': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
        {'ref': 'A.8.34', 'family': 'A.8', 'title': 'Protection of information systems during audit testing'},
    ],
    'aide_audit_protect': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
        {'ref': 'A.8.34', 'family': 'A.8', 'title': 'Protection of information systems during audit testing'},
    ],
    'journald': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
    ],
    'process_acct': [
        {'ref': 'A.8.15', 'family': 'A.8', 'title': 'Logging'},
    ],
    'file_integrity': [
        {'ref': 'A.8.32', 'family': 'A.8', 'title': 'Change management'},
        {'ref': 'A.8.16', 'family': 'A.8', 'title': 'Monitoring activities'},
    ],
    'debsums': [
        {'ref': 'A.8.32', 'family': 'A.8', 'title': 'Change management'},
    ],
    'mem_protection': [
        {'ref': 'A.8.27', 'family': 'A.8', 'title': 'Secure system architecture and engineering principles'},
    ],
    'sysctl_hardening': [
        {'ref': 'A.8.20', 'family': 'A.8', 'title': 'Networks security'},
        {'ref': 'A.8.9', 'family': 'A.8', 'title': 'Configuration management'},
    ],
    'pkg_cleanup': [
        {'ref': 'A.8.9', 'family': 'A.8', 'title': 'Configuration management'},
    ],
    'remove_legacy_svcs': [
        {'ref': 'A.8.9', 'family': 'A.8', 'title': 'Configuration management'},
    ],
    'disable_services': [
        {'ref': 'A.8.9', 'family': 'A.8', 'title': 'Configuration management'},
    ],
    'net_protocols': [
        {'ref': 'A.8.20', 'family': 'A.8', 'title': 'Networks security'},
        {'ref': 'A.8.21', 'family': 'A.8', 'title': 'Security of network services'},
    ],
    'pve_fail2ban': [
        {'ref': 'A.8.16', 'family': 'A.8', 'title': 'Monitoring activities'},
        {'ref': 'A.5.7', 'family': 'A.5', 'title': 'Threat intelligence'},
    ],
    'apt_show_versions': [
        {'ref': 'A.8.8', 'family': 'A.8', 'title': 'Management of technical vulnerabilities'},
    ],
    'cron_hardening': [
        {'ref': 'A.8.2', 'family': 'A.8', 'title': 'Privileged access rights'},
    ],
    'pam_tmpdir': [
        {'ref': 'A.8.10', 'family': 'A.8', 'title': 'Information deletion'},
    ],
    'restrict_compilers': [
        {'ref': 'A.8.19', 'family': 'A.8', 'title': 'Installation of software on operational systems'},
    ],
}


# BSI IT-Grundschutz Kompendium (subset — modules SYS, OPS, NET, DER, CON).
BSI_GRUNDSCHUTZ = {
    'pam_faillock': [
        {'ref': 'ORP.4.A23', 'family': 'ORP', 'title': 'Regelung für passwortverarbeitende Anwendungen und IT-Systeme'},
    ],
    'pw_quality': [
        {'ref': 'ORP.4.A22', 'family': 'ORP', 'title': 'Regelung zur Passwortqualität'},
        {'ref': 'ORP.4.A8', 'family': 'ORP', 'title': 'Regelung des Passwortgebrauchs'},
    ],
    'pw_aging': [
        {'ref': 'ORP.4.A23', 'family': 'ORP', 'title': 'Regelung für passwortverarbeitende Anwendungen und IT-Systeme'},
    ],
    'pw_history': [
        {'ref': 'ORP.4.A23', 'family': 'ORP', 'title': 'Regelung für passwortverarbeitende Anwendungen und IT-Systeme'},
        {'ref': 'ORP.4.A8', 'family': 'ORP', 'title': 'Regelung des Passwortgebrauchs'},
    ],
    'pw_hash_rounds': [
        {'ref': 'CON.1.A1', 'family': 'CON', 'title': 'Auswahl geeigneter kryptografischer Verfahren'},
    ],
    'ssh_crypto': [
        {'ref': 'SYS.1.3.A8', 'family': 'SYS', 'title': 'Verschlüsselter Zugriff über Secure Shell'},
        {'ref': 'CON.1.A1', 'family': 'CON', 'title': 'Auswahl geeigneter kryptografischer Verfahren'},
    ],
    'ssh_perms': [
        {'ref': 'SYS.1.3.A8', 'family': 'SYS', 'title': 'Verschlüsselter Zugriff über Secure Shell'},
    ],
    'file_perms': [
        {'ref': 'SYS.1.3.A14', 'family': 'SYS', 'title': 'Verhinderung des Ausspähens von Informationen über das System und über Benutzende'},
        {'ref': 'ORP.4.A7', 'family': 'ORP', 'title': 'Vergabe von Zugriffsrechten'},
    ],
    'default_umask': [
        {'ref': 'SYS.1.3.A14', 'family': 'SYS', 'title': 'Verhinderung des Ausspähens von Informationen über das System und über Benutzende'},
    ],
    'apparmor': [
        {'ref': 'SYS.1.3.A10', 'family': 'SYS', 'title': 'Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen'},
        {'ref': 'SYS.1.3.A16', 'family': 'SYS', 'title': 'Zusätzliche Verhinderung der Ausbreitung bei der Ausnutzung von Schwachstellen'},
    ],
    'inactive_accounts': [
        {'ref': 'ORP.4.A7', 'family': 'ORP', 'title': 'Vergabe von Zugriffsrechten'},
    ],
    'vsnfd_kernel_lockdown': [
        {'ref': 'SYS.1.3.A17', 'family': 'SYS', 'title': 'Zusätzlicher Schutz des Kernels'},
    ],
    'vsnfd_password_min_12': [
        {'ref': 'ORP.4.A22', 'family': 'ORP', 'title': 'Regelung zur Passwortqualität'},
    ],
    'fs_modules': [
        {'ref': 'SYS.1.1.A6', 'family': 'SYS', 'title': 'Deaktivierung nicht benötigter Dienste'},
    ],
    'usb_storage': [
        {'ref': 'SYS.1.3.A3', 'family': 'SYS', 'title': 'Kein automatisches Einbinden von Wechsellaufwerken'},
        {'ref': 'SYS.1.1.A5', 'family': 'SYS', 'title': 'Schutz von Schnittstellen'},
    ],
    'mount_options': [
        {'ref': 'SYS.1.1.A16', 'family': 'SYS', 'title': 'Sichere Installation und Grundkonfiguration von Servern'},
    ],
    'core_dumps': [
        {'ref': 'SYS.1.3.A4', 'family': 'SYS', 'title': 'Schutz vor Ausnutzung von Schwachstellen in Anwendungen'},
    ],
    'audit_rules': [
        {'ref': 'OPS.1.1.5.A3', 'family': 'OPS', 'title': 'Konfiguration der Protokollierung auf System- und Netzebene'},
        {'ref': 'DER.1.A5', 'family': 'DER', 'title': 'Einsatz von mitgelieferten Systemfunktionen zur Detektion'},
    ],
    'audit_boot': [
        {'ref': 'OPS.1.1.5.A3', 'family': 'OPS', 'title': 'Konfiguration der Protokollierung auf System- und Netzebene'},
    ],
    'auditd_service': [
        {'ref': 'OPS.1.1.5.A1', 'family': 'OPS', 'title': 'Erstellung einer Sicherheitsrichtlinie für die Protokollierung'},
        {'ref': 'OPS.1.1.5.A3', 'family': 'OPS', 'title': 'Konfiguration der Protokollierung auf System- und Netzebene'},
    ],
    'audit_immutable': [
        {'ref': 'OPS.1.1.5.A10', 'family': 'OPS', 'title': 'Zugriffsschutz für Protokollierungsdaten'},
    ],
    'aide_audit_protect': [
        {'ref': 'DER.1.A18', 'family': 'DER', 'title': 'Durchführung regelmäßiger Integritätskontrollen'},
        {'ref': 'OPS.1.1.5.A10', 'family': 'OPS', 'title': 'Zugriffsschutz für Protokollierungsdaten'},
    ],
    'journald': [
        {'ref': 'OPS.1.1.5.A3', 'family': 'OPS', 'title': 'Konfiguration der Protokollierung auf System- und Netzebene'},
    ],
    'process_acct': [
        {'ref': 'OPS.1.1.5.A3', 'family': 'OPS', 'title': 'Konfiguration der Protokollierung auf System- und Netzebene'},
    ],
    'file_integrity': [
        {'ref': 'DER.1.A18', 'family': 'DER', 'title': 'Durchführung regelmäßiger Integritätskontrollen'},
        {'ref': 'SYS.1.1.A27', 'family': 'SYS', 'title': 'Hostbasierte Angriffserkennung'},
    ],
    'debsums': [
        {'ref': 'DER.1.A18', 'family': 'DER', 'title': 'Durchführung regelmäßiger Integritätskontrollen'},
    ],
    'mem_protection': [
        {'ref': 'SYS.1.3.A4', 'family': 'SYS', 'title': 'Schutz vor Ausnutzung von Schwachstellen in Anwendungen'},
        {'ref': 'SYS.1.3.A17', 'family': 'SYS', 'title': 'Zusätzlicher Schutz des Kernels'},
    ],
    'sysctl_hardening': [
        {'ref': 'SYS.1.3.A4', 'family': 'SYS', 'title': 'Schutz vor Ausnutzung von Schwachstellen in Anwendungen'},
    ],
    'net_protocols': [
        {'ref': 'SYS.1.1.A6', 'family': 'SYS', 'title': 'Deaktivierung nicht benötigter Dienste'},
    ],
    'pkg_cleanup': [
        {'ref': 'SYS.1.1.A6', 'family': 'SYS', 'title': 'Deaktivierung nicht benötigter Dienste'},
    ],
    'remove_legacy_svcs': [
        {'ref': 'SYS.1.1.A6', 'family': 'SYS', 'title': 'Deaktivierung nicht benötigter Dienste'},
    ],
    'disable_services': [
        {'ref': 'SYS.1.1.A6', 'family': 'SYS', 'title': 'Deaktivierung nicht benötigter Dienste'},
    ],
    'restrict_compilers': [
        {'ref': 'SYS.1.3.A5', 'family': 'SYS', 'title': 'Sichere Installation von Software-Paketen'},
    ],
    'pve_fail2ban': [
        {'ref': 'DER.1.A5', 'family': 'DER', 'title': 'Einsatz von mitgelieferten Systemfunktionen zur Detektion'},
        {'ref': 'SYS.1.1.A27', 'family': 'SYS', 'title': 'Hostbasierte Angriffserkennung'},
    ],
    # VS-NfD-specific informational checks -> BSI Grundschutz
    'vsnfd_disk_encryption': [
        {'ref': 'SYS.1.1.A34', 'family': 'SYS', 'title': 'Festplattenverschlüsselung'},
        {'ref': 'SYS.1.5.A28', 'family': 'SYS', 'title': 'Verschlüsselung von virtuellen IT-Systemen'},
    ],
    'vsnfd_audit_retention': [
        {'ref': 'OPS.1.1.5.A8', 'family': 'OPS', 'title': 'Archivierung von Protokollierungsdaten'},
    ],
    'vsnfd_journald_size': [
        {'ref': 'OPS.1.1.5.A3', 'family': 'OPS', 'title': 'Konfiguration der Protokollierung auf System- und Netzebene'},
    ],
    'vsnfd_secure_boot': [
        {'ref': 'SYS.1.1.A36', 'family': 'SYS', 'title': 'Absicherung des Bootvorgangs'},
    ],
    # NS rebuild 2026-06-15 (BSI IT-Grundschutz, web-verified). Dropped the fabricated
    # SYS.1.3.A19/A22 and the ENTFALLEN SYS.1.3.A1/A11; remapped DER.4.A4->DER.1.A18,
    # SYS.1.5.A4->SYS.1.1.A34; fixed all ORP.4 family tags (were 'OPS'). Intentionally
    # unmapped (no defensible Grundschutz server requirement): cron_hardening, session_limit,
    # shell_timeout (idle-lock is client req SYS.2.1), login_banners (no banner req in GS),
    # pam_tmpdir, apt_show_versions (patch-mgmt = OPS.1.1.3, A-number unconfirmed).
}


# ──────────────────────────────────────────────────────────────────────────
# ANSSI-BP-028 v2.0 (2022-10-03) — "Recommandations de configuration d'un
# système GNU/Linux". The recognised French national Linux-hardening baseline.
# Both Diffusion Restreinte (protection regime under Instruction interministérielle
# n° 901 / II 901) and the RGS reference ANSSI-BP-028 as the concrete technical
# hardening measure set, so 'dr' + 'rgs' both inherit this mapping — same as
# 'vs-nfd' inherits BSI Grundschutz.
# NS Jul 2026 — R-numbers + French titles verified against the official ANSSI PDF
# (v2.0, "Liste des recommandations" p.71-73). Checks with NO defensible BP-028
# recommendation are INTENTIONALLY UNMAPPED (no fabrication, per the BSI rebuild note):
#   ssh_crypto / ssh_perms  -> BP-028 defers OpenSSH to a separate ANSSI note (NT-SSH)
#   vsnfd_kernel_lockdown   -> only Annexe A (non-numbered), not a recommendation
#   vsnfd_disk_encryption   -> no LUKS/FDE recommendation in v2.0
#   pve_fail2ban            -> host lockout is R67 (pam_faillock); no fail2ban item
#   restrict_compilers / debsums / process_acct / vsnfd_audit_retention -> no matching R-number
# ──────────────────────────────────────────────────────────────────────────
ANSSI_BP028 = {
    'pam_faillock': [
        {'ref': 'R67', 'family': 'services', 'title': 'Sécuriser les authentifications distante par PAM'},
    ],
    'pw_quality': [
        {'ref': 'R67', 'family': 'services', 'title': 'Sécuriser les authentifications distante par PAM'},
        {'ref': 'R31', 'family': 'comptes', 'title': 'Utiliser des mots de passe robustes'},
    ],
    'pw_aging': [
        {'ref': 'R31', 'family': 'comptes', 'title': 'Utiliser des mots de passe robustes'},
    ],
    'pw_history': [
        {'ref': 'R31', 'family': 'comptes', 'title': 'Utiliser des mots de passe robustes'},
    ],
    'pw_hash_rounds': [
        {'ref': 'R68', 'family': 'services', 'title': 'Protéger les mots de passe stockés'},
        {'ref': 'R31', 'family': 'comptes', 'title': 'Utiliser des mots de passe robustes'},
    ],
    'file_perms': [
        {'ref': 'R50', 'family': 'fichiers', 'title': "Restreindre les droits d'accès aux fichiers et aux répertoires sensibles"},
        {'ref': 'R51', 'family': 'fichiers', 'title': "Changer les secrets et droits d'accès dès l'installation"},
    ],
    'default_umask': [
        {'ref': 'R36', 'family': 'controle_acces', 'title': 'Modifier la valeur par défaut de UMASK'},
    ],
    'apparmor': [
        {'ref': 'R45', 'family': 'controle_acces', 'title': 'Activer les profils de sécurité AppArmor'},
        {'ref': 'R37', 'family': 'controle_acces', 'title': "Utiliser des fonctionnalités de contrôle d'accès obligatoire MAC"},
    ],
    'inactive_accounts': [
        {'ref': 'R30', 'family': 'comptes', 'title': 'Désactiver les comptes utilisateur inutilisés'},
    ],
    'vsnfd_password_min_12': [
        {'ref': 'R67', 'family': 'services', 'title': 'Sécuriser les authentifications distante par PAM'},
    ],
    'fs_modules': [
        {'ref': 'R10', 'family': 'noyau', 'title': 'Désactiver le chargement des modules noyau'},
    ],
    'usb_storage': [
        {'ref': 'R10', 'family': 'noyau', 'title': 'Désactiver le chargement des modules noyau'},
    ],
    'mount_options': [
        {'ref': 'R28', 'family': 'partitionnement', 'title': 'Partitionnement type'},
    ],
    'core_dumps': [
        {'ref': 'R14', 'family': 'noyau', 'title': 'Paramétrer les options de configuration des systèmes de fichiers'},
        {'ref': 'R8', 'family': 'noyau', 'title': 'Paramétrer les options de configuration de la mémoire'},
    ],
    'audit_rules': [
        {'ref': 'R73', 'family': 'journalisation', 'title': "Journaliser l'activité système avec auditd"},
    ],
    'audit_boot': [
        {'ref': 'R73', 'family': 'journalisation', 'title': "Journaliser l'activité système avec auditd"},
    ],
    'auditd_service': [
        {'ref': 'R73', 'family': 'journalisation', 'title': "Journaliser l'activité système avec auditd"},
    ],
    'audit_immutable': [
        {'ref': 'R73', 'family': 'journalisation', 'title': "Journaliser l'activité système avec auditd"},
    ],
    'aide_audit_protect': [
        {'ref': 'R77', 'family': 'surveillance', 'title': 'Protéger la base de données des scellés'},
    ],
    'journald': [
        {'ref': 'R71', 'family': 'journalisation', 'title': 'Mettre en place un système de journalisation'},
        {'ref': 'R72', 'family': 'journalisation', 'title': "Mettre en place des journaux d'activité de service dédiés"},
    ],
    'file_integrity': [
        {'ref': 'R76', 'family': 'surveillance', 'title': "Sceller et vérifier l'intégrité des fichiers"},
        {'ref': 'R77', 'family': 'surveillance', 'title': 'Protéger la base de données des scellés'},
    ],
    'mem_protection': [
        {'ref': 'R9', 'family': 'noyau', 'title': 'Paramétrer les options de configuration du noyau'},
        {'ref': 'R8', 'family': 'noyau', 'title': 'Paramétrer les options de configuration de la mémoire'},
        {'ref': 'R11', 'family': 'noyau', 'title': 'Activer et configurer le LSM Yama'},
    ],
    'sysctl_hardening': [
        {'ref': 'R9', 'family': 'noyau', 'title': 'Paramétrer les options de configuration du noyau'},
        {'ref': 'R8', 'family': 'noyau', 'title': 'Paramétrer les options de configuration de la mémoire'},
        {'ref': 'R12', 'family': 'noyau', 'title': 'Paramétrer les options de configuration du réseau IPv4'},
        {'ref': 'R14', 'family': 'noyau', 'title': 'Paramétrer les options de configuration des systèmes de fichiers'},
    ],
    'net_protocols': [
        {'ref': 'R10', 'family': 'noyau', 'title': 'Désactiver le chargement des modules noyau'},
        {'ref': 'R13', 'family': 'noyau', 'title': 'Désactiver le plan IPv6'},
    ],
    'pkg_cleanup': [
        {'ref': 'R58', 'family': 'paquets', 'title': "N'installer que les paquets strictement nécessaires"},
    ],
    'remove_legacy_svcs': [
        {'ref': 'R62', 'family': 'services', 'title': 'Désactiver les services non nécessaires'},
        {'ref': 'R58', 'family': 'paquets', 'title': "N'installer que les paquets strictement nécessaires"},
    ],
    'disable_services': [
        {'ref': 'R62', 'family': 'services', 'title': 'Désactiver les services non nécessaires'},
        {'ref': 'R63', 'family': 'services', 'title': 'Désactiver les fonctionnalités des services non essentielles'},
    ],
    'vsnfd_journald_size': [
        {'ref': 'R28', 'family': 'partitionnement', 'title': 'Partitionnement type'},
    ],
    'vsnfd_secure_boot': [
        {'ref': 'R3', 'family': 'materiel', 'title': 'Activer le démarrage sécurisé UEFI'},
        {'ref': 'R4', 'family': 'materiel', 'title': 'Remplacer les clés préchargées'},
    ],
}


# Master lookup
FRAMEWORK_MAPPING = {
    'cmmc1':  CMMC_L1,
    'cmmc2':  CMMC_L2_NIST_171,
    'nist53': NIST_800_53,
    'stig':   DISA_STIG,
    'iso':    ISO_27001,
    'bsi':    BSI_GRUNDSCHUTZ,
    'vs-nfd': BSI_GRUNDSCHUTZ,  # VS-NfD inherits BSI Grundschutz refs
    'dr':     ANSSI_BP028,      # Diffusion Restreinte (II 901) — French Linux baseline = ANSSI-BP-028
    'rgs':    ANSSI_BP028,      # RGS references ANSSI-BP-028 for Linux system hardening
}


# ──────────────────────────────────────────────────────────────────────────
# Remediation hints — short, actionable, in English. Keep these focused on
# WHAT the operator should do; the specific shell command is in the apply
# block of `_HARDENING_PROFILES` (manager.py).
# ──────────────────────────────────────────────────────────────────────────
REMEDIATION = {
    'pam_faillock': {
        'summary': 'Lock accounts after 5 failed login attempts.',
        'how_to_fix': 'PegaProx > Settings > Hardening > Apply "PAM faillock". Manually: edit /etc/security/faillock.conf with deny=5, unlock_time=900, fail_interval=900, then enable faillock in /etc/pam.d/common-auth and common-account.',
    },
    'session_limit': {
        'summary': 'Limit concurrent sessions per user (TMOUT + maxlogins).',
        'how_to_fix': 'Set TMOUT=900 in /etc/profile.d/tmout.sh and maxlogins in /etc/security/limits.conf. Apply via PegaProx hardening or manual.',
    },
    'shell_timeout': {
        'summary': 'Auto-logout idle interactive shells after a defined idle time.',
        'how_to_fix': 'Set TMOUT=900 in /etc/profile.d/tmout.sh and ensure it is exported and read-only. PegaProx hardening apply handles this.',
    },
    'login_banners': {
        'summary': 'Display a legal/security warning banner before login.',
        'how_to_fix': 'Populate /etc/issue, /etc/issue.net, /etc/motd with the appropriate notice (DoD CnC banner for federal use). Apply via PegaProx.',
    },
    'inactive_accounts': {
        'summary': 'Disable user accounts after a defined period of inactivity (35 days for STIG).',
        'how_to_fix': 'Set INACTIVE=35 in /etc/default/useradd and run useradd -D -f 35. PegaProx hardening enforces 35 days by default.',
    },
    'pw_quality': {
        'summary': 'Enforce password complexity (length, character classes).',
        'how_to_fix': 'Configure /etc/security/pwquality.conf with minlen=14 (12 for VS-NfD), minclass=4, dcredit/ucredit/lcredit/ocredit=-1.',
    },
    'pw_history': {
        'summary': 'Prevent password reuse for the last N generations (5+ recommended).',
        'how_to_fix': 'In /etc/pam.d/common-password, set "remember=5" on the pam_pwhistory line.',
    },
    'pw_aging': {
        'summary': 'Set sensible password aging (max 60-90 days, min 1 day, warn 7 days).',
        'how_to_fix': 'Edit /etc/login.defs: PASS_MAX_DAYS 60, PASS_MIN_DAYS 1, PASS_WARN_AGE 7. Existing accounts: chage -M 60 -m 1 -W 7 <user>.',
    },
    'pw_hash_rounds': {
        'summary': 'Use strong password hashing (yescrypt or SHA-512 with rounds≥5000).',
        'how_to_fix': 'In /etc/pam.d/common-password: pam_unix.so ... yescrypt rounds=5 OR sha512 rounds=10000. PegaProx enforces yescrypt by default.',
    },
    'ssh_crypto': {
        'summary': 'Restrict SSH to strong ciphers, KEX algorithms and MACs only.',
        'how_to_fix': 'Append to /etc/ssh/sshd_config (or drop into /etc/ssh/sshd_config.d/): KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org; Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com; MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com. Reload sshd.',
    },
    'ssh_perms': {
        'summary': 'sshd_config and host keys must be 0600 owned by root:root.',
        'how_to_fix': 'chmod 600 /etc/ssh/sshd_config /etc/ssh/ssh_host_*_key; chown root:root /etc/ssh/*',
    },
    'file_perms': {
        'summary': 'Critical config files have correct ownership and restrictive perms.',
        'how_to_fix': 'PegaProx hardening apply enforces 644/640/600 on /etc/passwd, /etc/shadow, /etc/gshadow, /etc/group and similar.',
    },
    'default_umask': {
        'summary': 'Default umask 027 so newly created files are not world-readable.',
        'how_to_fix': 'Set UMASK 027 in /etc/login.defs and umask 027 in /etc/profile.d/umask.sh.',
    },
    'apparmor': {
        'summary': 'Enable AppArmor with all profiles in enforce mode.',
        'how_to_fix': 'apt install apparmor apparmor-profiles apparmor-utils; systemctl enable --now apparmor; aa-enforce /etc/apparmor.d/*',
    },
    'fs_modules': {
        'summary': 'Disable unused/legacy filesystem kernel modules (cramfs, freevxfs, jffs2, hfs, hfsplus, udf, etc).',
        'how_to_fix': 'Add "install <module> /bin/true" entries to /etc/modprobe.d/cis-fs.conf and blacklist them.',
    },
    'usb_storage': {
        'summary': 'Disable USB mass storage kernel module on servers.',
        'how_to_fix': 'echo "install usb-storage /bin/true" > /etc/modprobe.d/cis-usb.conf and blacklist usb-storage.',
    },
    'mount_options': {
        'summary': '/dev/shm, /tmp, /var/tmp mounted with nodev,nosuid,noexec.',
        'how_to_fix': 'Adjust /etc/fstab entries for tmpfs and tmp partitions. Remount: mount -o remount,nodev,nosuid,noexec /dev/shm.',
    },
    'core_dumps': {
        'summary': 'Disable core dumps for SUID programs and unprivileged users.',
        'how_to_fix': 'Add "* hard core 0" to /etc/security/limits.conf and "fs.suid_dumpable = 0" to /etc/sysctl.d/.',
    },
    'audit_rules': {
        'summary': 'auditd has rules for time changes, account events, MAC changes, network changes, file deletes, privilege use, etc.',
        'how_to_fix': 'Drop a CIS-aligned ruleset into /etc/audit/rules.d/cis.rules and run augenrules --load. PegaProx hardening ships a complete ruleset.',
    },
    'audit_boot': {
        'summary': 'Kernel auditing is enabled at boot via audit=1 GRUB parameter.',
        'how_to_fix': 'Append audit=1 audit_backlog_limit=8192 to GRUB_CMDLINE_LINUX in /etc/default/grub, update-grub, reboot.',
    },
    'auditd_service': {
        'summary': 'auditd service is enabled and running.',
        'how_to_fix': 'apt install auditd; systemctl enable --now auditd',
    },
    'audit_immutable': {
        'summary': 'Audit configuration is in immutable mode (-e 2) so rules cannot be changed without reboot.',
        'how_to_fix': 'Append "-e 2" as the LAST line of /etc/audit/rules.d/99-immutable.rules; augenrules --load; reboot to take effect.',
    },
    'aide_audit_protect': {
        'summary': 'AIDE monitors /var/log/audit for tampering.',
        'how_to_fix': 'Install aide; add /var/log/audit to /etc/aide/aide.conf.d/; aideinit; schedule daily aide --check.',
    },
    'journald': {
        'summary': 'systemd-journald configured for persistent storage, compression, sane size cap.',
        'how_to_fix': 'Edit /etc/systemd/journald.conf: Storage=persistent, Compress=yes, SystemMaxUse=2G, MaxRetentionSec=180day. Restart systemd-journald.',
    },
    'process_acct': {
        'summary': 'Process accounting (acct/psacct) is enabled.',
        'how_to_fix': 'apt install acct; systemctl enable --now acct',
    },
    'sysstat': {
        'summary': 'sysstat (sar) is collecting system performance data.',
        'how_to_fix': 'apt install sysstat; set ENABLED="true" in /etc/default/sysstat; systemctl enable --now sysstat',
    },
    'file_integrity': {
        'summary': 'AIDE (or equivalent) maintains a file-integrity baseline DB.',
        'how_to_fix': 'apt install aide; aideinit; schedule daily aide --check via cron or systemd timer.',
    },
    'debsums': {
        'summary': 'debsums verifies installed package files match their original checksums.',
        'how_to_fix': 'apt install debsums; schedule daily "debsums --all" run; alert on differences.',
    },
    'mem_protection': {
        'summary': 'Memory protection enabled (NX, ASLR full).',
        'how_to_fix': 'kernel.randomize_va_space=2 in /etc/sysctl.d/. NX requires NX-capable CPU + 64-bit kernel (default on Proxmox).',
    },
    'sysctl_hardening': {
        'summary': 'Network/kernel sysctl hardening (rp_filter, syncookies, kptr_restrict, dmesg_restrict, etc.).',
        'how_to_fix': 'PegaProx ships /etc/sysctl.d/99-pegaprox-hardening.conf with the full set. Apply via the hardening UI or sysctl --system.',
    },
    'pkg_cleanup': {
        'summary': 'Remove unused/orphaned packages.',
        'how_to_fix': 'apt autoremove --purge; apt purge $(deborphan)',
    },
    'remove_legacy_svcs': {
        'summary': 'Remove legacy/insecure services (rsh, rlogin, telnet, nis, talk).',
        'how_to_fix': 'apt purge rsh-* rlogin-* telnet telnetd talk talkd ntalk nis ypbind',
    },
    'disable_services': {
        'summary': 'Disable services not needed on a Proxmox node (cups, avahi-daemon, etc.).',
        'how_to_fix': 'systemctl disable --now cups avahi-daemon (only if your environment does not need them).',
    },
    'net_protocols': {
        'summary': 'Disable rare network protocols (DCCP, SCTP, RDS, TIPC).',
        'how_to_fix': 'Add "install <proto> /bin/true" entries to /etc/modprobe.d/cis-net.conf.',
    },
    'restrict_compilers': {
        'summary': 'Restrict gcc/cc and other build tools to root only on production servers.',
        'how_to_fix': 'chmod 700 /usr/bin/gcc* /usr/bin/cc* /usr/bin/as ld (re-evaluate if you need to build modules locally).',
    },
    'cron_hardening': {
        'summary': 'cron and at restricted to root via /etc/cron.allow and /etc/at.allow.',
        'how_to_fix': 'echo root > /etc/cron.allow; echo root > /etc/at.allow; rm -f /etc/cron.deny /etc/at.deny; chmod 640 /etc/cron.allow /etc/at.allow.',
    },
    'pam_tmpdir': {
        'summary': 'Per-user private /tmp via pam_tmpdir.',
        'how_to_fix': 'apt install libpam-tmpdir; ensure pam_tmpdir.so is referenced in /etc/pam.d/common-session.',
    },
    'pve_fail2ban': {
        'summary': 'fail2ban running with a [proxmox] jail for pveproxy/pvedaemon brute-force protection.',
        'how_to_fix': 'PegaProx > Settings > Hardening > Apply "fail2ban (PVE)". Auto-detects Debian version and picks iptables or nftables banaction.',
    },
    'apt_show_versions': {
        'summary': 'apt-show-versions is installed for tracking which packages have updates pending.',
        'how_to_fix': 'apt install apt-show-versions; schedule "apt-show-versions -u" runs to identify outdated packages.',
    },
    'backup_dns': {
        'summary': 'A secondary / backup DNS resolver is configured.',
        'how_to_fix': 'Add a second nameserver entry in /etc/resolv.conf or your systemd-resolved config.',
    },
    'postfix_banner': {
        'summary': 'Postfix mail banner does not disclose the OS / version.',
        'how_to_fix': 'In /etc/postfix/main.cf set: smtpd_banner = $myhostname ESMTP. Reload postfix.',
    },
    'pam_password_repair': {
        'summary': 'Repairs a broken /etc/pam.d/common-password stack where pam_pwhistory.so use_authtok appears without a preceding pam_pwquality.so. Triggers "Authentication token manipulation error" on every passwd call until repaired.',
        'how_to_fix': 'PegaProx > Settings > Hardening > Apply "Repair PAM password stack (recovery)". Either inserts pam_pwquality.so before pam_pwhistory.so (preferred) or strips use_authtok from pwhistory if libpam-pwquality is not installed. Backup of the original file is saved as common-password.bak.repair-<timestamp>.',
    },
    'vsnfd_disk_encryption': {
        'summary': 'Disk encryption (LUKS or ZFS native) for VS-NfD-classified data at rest.',
        'how_to_fix': 'INFORMATIONAL — must be planned at install time. PegaProx cannot retroactively encrypt; document operator decision per BSI guidance.',
    },
    'vsnfd_audit_retention': {
        'summary': 'journald MaxRetentionSec ≥ 6 months for VS-NfD audit retention.',
        'how_to_fix': 'In /etc/systemd/journald.conf set MaxRetentionSec=180day. Ensure SystemMaxUse is sized accordingly.',
    },
    'vsnfd_journald_size': {
        'summary': 'journald SystemMaxUse ≥ 1G to retain enough audit history.',
        'how_to_fix': 'In /etc/systemd/journald.conf set SystemMaxUse=1G (or larger) and restart systemd-journald.',
    },
    'vsnfd_secure_boot': {
        'summary': 'UEFI Secure Boot is enabled (or documented as compensating control).',
        'how_to_fix': 'INFORMATIONAL — enable Secure Boot in UEFI; ensure shim/grub are signed. PegaProx detects but cannot enable Secure Boot.',
    },
    'vsnfd_kernel_lockdown': {
        'summary': 'Linux kernel lockdown mode (integrity or confidentiality) is active.',
        'how_to_fix': 'Add "lockdown=integrity" (or "confidentiality") to GRUB_CMDLINE_LINUX, update-grub, reboot. Requires Secure Boot for full effect.',
    },
    'vsnfd_password_min_12': {
        'summary': 'Minimum password length 12 (BSI-conformant).',
        'how_to_fix': 'Set minlen=12 in /etc/security/pwquality.conf (PegaProx CIS profile uses minlen=14 by default which already satisfies this).',
    },
}


# ──────────────────────────────────────────────────────────────────────────
# Per-control severity (audit-style risk rating)
#
# - high          : Direct compromise / data-loss risk if missing
# - medium        : Defense-in-depth, detection or meaningful hardening gap
# - low           : Hygiene / good practice with marginal direct impact
# - informational : VS-NfD or operator-decision items that have no automated apply
# ──────────────────────────────────────────────────────────────────────────
SEVERITY = {
    # High — direct exposure
    'pam_faillock':       'high',
    'sshd_hardening':     'high',   # NS: root SSH login policy + MaxAuthTries (#500)
    'pam_nullok_removal': 'high',   # NS: blocks empty-password PAM auth (#500)
    'ssh_crypto':         'high',
    'ssh_perms':          'high',
    'file_perms':         'high',
    'pw_quality':         'high',
    'pw_hash_rounds':     'high',
    'audit_rules':        'high',
    'apparmor':           'high',
    'mem_protection':     'high',
    'pve_fail2ban':       'high',
    'usb_storage':        'high',
    'audit_immutable':    'high',
    'aide_audit_protect': 'high',
    'core_dumps':         'high',
    # Medium — detection / partial defense / config hygiene with real impact
    'pw_history':         'medium',
    'pw_aging':           'medium',
    'login_banners':      'medium',
    'file_integrity':     'medium',
    'audit_boot':         'medium',
    'auditd_service':     'medium',
    'journald':           'medium',
    'inactive_accounts':  'medium',
    'session_limit':      'medium',
    'shell_timeout':      'medium',
    'fs_modules':         'medium',
    'mount_options':      'medium',
    'sysctl_hardening':   'medium',
    'debsums':            'medium',
    'net_protocols':      'medium',
    'disable_services':   'medium',
    'remove_legacy_svcs': 'medium',
    'restrict_compilers': 'medium',
    'pam_tmpdir':         'medium',
    'cron_hardening':     'medium',
    'process_acct':       'medium',
    'sysstat':            'medium',
    'apt_show_versions':  'medium',
    'pkg_cleanup':        'medium',
    # Low — minor hygiene
    'default_umask':      'low',
    'backup_dns':         'low',
    'postfix_banner':     'low',
    # Recovery / operational fixers — not a real compliance gap, but high-severity
    # if triggered (system can't change passwords).
    'pam_password_repair': 'high',
    # Informational — VS-NfD specific, no auto-apply
    'vsnfd_disk_encryption':  'informational',
    'vsnfd_audit_retention':  'informational',
    'vsnfd_journald_size':    'informational',
    'vsnfd_secure_boot':      'informational',
    'vsnfd_kernel_lockdown':  'informational',
    'vsnfd_password_min_12':  'informational',
}


# Severity → recommended remediation timeline. Aligned with what most internal
# audit programs use (ISO 27001 surveillance audit, SOC2 Type II frequency).
RECOMMENDED_TIMELINE = {
    'high':          {'days': 30,  'label': 'Within 30 days'},
    'medium':        {'days': 90,  'label': 'Within 90 days'},
    'low':           {'days': 180, 'label': 'Within 180 days'},
    'informational': {'days': None, 'label': 'Operator decision, document outcome'},
}


# Severity → priority numeric (1 = highest).
PRIORITY_LEVEL = {
    'high':          1,
    'medium':        2,
    'low':           3,
    'informational': 4,
}


# ──────────────────────────────────────────────────────────────────────────
# Framework metadata — for the cover page / scope statement.
# Keep this current with the actually-mapped revision.
# ──────────────────────────────────────────────────────────────────────────
FRAMEWORK_META = {
    'cmmc1': {
        'full_name':    'CMMC Level 1 (FAR 52.204-21)',
        'revision':     'CMMC Model 2.0, March 2024',
        'source_url':   'https://dodcio.defense.gov/CMMC/',
        'control_count': 17,
        'note':         'Basic safeguarding of Federal Contract Information (FCI) — the 15 FAR 52.204-21 requirements, expressed as 17 CMMC practices.',
    },
    'cmmc2': {
        'full_name':    'CMMC Level 2 / NIST SP 800-171',
        'revision':     'NIST SP 800-171 Rev. 2 (Feb 2020). CMMC L2 mirrors all 110 NIST 800-171 controls.',
        'source_url':   'https://csrc.nist.gov/pubs/sp/800/171/r2/upd1/final',
        'control_count': 110,
        'note':         'Required for handling Controlled Unclassified Information (CUI). 110 controls in 14 families.',
    },
    'nist53': {
        'full_name':    'NIST SP 800-53 (Mod baseline)',
        'revision':     'NIST SP 800-53 Rev. 5, September 2020',
        'source_url':   'https://csrc.nist.gov/pubs/sp/800/53/r5/upd1/final',
        'control_count': 287,
        'note':         'Federal civilian baseline. Mod baseline = ~287 controls. PegaProx maps the technical-control subset relevant to a Linux hypervisor.',
    },
    'stig': {
        'full_name':    'DISA STIG (RHEL 9 / Ubuntu 22.04)',
        'revision':     'RHEL 9 STIG (current) + Ubuntu 22.04 STIG (current). Refs may need refresh per release.',
        'source_url':   'https://public.cyber.mil/stigs/',
        'control_count': None,
        'note':         'Defense Information Systems Agency Security Technical Implementation Guide. Refs assume RHEL 9 baseline; Ubuntu 22.04 refs are equivalent.',
    },
    'iso': {
        'full_name':    'ISO/IEC 27001:2022 Annex A',
        'revision':     'ISO/IEC 27001:2022, October 2022 — supersedes 2013 / 2017 amendments',
        'source_url':   'https://www.iso.org/standard/27001',
        'control_count': 93,
        'note':         '93 controls in 4 themes: Organizational, People, Physical, Technological. PegaProx covers the Technological controls applicable to Linux node hardening.',
    },
    'bsi': {
        'full_name':    'BSI IT-Grundschutz Kompendium',
        'revision':     'BSI IT-Grundschutz Kompendium Edition 2024',
        'source_url':   'https://www.bsi.bund.de/dok/itgs',
        'control_count': None,
        'note':         'Bundesamt für Sicherheit in der Informationstechnik. Modules SYS / OPS / NET / DER / CON / APP. PegaProx focuses on SYS.1.3 (general Linux server) and adjacent modules.',
    },
    'vs-nfd': {
        'full_name':    'VS-NfD (Verschlusssache - Nur für den Dienstgebrauch)',
        'revision':     'VS-Anweisung (VSA), based on BSI IT-Grundschutz; PegaProx adds 6 informational checks',
        'source_url':   'https://www.bsi.bund.de/EN/Themen/ZertifizierungundAnerkennung/Produktzertifizierung/Zertifizierung-und-Anerkennung-VS/zertifizierung-und-anerkennung-vs_node.html',
        'control_count': None,
        'note':         'German national restricted-use classification. PegaProx provides a Proxmox-safe BSI Grundschutz subset + 6 VS-NfD-specific informational checks.',
    },
    'dr': {
        'full_name':    'Diffusion Restreinte (II 901)',
        'revision':     'Instruction interministérielle n° 901; technical Linux baseline = ANSSI-BP-028 v2.0 (2022-10-03)',
        'source_url':   'https://cyber.gouv.fr/publications/recommandations-de-securite-relatives-un-systeme-gnulinux',
        'control_count': None,
        'note':         'French national restricted classification. II 901 sets the protection regime for DR-level information systems; PegaProx maps the technical Linux-hardening measures to ANSSI-BP-028 (the recognised French baseline). Audit-prep evidence — not a homologation.',
    },
    'rgs': {
        'full_name':    'RGS (Référentiel Général de Sécurité)',
        'revision':     'RGS v2.0; Linux-hardening implementation reference = ANSSI-BP-028 v2.0 (2022-10-03)',
        'source_url':   'https://cyber.gouv.fr/le-referentiel-general-de-securite-rgs-version-20',
        'control_count': None,
        'note':         'French general security framework for administrations. RGS points to ANSSI technical guides for implementation; PegaProx maps the Linux node-hardening subset to ANSSI-BP-028. Technical-config evidence only.',
    },
}


# ──────────────────────────────────────────────────────────────────────────
# Compliance posture rating thresholds. Used by the PDF report to label the
# overall coverage with a categorical posture statement.
#
# Important: high-severity controls are weighted more — a cluster that passes
# 100% of LOW but 0% of HIGH is not "substantially compliant". The function
# `evaluate_posture(stats)` applies this logic.
# ──────────────────────────────────────────────────────────────────────────
POSTURE_LEVELS = [
    # ordered from best to worst; first matching threshold wins
    {'id': 'substantial',  'label': 'Substantially Compliant',
     'min_overall_pct': 95, 'min_high_pct': 100,
     'description': 'Coverage is materially complete with all high-severity controls satisfied. Suitable to enter formal audit with focus on documentation and process evidence.'},
    {'id': 'largely',      'label': 'Largely Compliant',
     'min_overall_pct': 85, 'min_high_pct': 90,
     'description': 'Most controls are satisfied; remaining gaps include at most a small number of medium-severity items. Closeable in a single remediation cycle.'},
    {'id': 'partial',      'label': 'Partially Compliant',
     'min_overall_pct': 65, 'min_high_pct': 70,
     'description': 'Significant control gaps remain, including high-severity items. Coverage is below the level expected to enter a formal certification audit.'},
    {'id': 'marginal',     'label': 'Marginally Compliant',
     'min_overall_pct': 40, 'min_high_pct': 0,
     'description': 'Substantial remediation required across multiple control families before any audit deliverable can be produced.'},
    {'id': 'noncompliant', 'label': 'Non-Compliant',
     'min_overall_pct': 0,  'min_high_pct': 0,
     'description': 'Comprehensive remediation required. Recommend a structured hardening project before re-running the assessment.'},
]


# ──────────────────────────────────────────────────────────────────────────
# Glossary — for auditors / managers who don't speak Linux fluently.
# Plain-language definitions of the technical terms used in the report.
# ──────────────────────────────────────────────────────────────────────────
GLOSSARY = {
    'AIDE':        'Advanced Intrusion Detection Environment — a host-based file-integrity monitor for Linux. Maintains a hash database of selected files; alerts on unauthorized modification.',
    'AppArmor':    'Linux Mandatory Access Control framework; restricts what files and capabilities a given program can access, even when running as root.',
    'auditd':      'The Linux audit daemon — collects security-relevant kernel and userspace events (logon, syscalls, file access, privilege changes) into a tamper-resistant log.',
    'journald':    'systemd-journald — the system log collector on modern Linux. Replaces the older syslog file format with a structured, indexable journal.',
    'LUKS':        'Linux Unified Key Setup — the standard full-disk-encryption format on Linux.',
    'PAM':         'Pluggable Authentication Modules — the authentication framework for Linux. Modules implement password complexity, account lockout, MFA, etc.',
    'pwquality':   'libpwquality — Linux password complexity policy library used by PAM (length, character classes, dictionary checks).',
    'sysctl':      'Linux kernel runtime parameter interface (e.g. network stack tuning, memory protections). Settings live in /etc/sysctl.d/.',
    'ASLR':        'Address Space Layout Randomization — a memory protection that randomizes the location of executable code and data, making exploitation harder.',
    'NX':          'No-eXecute — CPU-enforced memory protection bit that prevents code execution in data pages.',
    'TPM':         'Trusted Platform Module — hardware crypto chip used for measured boot, key sealing and secure storage of credentials.',
    'yescrypt':    'Modern password-hashing function (replaces SHA-512 crypt); designed to be hard to crack on GPUs/ASICs.',
    'PVE':         'Proxmox Virtual Environment — the open-source hypervisor management platform PegaProx orchestrates.',
    'PegaProx':    'The multi-cluster Proxmox VE / XCP-ng management platform that produced this report.',
    'SUID':        'Set User ID — a special permission bit that runs an executable with the privileges of its owner instead of the calling user.',
    'fail2ban':    'Log-based brute-force protection — bans IPs that exceed a failed-login threshold via firewall rules.',
    'KEX':         'Key Exchange algorithm — the SSH protocol step where client and server agree on a shared session key.',
    'CIS':         'Center for Internet Security — publishes hardening benchmarks for Linux, Windows, container platforms, etc.',
    'CMMC':        'Cybersecurity Maturity Model Certification — U.S. Department of Defense framework for protecting Federal Contract Information and Controlled Unclassified Information.',
    'NIST 800-171': 'NIST publication: Protecting Controlled Unclassified Information in Nonfederal Systems and Organizations. The technical baseline behind CMMC L2.',
    'NIST 800-53':  'NIST publication: Security and Privacy Controls for Information Systems and Organizations. Federal civilian baseline.',
    'STIG':        'DISA Security Technical Implementation Guide — DoD-mandated configuration standard.',
    'ISO 27001':   'International standard for Information Security Management Systems (ISMS). Annex A lists the controls organisations are expected to evaluate.',
    'NIS2':        'Network and Information Security Directive 2 — EU regulation for operators of essential services (effective Oct 2024).',
    'KRITIS':      'German implementation of NIS2 — Critical Infrastructure regulation by the BSI.',
    'BSI':         'Bundesamt für Sicherheit in der Informationstechnik — the German Federal Office for Information Security.',
    'IT-Grundschutz': 'BSI methodology and control catalogue for information security in German government / industry.',
    'VS-NfD':      'Verschlusssache - Nur für den Dienstgebrauch — German national classification level "For Official Use Only".',
    'ANSSI':       'Agence nationale de la sécurité des systèmes d\'information — the French national cybersecurity authority (the French counterpart to the German BSI).',
    'ANSSI-BP-028': 'ANSSI\'s "Recommandations de configuration d\'un système GNU/Linux" (v2.0, 2022) — the recognised French Linux system-hardening baseline (numbered recommendations R1–R80).',
    'Diffusion Restreinte': 'French national "Restricted" protection level for sensitive information; the information-system protection regime is set by Instruction interministérielle n° 901 (II 901). Rough analogue of German VS-NfD.',
    'II 901':      'Instruction interministérielle n° 901 — French regulation defining the protection of information systems handling Diffusion Restreinte information.',
    'RGS':         'Référentiel Général de Sécurité — the French general security framework mandatory for administrations\' information systems (crypto, authentication, audit, timestamping).',
    'FIPS 140-3':  'Federal Information Processing Standard for cryptographic modules. Validates the implementation of the crypto library itself, not the system hardening.',
    'OVMF':        'Open Virtual Machine Firmware — the UEFI implementation used in QEMU / KVM virtual machines.',
    'Secure Boot': 'UEFI feature that allows only firmware-signed boot loaders to run, preventing certain rootkit/bootkit attacks.',
}


# ──────────────────────────────────────────────────────────────────────────
# Standardised audit methodology language. Reused verbatim by the PDF.
# ──────────────────────────────────────────────────────────────────────────
METHODOLOGY = {
    'overview': (
        'PegaProx executes deterministic checks over SSH against each in-scope '
        'cluster node and compares the observed configuration against the expected '
        'value defined by the selected hardening profile. Each check has a '
        'documented "check command" and an expected output; deviations are recorded '
        'as findings. No manual sampling is performed: 100% of in-scope nodes are '
        'evaluated on every report run.'
    ),
    'procedures': [
        ('Inquiry',         'PegaProx reads the configured hardening profile (e.g. "CMMC L2") and resolves it to a list of internal control checks via FRAMEWORK_MAPPING.'),
        ('Inspection',      'PegaProx connects to each node via SSH and inspects configuration files, runtime kernel parameters, service status and file permissions.'),
        ('Re-performance',  'PegaProx executes the documented check command on each node and verifies the actual output matches the expected value.'),
        ('Evidence capture','When verbose mode is enabled, PegaProx records the exact check command and the actual node output for each control, included in Appendix C.'),
    ],
    'sampling': '100% of in-scope cluster nodes evaluated. No statistical sampling applied. SSH unreachable nodes are reported as "not evaluated" rather than passed or failed.',
    'criteria': 'Mappings between internal checks and framework control IDs are maintained in pegaprox/core/compliance_mapping.py. Mappings should be re-verified against the current revision of the applicable framework before the report is used as input to a formal audit.',
    'limitations': (
        'PegaProx assesses technical configuration only. The following are out of scope and must be evaluated separately by a qualified auditor: '
        '(1) administrative policies and procedures, '
        '(2) personnel security and awareness training, '
        '(3) physical security of the data centre, '
        '(4) incident response plans and tabletop exercises, '
        '(5) supply chain risk management, '
        '(6) the cryptographic module validation status (FIPS 140-3 requires a separately validated module — not satisfiable on stock Proxmox).'
    ),
}


# ──────────────────────────────────────────────────────────────────────────
# Helper functions
# ──────────────────────────────────────────────────────────────────────────

def get_mapping(framework_id):
    """Return the (mapping, family_labels) tuple for a framework id, or empty if unknown."""
    return FRAMEWORK_MAPPING.get(framework_id, {}), FAMILY_LABELS


def remediation_for(internal_id):
    """Return remediation hint dict, or a stub if not present."""
    return REMEDIATION.get(internal_id, {
        'summary': f'No prescribed remediation for {internal_id}.',
        'how_to_fix': 'Consult PegaProx Hardening tool for the apply command, or the relevant CIS / STIG benchmark.',
    })


def severity_for(internal_id):
    """Return severity level for an internal control id (high/medium/low/informational)."""
    return SEVERITY.get(internal_id, 'medium')  # conservative default


def framework_meta(framework_id):
    """Return metadata dict for a framework id, or a stub if unknown."""
    return FRAMEWORK_META.get(framework_id, {
        'full_name': framework_id,
        'revision':  'Unknown revision',
        'source_url': '',
        'control_count': None,
        'note': '',
    })


def evaluate_posture(overall_pct, high_pct):
    """Pick the posture level for a given (overall_pct, high_severity_pct) pair.

    Returns the posture dict from POSTURE_LEVELS, falling back to noncompliant.
    """
    if overall_pct is None:
        overall_pct = 0
    if high_pct is None:
        high_pct = 100  # no high-severity controls in scope => gate vacuously satisfied (matches dashboard.js)
    for lvl in POSTURE_LEVELS:
        if overall_pct >= lvl['min_overall_pct'] and high_pct >= lvl['min_high_pct']:
            return lvl
    return POSTURE_LEVELS[-1]
