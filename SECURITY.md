# Security Policy

## Reporting a Vulnerability

The PegaProx team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose any issues you find.

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report them privately, either via
[GitHub Security Advisories](https://github.com/PegaProx/project-pegaprox/security/advisories/new)
or via email to:

📧 **[support@pegaprox.com](mailto:support@pegaprox.com)**

### What to Include

To help us understand and resolve the issue as quickly as possible, please include:

- A description of the vulnerability and its potential impact
- Step-by-step instructions to reproduce the issue
- Affected version(s) of PegaProx
- Any relevant screenshots, logs, or proof-of-concept code
- Your suggested fix or mitigation, if any

### Response Timeline

| Action | Timeframe |
|---|---|
| Acknowledgment of your report | Within 48 hours |
| Initial assessment and triage | Within 5 business days |
| Status update on the fix | Within 10 business days |
| Security patch release | Depending on severity |

PegaProx is maintained by a small volunteer team, so these are targets rather than guarantees.
We will keep you informed throughout the process and credit you in the advisory (unless you prefer to remain anonymous).

## Supported Versions

Security fixes are made for the latest release only and ship as a new release. Older releases
do not get backports.

| Version | Supported |
|---|---|
| Latest release | ✅ Yes |
| Older releases | ❌ No, please update |

Please check that an issue still exists in the latest release before you report it.

## Verifying Releases

Since 1.4.0, every release carries a CycloneDX SBOM as a release asset
(`pegaprox-v<version>.cdx.json`), built in CI when the release is published. It lists the
Python packages a fresh install of the release resolves from `requirements.txt` and the
browser libraries the web interface loads, each with its version. Operating system packages
inside the Docker and appliance images are not part of it.

Since 1.4.1, the Docker image and the VM (qcow2) and LXC (tar.xz) appliance images carry
signed build provenance (GitHub artifact attestations, logged with Sigstore). You can verify
them with the GitHub CLI:

```bash
# Docker image (version without a leading v, for example 1.4.1)
gh attestation verify oci://ghcr.io/pegaprox/pegaprox:<version> -R PegaProx/project-pegaprox

# VM or LXC appliance image
gh attestation verify <file> -R PegaProx/project-pegaprox
```

OVA files, `SHA256SUMS.txt`, the SBOM and the Debian packages are not attested yet.

Security advisories are published at
https://github.com/PegaProx/project-pegaprox/security/advisories.

The SBOM and attestations are provided as is, for your own inventory and compliance work,
for example under the EU Cyber Resilience Act. Like the software itself, they come without
warranty and create no support obligation.

## Scope

The following areas are **in scope** for security reports:

- Authentication and authorization (login, 2FA, session management, RBAC, LDAP/OIDC)
- Proxmox VE, XCP-ng and ESXi credential handling and storage
- Encryption of data at rest (database, configuration files, key storage)
- Cross-site scripting (XSS), cross-site request forgery (CSRF), and injection vulnerabilities
- Privilege escalation between user roles
- VM-level ACL bypasses and multi-tenancy isolation failures
- noVNC and xterm.js console access control
- SSL/TLS configuration and certificate handling
- SSH host key verification
- Remote code execution or command injection via the web interface or API
- Information disclosure through API responses, error messages, or logs
- Integrity of the audit log
- The build and release pipeline (CI workflows, signed artifacts)

Please test only against an installation you run yourself or are allowed to test. Do not
scan or attack pegaprox.com and its subdomains, the update and package mirrors, or the GitHub
repository and its CI (for example with pull requests that try to exploit a workflow). Report
issues there from the public code and configuration instead.

The following are **out of scope**:

- Vulnerabilities in Proxmox VE, XCP-ng or ESXi themselves (please report those to the respective vendor)
- Denial-of-service (DoS) attacks without a demonstrated security impact
- Social engineering or phishing attacks against PegaProx users or team members
- Issues in third-party dependencies without a demonstrated exploit path in PegaProx
- Reports from automated scanners without manual verification
- AI-generated reports (from LLMs or AI-based scanners) that the reporter has not verified
  manually. Please confirm the issue against a real PegaProx installation and include a
  working proof of concept
- Missing security headers that have no demonstrated exploitability
- Vulnerabilities requiring physical access to the server

## Security Architecture

PegaProx implements the following security measures:

- **Database encryption at rest:** Where the `sqlcipher3` module is available, the whole
  database is encrypted with SQLCipher 4 (AES-256-CBC + HMAC-SHA512). That is the case for
  installs with `deploy.sh` or pip on Linux x86_64 and aarch64, macOS and Windows, for the
  amd64 and arm64 Docker images and appliance images, and for the Debian package on amd64.
  The 32-bit ARM Docker image uses plain SQLite, and so does the Debian package on arm64
  where its `python3-sqlcipher3` holds the x86_64 module only (the one of apt.pegaprox.com,
  and the one the appliance images build, is built for arm64). On every install,
  sensitive fields (cluster passwords, SSH keys, API token secrets, TOTP secrets) are also
  encrypted individually with AES-256-GCM. PegaProx warns at startup when the database stays
  plain SQLite, and the `--keystore-status` option shows the active mode and the key source.
- **Key management:** The master key is loaded from `PEGAPROX_DB_KEY`, a systemd
  `LoadCredentialEncrypted` credential, `PEGAPROX_KEY_FILE` or `/etc/pegaprox/secret.key`.
  `deploy.sh` creates `/etc/pegaprox/secret.key`, the Debian package before PegaProx starts
  (an appliance at its first start). A package install whose database was encrypted before
  keeps that key: it is copied there from the config directory, where the old file stays.
  Docker keeps its key in the config directory by default, so treat a backup of `config/` as
  secret or move the key out of it.
- **Encrypted exports:** Configuration backups are always password-protected and encrypted
  with AES-256-GCM, with the key derived from the password by PBKDF2-HMAC-SHA256.
- **Password hashing:** Local user passwords are hashed with Argon2id. Hashes from older
  versions are upgraded at the next login.
- **Two-factor authentication:** TOTP and WebAuthn (FIDO2). Administrators can require 2FA for
  all users.
- **Transport security:** The web interface is served over HTTPS, with a self-signed
  certificate until you add your own or use the built-in ACME support. TLS certificate
  verification can be enabled per connection for Proxmox VE clusters, XCP-ng pools and ESXi
  hosts, and for LDAP in the LDAP settings. It is off by default because these systems usually
  start with self-signed certificates. PegaProx logs a security warning while it is off for a
  Proxmox VE cluster or for LDAP.
- **SSH host key verification:** Host keys are pinned on first contact and a changed key is
  rejected. A strict mode that also rejects unknown hosts is enabled with
  `PEGAPROX_SSH_STRICT_HOST_KEYS=1`.
- **Session management:** Sessions end after 8 hours of inactivity by default (configurable)
  and 12 hours after sign-in at the latest. Sessions started with "Remember me" last up to
  7 days.
- **Brute-force protection:** Failed logins lock the client IP and the account temporarily,
  and the API is rate-limited per client IP.
- **CSRF protection:** Origin and Referer checks on state-changing API requests.
- **Role-based access control:** Built-in roles (admin, user, viewer) and custom roles with
  granular permissions.
- **VM-level ACLs:** Fine-grained per-VM permissions for multi-tenant environments.
- **Audit logging:** User actions are recorded in an HMAC-signed hash chain that can be
  verified, with a configurable retention period, and can be forwarded to a SIEM (syslog,
  Splunk, Elasticsearch or HTTP).
- **Supply chain:** All GitHub Actions in CI are pinned to commit SHAs, workflows run with a
  read-only token by default and get write permissions per job only where needed. Releases
  carry an SBOM and signed build provenance (see [Verifying Releases](#verifying-releases)).

## AI-Assisted Development

PegaProx accepts AI-assisted contributions under the rules in
[CONTRIBUTING.md](CONTRIBUTING.md): the contributor must have read, understood and tested every
line, and must name the assistant or model used in the pull request. We record this for
licensing and compliance review. Every pull request runs the test suite (for first-time
contributors after a maintainer approves the run) and is reviewed by a maintainer before merge.

## Disclosure Policy

- We follow a **coordinated disclosure** model. We ask that you give us a reasonable amount of time to address the vulnerability before making any information public.
- We will coordinate with you on the disclosure timeline and, where it applies, request a CVE identifier through GitHub.
- We will publicly acknowledge your contribution in the release notes and security advisory (with your permission).

## Safe Harbor

For research on installations you run yourself or are allowed to test, within the scope
above, we consider security research conducted in accordance with this policy to be:

- **Authorized** under applicable anti-hacking laws, and we will not initiate or support legal action against you for accidental, good-faith violations of this policy
- **Exempt** from restrictions in our terms of service that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy
- **Lawful**, helpful, and conducted in the overall interest of the security of the internet

You are expected, as always, to comply with all applicable laws. If at any point you have concerns or are uncertain whether your security research is consistent with this policy, please reach out to us at [support@pegaprox.com](mailto:support@pegaprox.com) before going any further.

## Best Practices for Users

To keep your PegaProx installation secure:

1. **Finish the first-run setup right away.** PegaProx has no default web login: the setup
   creates the admin account with a password you choose. Keep the port reachable only from
   trusted networks until it is done. On the prebuilt appliance, change the password of the
   OS user `pegaprox_admin` on first boot.
2. **Enable 2FA** for all user accounts, especially administrators, preferably with WebAuthn.
3. **Use HTTPS** with a valid TLS certificate in production instead of the self-signed one.
4. **Restrict network access** to the PegaProx web interface (port 5000, and 5001-5002 for the
   consoles) using firewall rules.
5. **Keep PegaProx updated** to the latest version.
6. **Use a dedicated Proxmox VE user or API token** for each cluster connection instead of
   `root@pam`, with only the privileges PegaProx uses (see
   [docs/proxmox-permissions.md](docs/proxmox-permissions.md)). This narrows API access only;
   features that need a shell still use SSH to the nodes. If you add a cluster with a
   password, PegaProx creates an API token for that user (named `pegaprox_` followed by six
   digits) without privilege separation and without expiry, and deletes it when you remove the
   cluster. If the cluster was unreachable at that moment, delete the token in Proxmox VE
   (Datacenter → Permissions → API Tokens).
7. **Enable TLS certificate verification** for cluster and LDAP connections, using a trusted
   certificate or your own CA.
8. **Enable strict SSH host key checking** (`PEGAPROX_SSH_STRICT_HOST_KEYS=1`) once all nodes
   are known.
9. **Use full-database encryption** if you need the database encrypted as a whole (an install
   with SQLCipher, see above), and store the master key outside the data directory, for
   example with systemd `LoadCredentialEncrypted`.
10. **Review audit logs** regularly for suspicious activity, or forward them to your SIEM.
11. **Apply the principle of least privilege** when assigning PegaProx user roles and VM ACLs.

## Contact

For security-related inquiries: **[support@pegaprox.com](mailto:support@pegaprox.com)**

---

*This policy is inspired by industry best practices and may be updated from time to time.*
