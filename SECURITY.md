# Security Policy

## Reporting a Vulnerability

The PegaProx team takes security vulnerabilities seriously. We appreciate your efforts to responsibly disclose any issues you find.

**Please do NOT report security vulnerabilities through public GitHub issues, discussions, or pull requests.**

Instead, please report them via email to:

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

We will keep you informed throughout the process and credit you in the advisory (unless you prefer to remain anonymous).

## Supported Versions

| Version | Supported |
|---|---|
| >= 0.9.2 | ✅ Yes |
| < 0.9.2 | ❌ No |

We strongly recommend always running the latest version of PegaProx.

## Scope

The following areas are **in scope** for security reports:

- Authentication and authorization (login, 2FA, session management, RBAC)
- Proxmox API credential handling and storage
- Encryption of data at rest (SQLite database, configuration files)
- Cross-site scripting (XSS), cross-site request forgery (CSRF), and injection vulnerabilities
- Privilege escalation between user roles (Admin, Operator, Viewer)
- VM-level ACL bypasses and multi-tenancy isolation failures
- noVNC console access control
- SSL/TLS configuration and certificate handling
- Remote code execution or command injection via the web interface
- Information disclosure through API responses, error messages, or logs

The following are **out of scope**:

- Vulnerabilities in Proxmox VE itself (please report those to the Proxmox team)
- Denial-of-service (DoS) attacks without a demonstrated security impact
- Social engineering or phishing attacks against PegaProx users or team members
- Issues in third-party dependencies without a demonstrated exploit path in PegaProx
- Reports from automated scanners without manual verification
- Missing security headers that have no demonstrated exploitability
- Vulnerabilities requiring physical access to the server

## Security Architecture

PegaProx implements the following security measures:

- **Encryption at rest:** All sensitive data is encrypted with AES-256-GCM
- **Password hashing:** User passwords are hashed using Argon2id
- **Transport security:** HTTPS is enforced for all production deployments
- **Session management:** Tokens expire automatically after inactivity
- **Brute-force protection:** Rate limiting is applied to authentication endpoints
- **Role-based access control:** Permission models 
- **VM-level ACLs:** Fine-grained per-VM permissions for multi-tenant environments
- **Audit logging:** All user actions are logged for accountability
- **Update integrity verification:** SHA256 hash verification for update archives (May 2026)

### Update Security (May 2026 Enhancement)

PegaProx implements cryptographic verification of update archives to prevent supply-chain attacks:

- **SHA256 verification:** All update archives are verified against a SHA256 hash published in `version.json`
- **Protected files:** Critical files like `requirements.txt` are protected from being overwritten by updates
- **Audit trail:** All update attempts (successful, failed, or unverified) are logged to the audit log
- **Backward compatibility:** Updates without hashes proceed with a security warning (for legacy compatibility)

**For update publishers:** To generate the hash for a new release:
```bash
sha256sum main.tar.gz
# Add the output to version.json as "archive_sha256": "hash_value"
```

**For administrators:** Updates will be rejected if:
- The downloaded archive hash does not match the expected hash in `version.json`
- This protects against man-in-the-middle attacks and compromised update sources

## Disclosure Policy

- We follow a **coordinated disclosure** model. We ask that you give us a reasonable amount of time to address the vulnerability before making any information public.
- We will coordinate with you on the disclosure timeline and, if applicable, assign a CVE identifier.
- We will publicly acknowledge your contribution in the release notes and security advisory (with your permission).

## Safe Harbor

We consider security research conducted in accordance with this policy to be:

- **Authorized** under applicable anti-hacking laws, and we will not initiate or support legal action against you for accidental, good-faith violations of this policy
- **Exempt** from restrictions in our terms of service that would interfere with conducting security research, and we waive those restrictions on a limited basis for work done under this policy
- **Lawful**, helpful, and conducted in the overall interest of the security of the internet

You are expected, as always, to comply with all applicable laws. If at any point you have concerns or are uncertain whether your security research is consistent with this policy, please reach out to us at [support@pegaprox.com](mailto:support@pegaprox.com) before going any further.

## Best Practices for Users

To keep your PegaProx installation secure:

1. **Change default credentials immediately** after the first login
2. **Enable 2FA** for all user accounts, especially administrators
3. **Use HTTPS** with a valid TLS certificate in production
4. **Restrict network access** to the PegaProx web interface (port 5000) using firewall rules
5. **Keep PegaProx updated** to the latest version
6. **Use strong, unique root credentials** for each Proxmox cluster connection
7. **Review audit logs** regularly for suspicious activity
8. **Apply the principle of least privilege** when assigning user roles

## Contact

For security-related inquiries: **[support@pegaprox.com](mailto:support@pegaprox.com)**

---

*This policy is inspired by industry best practices and may be updated from time to time. Last updated: March 2026.*
