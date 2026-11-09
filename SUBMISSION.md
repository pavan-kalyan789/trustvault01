# TrustVault — RISE Challenge Submission Overview (SUBMISSION.md)

**Project Name:** TrustVault — Secure Document Sharing with a Real Audit Trail  
**Track:** RISE Challenge — Enterprise Cybersecurity & Zero-Trust Applications  
**Primary Architect & Security Reviewer:** Application Security Engineering Team  

---

## 1. Project Overview & Deliverables

TrustVault is an enterprise cybersecurity platform designed to guarantee document privacy, prevent Insecure Direct Object References (IDOR), enforce instantaneous permission revocation, and maintain an immutable, tamper-evident audit ledger.

### Key Deliverables:
- **Centralized Authorization Broker:** Server-side enforcement evaluating database grants on every request; returns `404 Not Found` for unauthorized attempts to prevent horizontal reconnaissance.
- **Immediate Permission Revocation:** Zero-token delay; revoking access in the database immediately blocks subsequent downloads and views.
- **Administrative Separation of Duty:** Administrators govern users and inspect audit logs, but cannot automatically download or preview confidential documents without explicit grants.
- **Private Object Storage:** Files stored outside web-accessible roots under mode 0600 with random UUID storage keys.
- **Strict File Validation:** Pre-flight and server-side magic byte inspection rejecting MIME spoofing, executable binaries (PE/ELF), path traversal, and oversized uploads (>10 MB).
- **Tamper-Evident Audit Trail:** HMAC-SHA256 hash-chained event ledger with serialized concurrency locking and live verification engine.
- **Automated Security Test Suite:** 20 Vitest integration tests covering authentication, IDOR, revocation, storage, audit integrity, and mutation testing.
- **Interactive Security & Pentest Console:** Real-time in-app security verification console executing all 20 threat vectors live against backend endpoints.

---

## 2. Default Demo Accounts

For immediate evaluation, the platform includes a top-bar **1-Click Demo Switcher** and four pre-seeded accounts:

| Role | Email | Password | Primary Capabilities |
| :--- | :--- | :--- | :--- |
| **Administrator (CSO)** | `admin@trustvault.local` | `TrustVault2026!Admin` | User lifecycle, system telemetry, audit chain verification (No direct document reading). |
| **Document Owner (Legal)** | `owner@trustvault.local` | `TrustVault2026!Owner` | Upload documents, grant READ/EDIT access, execute immediate revocation, soft-delete. |
| **Viewer (Compliance)** | `viewer@trustvault.local` | `TrustVault2026!Viewer` | Download shared documents, view authorized metadata (Cannot upload or modify). |
| **Other Viewer (Contractor)**| `other@trustvault.local` | `TrustVault2026!Other` | Unshared account demonstrating complete 404 anti-IDOR isolation. |

---

## 3. Automated Verification Commands

```bash
# Run full automated security test suite (20 tests + mutation testing)
npm run test

# Run security test suite specifically
npm run test:security

# Run TypeScript compilation check
npm run lint

# Build production bundle
npm run build
```

---

## 4. Security Guarantees & Verification Matrix

- **IDOR Protection:** Verified by automated regression tests and live pentest console.
- **Immediate Revocation:** Verified on live downloads right after grant deletion.
- **Audit Non-Repudiation:** Verified by recursive HMAC-SHA256 chain calculation from genesis.
- **Mutation Tested:** Proved that removing central authorization causes test failures, and restoring check restores pass status.
