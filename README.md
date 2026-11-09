# TrustVault — Secure Document Sharing with a Real Audit Trail

**Tagline:** Secure Documents. Controlled Access. Verifiable Trust.  
**Built for:** RISE Challenge — Enterprise Secure Document Sharing  

TrustVault is an enterprise cybersecurity platform prioritizing zero-trust authorization, Insecure Direct Object Reference (IDOR) prevention, instantaneous permission revocation, and an append-only, tamper-evident HMAC-SHA256 audit ledger.

---

## Key Security Features

1. **Anti-IDOR Centralized Authorization:**
   - Every protected request queries current database grants at request time.
   - Unauthorized requests return `HTTP 404 Not Found` to prevent document existence discovery.
   - Every denied attempt records an `ACCESS_DENIED` event in the audit ledger.

2. **Immediate Access Revocation:**
   - Revoking a grant sets `isActive = false` in the database immediately.
   - Subsequent download or preview requests are rejected instantaneously with zero token caching.
   - Streaming responses enforce `Cache-Control: no-store, private` and `X-Content-Type-Options: nosniff`.

3. **Administrative Separation of Duty:**
   - Administrators manage users, monitor security telemetry, and verify audit integrity.
   - Administrators do **not** possess automatic document download or decryption privileges.

4. **Private Storage & Magic Byte Validation:**
   - Files are stored with random UUID tokens outside the web directory.
   - Detects true file signatures: PDF (`%PDF-`), PNG, JPEG, ZIP containers (DOCX/XLSX).
   - Rejects PE/ELF executables, path traversal filenames, and files >10 MB.

5. **Tamper-Evident HMAC-SHA256 Audit Trail:**
   - Recursive hash-chained ledger starting from a defined genesis anchor.
   - Serialized append lock preventing race conditions on concurrent writes.
   - Verification endpoint detects altered, missing, or out-of-order events.

6. **Interactive Security & Pentest Console:**
   - In-app penetration testing console executing all 20 threat vectors live against backend endpoints.
   - Full mutation testing proving the test suite catches bypassed authorization.

---

## Quick Start & Local Development

```bash
# 1. Install dependencies
npm install

# 2. Run automated test suite (20 security integration tests + mutation testing)
npm run test

# 3. Start development server (Node.js + Express + Vite dev server on port 3000)
npm run dev
```

Open `http://localhost:3000` in your browser.

---

## Pre-Seeded Demo Accounts

The top navigation includes a **1-Click Demo Switcher** to seamlessly evaluate different roles:

- **Administrator (CSO):** `admin@trustvault.local` / `TrustVault2026!Admin`
- **Document Owner (Legal Counsel):** `owner@trustvault.local` / `TrustVault2026!Owner`
- **Viewer (Compliance Auditor):** `viewer@trustvault.local` / `TrustVault2026!Viewer`
- **Other Viewer (Contractor):** `other@trustvault.local` / `TrustVault2026!Other`

---

## Documentation Index

- `SECURITY.md` — Vulnerability review, attack methods, mitigations, and regression tests.
- `THREATS.md` — STRIDE enterprise threat model with >20 analyzed threat vectors.
- `PROMPTS.md` — Real AI-assisted security engineering log and manual corrections.
- `API.md` — Documented REST API endpoints, authorization checks, and payloads.
- `DEPLOYMENT.md` — Production Google Cloud Run, Firestore, and Cloud Storage setup.
- `SUBMISSION.md` — Challenge submission deliverables, credentials, and verification matrix.
- `firestore.rules` — Zero-trust rules denying direct client-side writes to audit and grants.
