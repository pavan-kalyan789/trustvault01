# TrustVault — AI-Assisted Security Development Log (PROMPTS.md)

This log records real AI-assisted security engineering sessions, discovered vulnerabilities, and manual security corrections during the build of TrustVault.

---

### Session Entry 1: Authorization Architecture & Centralized Decision Broker
- **Date:** 2026-11-09
- **Prompt Summary:** Implement a centralized authorization service for document access (READ, EDIT, OWNER) preventing Insecure Direct Object References (IDOR), and ensure administrators cannot automatically download confidential files.
- **What AI Generated:**
  - `src/server/authz.ts` with `canReadDocument()`, `canEditDocument()`, and `requireDocumentAccess()` middleware.
- **Specific Errors / Security Weaknesses Discovered:**
  - Initial check allowed administrators (`user.role === 'admin'`) to bypass `canReadDocument()`. This directly violated the specification: *"Administrator must NOT automatically have permission to read, preview, download, edit, or delete every document. Administrative privileges are not equivalent to document ownership."*
  - The middleware originally returned `HTTP 403 Forbidden` on unauthorized access, which allows attackers to enumerate document existence by probing sequential IDs (Information Disclosure).
- **Manual Corrections Applied:**
  - Removed admin bypass from `canReadDocument()` and `canEditDocument()`. Admins require an explicit permission grant just like any other user to download document bytes.
  - Changed unauthorized responses to `HTTP 404 Not Found` with message *"Document not found or access denied"*, preventing document existence disclosure.
  - Linked all denied attempts directly into `auditEngine.logEvent({ action: 'ACCESS_DENIED', outcome: 'DENIED' })`.
- **Git Commit Link:** Pending initial repository push.

---

### Session Entry 2: Immediate Access Revocation & Cache Prevention
- **Date:** 2026-11-09
- **Prompt Summary:** Implement immediate permission revocation so that revoking a grant takes effect instantaneously across all subsequent requests without token latency or stale cache reuse.
- **What AI Generated:**
  - `DELETE /api/documents/:id/permissions/:grantId` endpoint and database grant query logic.
- **Specific Errors / Security Weaknesses Discovered:**
  - Standard file streaming routes often leave HTTP caching headers default (`Cache-Control: public, max-age=...`), which causes browsers and intermediate corporate proxies to serve cached document copies even after permission revocation commits to the database.
- **Manual Corrections Applied:**
  - Hardened streaming headers on `GET /api/documents/:id/download` and `GET /api/documents/:id/preview`:
    - `Cache-Control: no-store, private`
    - `Pragma: no-cache`
    - `X-Content-Type-Options: nosniff`
  - Re-evaluates `getActiveGrant()` against current database state right before reading storage bytes into memory.
  - Added unit and integration tests proving access before revocation returns 200, and access after revocation immediately returns 404.
- **Git Commit Link:** Pending initial repository push.

---

### Session Entry 3: Tamper-Evident HMAC-SHA256 Audit Trail & Concurrency Lock
- **Date:** 2026-11-09
- **Prompt Summary:** Build an append-only cryptographic audit chain using HMAC-SHA256 with server-side secrets, backward hash pointers from genesis, and verification endpoint.
- **What AI Generated:**
  - `AuditEngine` with hash calculation over event fields and `prevHash`.
- **Specific Errors / Security Weaknesses Discovered:**
  - Concurrent audit writes (e.g., simultaneous file downloads or uploads) created race conditions where multiple events read the same `prevHash` before appending, causing chain branches and broken verification.
  - Metadata objects passed to HMAC calculation were unsorted, causing non-deterministic JSON string serialization across different Node runtime calls.
- **Manual Corrections Applied:**
  - Added serialized promise queue (`this.appendQueue`) in `AuditEngine` ensuring strict linear transaction order for all event appends.
  - Standardized canonical metadata sorting via `JSON.stringify(meta, Object.keys(meta).sort())` to guarantee deterministic HMAC hashing.
  - Created anchored cryptographic checkpoints (`auditCheckpoints`) with independent HMAC keys.
- **Git Commit Link:** Pending initial repository push.

---

### Session Entry 4: Binary Magic Byte Validation & Anti-MIME Spoofing
- **Date:** 2026-11-09
- **Prompt Summary:** Implement strict file validation preventing executable ingestion, MIME spoofing, oversized uploads, and path traversal in filenames.
- **What AI Generated:**
  - `validateUploadedFile()` checking file extensions and basic MIME strings.
- **Specific Errors / Security Weaknesses Discovered:**
  - Checking `req.file.mimetype` alone trusted the client-supplied header. An attacker could upload a dangerous Windows PE binary (`.exe`) or shell script and declare `Content-Type: application/pdf`.
- **Manual Corrections Applied:**
  - Added raw binary buffer signature inspection (`detectMagicBytes`):
    - Reads true header bytes (`%PDF-`, `89 50 4E 47`, `FF D8 FF`, `50 4B 03 04`).
    - Explicitly detects PE executable (`MZ`, `0x4D 0x5A`) and ELF (`\x7FELF`) binaries and aborts with security violations.
    - Added filename sanitization stripping path traversal sequences (`../`, control characters).
- **Git Commit Link:** Pending initial repository push.

---

### Session Entry 5: Mutation Testing Verification
- **Date:** 2026-11-09
- **Prompt Summary:** Execute mutation testing by temporarily bypassing central authorization check, verifying test failure, restoring check, and confirming test passes.
- **What AI Generated:**
  - Mutation test harness in `test/security.test.ts` and `/api/security/run-tests`.
- **Specific Errors / Security Weaknesses Discovered:**
  - Ensuring the application cannot accidentally remain in mutated bypass state if an unhandled exception occurs during the test.
- **Manual Corrections Applied:**
  - Enclosed mutation testing in a `try...finally` block that guarantees `setMutationTestBypass(false)` is always executed, even if assertions throw.
  - Added afterEach cleanup hook in Vitest.
- **Git Commit Link:** Pending initial repository push.
