# TrustVault — Enterprise Threat Model (THREATS.md)

**Methodology:** STRIDE (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)  
**System Scope:** TrustVault Document Sharing Platform, Authorization Broker, Private Object Storage, and Cryptographic Audit Chain.  

---

### Threat 1: Insecure Direct Object Reference (IDOR) on Document Download
- **Threat Description:** Attacker alters the document UUID in the download URL to access unshared confidential records.
- **STRIDE Category:** Elevation of Privilege / Information Disclosure
- **Attack Scenario:** Authenticated user with low privileges requests `GET /api/documents/doc_audit_q3/download`.
- **Potential Impact:** Direct breach of confidential enterprise files.
- **Mitigation:** Centralized authorization check re-evaluates database grants on every request. Returns 404 to avoid disclosure.
- **Relevant Test:** `test/security.test.ts` (Test 2.1 & 2.2).
- **Residual Risk:** Low. Protected by non-enumerable UUIDs and strict per-request database ACL evaluation.
- **Disposition:** Mitigated.

---

### Threat 2: Stale Authorization Token Usage After Permission Revocation
- **Threat Description:** User downloads documents after access has been revoked by the owner.
- **STRIDE Category:** Elevation of Privilege
- **Attack Scenario:** An employee whose project access was terminated downloads files using a previously established session.
- **Potential Impact:** Continued unauthorized access to sensitive company assets.
- **Mitigation:** Revocation sets `isActive = false` in the database immediately. Backend streams file bytes only after checking the database grant state at request time.
- **Relevant Test:** `test/security.test.ts` (Test 3.3).
- **Residual Risk:** Files already downloaded to local client disk cannot be recalled.
- **Disposition:** Mitigated.

---

### Threat 3: Administrator Privilege Abuse
- **Threat Description:** System administrator uses superuser privileges to download confidential documents without owner consent.
- **STRIDE Category:** Elevation of Privilege / Information Disclosure
- **Attack Scenario:** Malicious or compromised admin queries `GET /api/documents/:id/download`.
- **Potential Impact:** Violation of legal confidentiality and separation of duty.
- **Mitigation:** Administrative role is strictly segregated from document content permissions. Admins have metadata and audit visibility only.
- **Relevant Test:** `test/security.test.ts` (Test 2.3).
- **Residual Risk:** Low. Any access attempt is flagged in security alerts and audit trail.
- **Disposition:** Mitigated.

---

### Threat 4: MIME Type Spoofing & Executable Code Ingestion
- **Threat Description:** Attacker renames a script or executable to `.pdf` to bypass client extension checks.
- **STRIDE Category:** Tampering / Elevation of Privilege
- **Attack Scenario:** Attacker uploads a web shell or ransomware payload with `.pdf` extension.
- **Potential Impact:** Storage pollution or downstream client execution upon download.
- **Mitigation:** Server inspects raw magic bytes (e.g. `%PDF-`, PNG signatures). PE (`MZ`) and ELF signatures are rejected.
- **Relevant Test:** `test/security.test.ts` (Test 4.1 & 4.2).
- **Residual Risk:** Low. Zero-day parser vulnerabilities in client-side PDF readers.
- **Disposition:** Mitigated.

---

### Threat 5: Path Traversal via Filename Manipulation
- **Threat Description:** Attacker includes `../` sequences in original filename.
- **STRIDE Category:** Tampering / Information Disclosure
- **Attack Scenario:** Uploading a file named `../../../../etc/shadow`.
- **Potential Impact:** Overwriting critical system files or exposing arbitrary filesystem paths.
- **Mitigation:** Filenames are sanitized, and files are stored with isolated UUID keys `obj_<uuid>.bin` in a private directory.
- **Relevant Test:** `test/security.test.ts` (Test 4.3).
- **Residual Risk:** Negligible.
- **Disposition:** Mitigated.

---

### Threat 6: Audit Log Forgery & History Rewriting
- **Threat Description:** Malicious insider modifies or deletes audit logs to hide unauthorized actions.
- **STRIDE Category:** Repudiation / Tampering
- **Attack Scenario:** Attacker updates database record of an `ACCESS_DENIED` event to `SUCCESS`.
- **Potential Impact:** Destruction of audit evidence and loss of regulatory compliance.
- **Mitigation:** HMAC-SHA256 hash chaining links each event to previous record. Any modification invalidates chain verification.
- **Relevant Test:** `test/security.test.ts` (Test 5.2).
- **Residual Risk:** An attacker with root database access could delete the entire collection; mitigated by anchored checkpoints.
- **Disposition:** Mitigated.

---

### Threat 7: Broken Chain Concurrency Race Condition
- **Threat Description:** Concurrent high-frequency audit writes cause a split or race condition in the hash chain.
- **STRIDE Category:** Tampering / Denial of Service
- **Attack Scenario:** Multiple concurrent uploads cause simultaneous event insertions with overlapping previous hashes.
- **Potential Impact:** Broken audit chain and false positive tampering alarms.
- **Mitigation:** Serialized append mutex (`AuditEngine.appendQueue`) enforces strict linear transaction order.
- **Relevant Test:** `test/security.test.ts` (Test 5.3).
- **Residual Risk:** Low throughput under extreme distributed scale (>5,000 writes/sec); mitigated by batch queuing.
- **Disposition:** Mitigated.

---

### Threat 8: Deactivated User Session Persistence
- **Threat Description:** Deactivated user continues making API requests using an unexpired JWT or session token.
- **STRIDE Category:** Elevation of Privilege
- **Attack Scenario:** Suspended contractor accesses documents before 24-hour token expires.
- **Potential Impact:** Data exfiltration post-termination.
- **Mitigation:** `authenticateUser` queries `user.active` on every single request. Deactivated accounts are rejected with 403 immediately.
- **Relevant Test:** `test/security.test.ts` (Test 1.4).
- **Residual Risk:** Negligible.
- **Disposition:** Mitigated.

---

### Threat 9: Document Existence Reconnaissance via Search
- **Threat Description:** Unprivileged user uses search queries to discover existence of confidential documents.
- **STRIDE Category:** Information Disclosure
- **Attack Scenario:** Viewer searches for "Merger" or "Acquisition" to view document titles.
- **Potential Impact:** Disclosure of confidential corporate activity.
- **Mitigation:** Search filtering evaluates authorization at the database layer before returning any results.
- **Relevant Test:** `test/security.test.ts` (Test 2.4).
- **Residual Risk:** Zero.
- **Disposition:** Mitigated.

---

### Threat 10: Horizontal Escalation via Self-Grant
- **Threat Description:** User attempts to grant permissions on documents they do not own or grant themselves higher privileges.
- **STRIDE Category:** Elevation of Privilege
- **Attack Scenario:** Attacker calls `POST /api/documents/:id/permissions` on another user's document.
- **Potential Impact:** Unauthorized privilege grant creation.
- **Mitigation:** `canManageDocumentPermissions` strictly enforces ownership; self-grants are rejected with 400.
- **Relevant Test:** `test/security.test.ts` (Test 3.4).
- **Residual Risk:** Negligible.
- **Disposition:** Mitigated.

---

### Threat 11: Denial of Service via Oversized File Uploads
- **Threat Description:** Attacker floods storage or memory by uploading huge files.
- **STRIDE Category:** Denial of Service
- **Attack Scenario:** Uploading a 5 GB ISO image.
- **Potential Impact:** Server out-of-memory crash and disk exhaustion.
- **Mitigation:** Strict 10 MB file size limit enforced in multer and storage service before saving.
- **Relevant Test:** `test/security.test.ts` (Test 4.4).
- **Residual Risk:** Distributed network volumetric saturation; mitigated by Cloud Run infrastructure DDoS defense.
- **Disposition:** Mitigated.

---

### Threat 12: Public Cloud Storage Bucket Exposure
- **Threat Description:** Cloud storage bucket misconfigured with public read permissions.
- **STRIDE Category:** Information Disclosure
- **Attack Scenario:** Anonymous internet users query Google Cloud Storage bucket URLs directly.
- **Potential Impact:** Mass leak of enterprise documents.
- **Mitigation:** Public Access Prevention enabled, Uniform Bucket-Level Access enforced, no signed URLs exposed. All traffic routes through authenticated backend.
- **Relevant Test:** Section 7 & DEPLOYMENT.md configuration checklist.
- **Residual Risk:** Cloud admin manually disabling public access prevention in GCP console.
- **Disposition:** Mitigated.

---

### Threat 13: Browser and Intermediate Cache Poisoning of Sensitive Content
- **Threat Description:** Confidential document bytes cached in public CDN or shared browser caches.
- **STRIDE Category:** Information Disclosure
- **Attack Scenario:** Subsequent user at a shared workstation accesses cached document from browser history.
- **Potential Impact:** Leakage of sensitive documents on shared workstations.
- **Mitigation:** Headers `Cache-Control: no-store, private`, `Pragma: no-cache`, and `X-Content-Type-Options: nosniff` on all file responses.
- **Relevant Test:** `test/security.test.ts` (Test 3.1).
- **Residual Risk:** User downloading file to local disk and leaving it unencrypted.
- **Disposition:** Mitigated.

---

### Threat 14: Cross-Tenant Version Injection
- **Threat Description:** Attacker uploads a malicious version to replace legitimate document contents.
- **STRIDE Category:** Tampering
- **Attack Scenario:** Calling `POST /api/documents/:id/versions` without EDIT or OWNER privileges.
- **Potential Impact:** Tampered contracts or financial reports.
- **Mitigation:** Version endpoint enforces `requireDocumentAccess('EDIT')`.
- **Relevant Test:** `src/server/routes/documents.ts` versioning tests.
- **Residual Risk:** Authorized user with EDIT permission making erroneous changes; mitigated by full version history.
- **Disposition:** Mitigated.

---

### Threat 15: Cross-Site Scripting (XSS) via Stored Metadata
- **Threat Description:** Attacker injects HTML/JS into document title or description (`<script>alert(1)</script>`).
- **STRIDE Category:** Tampering / Elevation of Privilege
- **Attack Scenario:** Viewing document details executes malicious script in victim's browser session.
- **Potential Impact:** Session hijacking and unauthorized actions.
- **Mitigation:** React automatic context-aware escaping, Zod string sanitization, and `X-XSS-Protection` headers.
- **Relevant Test:** Zod schema validation in `src/server/routes/documents.ts`.
- **Residual Risk:** Low.
- **Disposition:** Mitigated.

---

### Threat 16: Authentication Credential Brute-Forcing
- **Threat Description:** Automated attacks attempting common passwords against user accounts.
- **STRIDE Category:** Spoofing
- **Attack Scenario:** High-frequency POST requests to `/api/auth/session`.
- **Potential Impact:** Account compromise.
- **Mitigation:** IP-based rate limiting on `/api/auth/session` (max 20 attempts/minute) and failed login alert tracking.
- **Relevant Test:** `server.ts` rate limiter middleware.
- **Residual Risk:** Distributed botnet rotating across thousands of IPs; mitigated by Cloud Armor in production.
- **Disposition:** Mitigated.

---

### Threat 17: Information Disclosure via Stack Traces in Server Errors
- **Threat Description:** Backend errors expose database schemas, internal paths, or library versions.
- **STRIDE Category:** Information Disclosure
- **Attack Scenario:** Malformed request triggers unhandled exception.
- **Potential Impact:** Reconnaissance data provided to attackers.
- **Mitigation:** Centralized error handling middleware intercepts all errors and returns standardized envelopes without internal stack traces in production.
- **Relevant Test:** `server.ts` error handler.
- **Residual Risk:** Negligible.
- **Disposition:** Mitigated.

---

### Threat 18: Client-Side Direct Database Manipulation
- **Threat Description:** Attacker attempts to modify Firestore collections using client-side SDK.
- **STRIDE Category:** Elevation of Privilege / Tampering
- **Attack Scenario:** Connecting directly to Firestore using app configuration.
- **Potential Impact:** Bypassing backend business logic.
- **Mitigation:** `firestore.rules` enforces `allow read, write: if false` on all sensitive collections (`documentGrants`, `auditEvents`, `documents`).
- **Relevant Test:** `firestore.rules` validation.
- **Residual Risk:** Zero when rules are deployed.
- **Disposition:** Mitigated.

---

### Threat 19: Expired Grant Reuse
- **Threat Description:** Grantee accesses document after the agreed expiration date.
- **STRIDE Category:** Elevation of Privilege
- **Attack Scenario:** Downloading a document after `grant.expiresAt` has elapsed.
- **Potential Impact:** Access beyond authorized governance window.
- **Mitigation:** `canReadDocument` checks `!grant.expiresAt || new Date(grant.expiresAt) > new Date()` on every query.
- **Relevant Test:** `test/security.test.ts` (Test 3.1).
- **Residual Risk:** Low.
- **Disposition:** Mitigated.

---

### Threat 20: Audit Trail Truncation or Drop Attack
- **Threat Description:** Attacker deletes the trailing 50 events from the audit collection.
- **STRIDE Category:** Repudiation
- **Attack Scenario:** Deleting recent records to hide an exfiltration incident.
- **Potential Impact:** Unnoticed loss of recent audit evidence.
- **Mitigation:** Anchored periodic checkpoints (`auditCheckpoints`) record event counts and head hashes signed with independent HMAC key.
- **Relevant Test:** `src/server/audit.ts` checkpoint verification.
- **Residual Risk:** Attacker dropping checkpoints if storage volume is compromised.
- **Disposition:** Mitigated.

---

### Threat 21: Cross-Site Request Forgery (CSRF)
- **Threat Description:** Malicious third-party website induces victim's browser to execute state-changing requests.
- **STRIDE Category:** Elevation of Privilege
- **Attack Scenario:** Hidden form submitting to `/api/documents/:id/permissions`.
- **Potential Impact:** Unauthorized permission grants.
- **Mitigation:** Token-based authentication using `Authorization: Bearer` headers (not vulnerable to standard browser cookie ambient transmission) and restricted CORS origins.
- **Relevant Test:** `server.ts` CORS and header handling.
- **Residual Risk:** Zero for Bearer header transport.
- **Disposition:** Mitigated.
