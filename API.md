# TrustVault — REST API Specification (API.md)

All protected endpoints require an `Authorization: Bearer <token>` header.
Standard error responses follow the format:
```json
{
  "error": "ErrorType",
  "message": "Human-readable description"
}
```

---

## 1. Authentication Endpoints

### `POST /api/auth/session`
- **Purpose:** Authenticate user credentials, verify active status, and issue session token.
- **Auth Required:** None (Public / Rate-limited).
- **Allowed Roles:** Any registered user.
- **Request Body:**
  ```json
  { "email": "owner@trustvault.local", "password": "TrustVault2026!Owner" }
  ```
- **Success Response (200 OK):**
  ```json
  {
    "success": true,
    "token": "tv_tok_...",
    "role": "owner",
    "user": { "id": "usr_owner_001", "email": "owner@trustvault.local", "displayName": "...", "role": "owner", "active": true },
    "expiresAt": 1778390000000
  }
  ```
- **Failure Responses:**
  - `400 BadRequest`: `{ "success": false, "error": "BadRequest", "message": "Invalid email or password format." }`
  - `401 Unauthorized`: `{ "success": false, "error": "Unauthorized", "message": "Invalid email or password." }`
  - `403 Forbidden`: `{ "success": false, "error": "Forbidden", "message": "This account has been deactivated." }`
  - `429 TooManyRequests`: `{ "success": false, "error": "TooManyRequests", "message": "Rate limit exceeded." }`
  - `500 InternalServerError`: `{ "success": false, "error": "InternalServerError", "message": "Authentication failed." }`

### `POST /api/auth/demo-session`
- **Purpose:** Verified demo authentication for evaluation. Validates against database records and issues real cryptographic session tokens.
- **Auth Required:** None.
- **Request Body:** `{ "role": "admin" | "owner" | "viewer" | "other" }`
- **Success Response (200 OK):** `{ "success": true, "token": "...", "role": "...", "user": { ... } }`

### `GET /api/auth/firebase-status`
- **Purpose:** Reports active authentication provider and transparent Firebase configuration status.
- **Auth Required:** None.
- **Success Response (200 OK):** `{ "success": true, "firebaseConfigured": boolean, "provider": string, "details": object }`

### `POST /api/auth/logout`
- **Purpose:** Invalidate session token and record `LOGOUT` audit event.
- **Auth Required:** Bearer Token.
- **Success Response (200 OK):** `{ "success": true, "message": "Logged out successfully." }`

### `GET /api/auth/me`
- **Purpose:** Retrieve the currently authenticated user's profile.
- **Auth Required:** Bearer Token.
- **Success Response (200 OK):** `{ "success": true, "user": { "id": "...", "email": "...", "role": "..." } }`

---

## 2. User Management Endpoints

### `GET /api/users`
- **Purpose:** List users. Returns candidate recipients for document sharing, or full directory for Admin.
- **Auth Required:** Bearer Token.
- **Success Response (200 OK):** `{ "users": [...] }`

### `POST /api/users`
- **Purpose:** Provision new user account.
- **Auth Required:** Bearer Token.
- **Allowed Roles:** `admin`.
- **Request Body:**
  ```json
  { "email": "...", "displayName": "...", "password": "...", "role": "viewer" }
  ```
- **Success Response (201 Created):** `{ "user": { ... } }`
- **Failure Responses:** `400 BadRequest`, `403 Forbidden`, `409 Conflict`.

### `PATCH /api/users/:id`
- **Purpose:** Activate/deactivate user account or change role.
- **Auth Required:** Bearer Token.
- **Allowed Roles:** `admin`.
- **Request Body:** `{ "active": false, "role": "viewer" }`
- **Success Response (200 OK):** `{ "user": { ... } }`

---

## 3. Document Management Endpoints

### `POST /api/documents`
- **Purpose:** Securely upload a new document into private object storage.
- **Auth Required:** Bearer Token.
- **Allowed Roles:** `owner`, `admin`.
- **Payload:** `multipart/form-data` with `file`, `name`, `category`, `description`.
- **Validation:** Enforces magic-byte file signature inspection, dangerous extension blacklist, path traversal sanitization, and 10 MB limit.
- **Success Response (201 Created):**
  ```json
  {
    "document": {
      "id": "doc_...",
      "name": "...",
      "sha256Hash": "...",
      "version": 1,
      "size": 1024,
      "category": "Contracts"
    }
  }
  ```
- **Failure Responses:** `400 ValidationFailed`, `401 Unauthorized`, `403 Forbidden`.

### `GET /api/documents`
- **Purpose:** Search and list documents accessible to the authenticated user.
- **Auth Required:** Bearer Token.
- **Allowed Roles:** Any.
- **Authorization Rule:** Strictly evaluates ownership and active grants before returning results. Unshared documents are filtered out.
- **Success Response (200 OK):** `{ "documents": [...] }`

### `GET /api/documents/:id`
- **Purpose:** Retrieve document metadata.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Caller must be owner, hold active grant, or be admin viewing governance metadata. Unauthorized returns `404 Not Found` to prevent discovery.
- **Success Response (200 OK):** `{ "document": { ... }, "userCanDownload": true }`

### `GET /api/documents/:id/download`
- **Purpose:** Stream document file bytes through authenticated proxy.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Re-checks current database permission on **every request**. Administrator without grant receives `404 Not Found`.
- **Headers Returned:**
  - `Content-Type: <mime>`
  - `Content-Disposition: attachment; filename="sanitized"`
  - `Cache-Control: no-store, private`
  - `X-Content-Type-Options: nosniff`
- **Success Response (200 OK):** Binary file stream.
- **Failure Responses:** `401 Unauthorized`, `404 Not Found` (access denied or doc missing).

### `GET /api/documents/:id/preview`
- **Purpose:** Stream file bytes inline for in-browser preview.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Identical to download check.
- **Headers Returned:** `Content-Disposition: inline`, `Cache-Control: no-store, private`.

### `PATCH /api/documents/:id`
- **Purpose:** Update document metadata (title, category, description).
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Requires `EDIT` permission or `OWNER`.
- **Success Response (200 OK):** `{ "document": { ... } }`

### `DELETE /api/documents/:id`
- **Purpose:** Soft-delete a document under retention policy.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Only document `OWNER` can delete.
- **Success Response (200 OK):** `{ "success": true, "message": "Document successfully soft-deleted." }`

### `POST /api/documents/:id/restore`
- **Purpose:** Restore soft-deleted document.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Only document `OWNER` can restore.

---

## 4. Permission Endpoints

### `GET /api/documents/:id/permissions`
- **Purpose:** List all active and revoked grants for a document.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Document `OWNER` only.

### `POST /api/documents/:id/permissions`
- **Purpose:** Grant explicit `READ` or `EDIT` permission to a user.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Document `OWNER` only. Self-grants are rejected.
- **Request Body:**
  ```json
  { "granteeEmail": "viewer@trustvault.local", "permissionLevel": "READ", "expiresAt": "2026-12-31T23:59:59Z" }
  ```
- **Success Response (201 Created):** `{ "grant": { "id": "grnt_...", "isActive": true } }`

### `DELETE /api/documents/:id/permissions/:grantId`
- **Purpose:** **Immediate permission revocation**.
- **Auth Required:** Bearer Token.
- **Authorization Rule:** Document `OWNER` only.
- **Effect:** Sets `grant.isActive = false` immediately. All subsequent access attempts fail with 404 instantly.
- **Success Response (200 OK):** `{ "success": true, "message": "Permission immediately revoked." }`

---

## 5. Audit & Governance Endpoints

### `GET /api/audit/events`
- **Purpose:** Retrieve immutable audit events. Admin sees all events; non-admins see only events where they are actor or target.
- **Auth Required:** Bearer Token.
- **Success Response (200 OK):** `{ "events": [...] }`

### `POST /api/audit/verify`
- **Purpose:** Cryptographically verify the recursive HMAC-SHA256 audit chain.
- **Auth Required:** Bearer Token.
- **Success Response (200 OK):**
  ```json
  {
    "verification": {
      "isValid": true,
      "totalEvents": 28,
      "verifiedCount": 28,
      "lastVerifiedHash": "..."
    }
  }
  ```

### `GET /api/admin/dashboard`
- **Purpose:** Retrieve admin telemetry, denied access statistics, and alerts.
- **Auth Required:** Bearer Token (`admin` only).

### `POST /api/security/run-tests`
- **Purpose:** Execute live backend penetration tests and mutation testing suite.
- **Auth Required:** Bearer Token.
