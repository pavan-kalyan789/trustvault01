# TrustVault — Enterprise Cloud Run Deployment Guide (DEPLOYMENT.md)

This guide documents deploying TrustVault to **Google Cloud Run** with a private Google Cloud Storage bucket and Cloud Firestore.

---

## 1. Firebase & Google Cloud Project Setup

1. Create a Google Cloud project or use your existing AI Studio project:
   ```bash
   gcloud config set project [YOUR_PROJECT_ID]
   ```
2. Enable required Cloud APIs:
   ```bash
   gcloud services enable \
     run.googleapis.com \
     firestore.googleapis.com \
     storage.googleapis.com \
     secretmanager.googleapis.com \
     artifactregistry.googleapis.com
   ```

---

## 2. Authentication Provider Configuration

1. In the Firebase Console, navigate to **Build > Authentication**.
2. Enable the **Email/Password** sign-in method.
3. Configure password policy: minimum 8 characters, non-alphanumeric character required.

---

## 3. Cloud Firestore Database Provisioning

1. In Firebase Console or via gcloud, create Cloud Firestore in **Native Mode**:
   ```bash
   gcloud firestore databases create --location=asia-east1
   ```
2. Collections initialized automatically by TrustVault:
   - `users`
   - `documents`
   - `documentGrants`
   - `documentVersions`
   - `auditEvents`
   - `auditCheckpoints`
   - `securityAlerts`
   - `systemSettings`

---

## 4. Firestore Security Rules Deployment

Deploy the zero-trust rules from `firestore.rules`:
```bash
firebase deploy --only firestore:rules
```
*Guarantees zero client-side direct writes to audit events or permission grants.*

---

## 5. Private Google Cloud Storage Bucket

1. Create a private bucket with **Public Access Prevention** and **Uniform Bucket-Level Access**:
   ```bash
   gcloud storage buckets create gs://[YOUR_PROJECT_ID]-vault-storage \
     --location=asia-east1 \
     --uniform-bucket-level-access \
     --public-access-prevention
   ```
2. Verify public access is strictly prohibited:
   ```bash
   gcloud storage buckets describe gs://[YOUR_PROJECT_ID]-vault-storage --format="default(iam_config)"
   ```

---

## 6. Service Account & Least-Privilege IAM Configuration

1. Create a dedicated Cloud Run runtime service account:
   ```bash
   gcloud iam service-accounts create trustvault-runner \
     --display-name="TrustVault Cloud Run Runtime"
   ```
2. Grant least-privilege storage access to the bucket:
   ```bash
   gcloud storage buckets add-iam-policy-binding gs://[YOUR_PROJECT_ID]-vault-storage \
     --member="serviceAccount:trustvault-runner@[YOUR_PROJECT_ID].iam.gserviceaccount.com" \
     --role="roles/storage.objectAdmin"
   ```
3. Grant Firestore access:
   ```bash
   gcloud projects add-iam-policy-binding [YOUR_PROJECT_ID] \
     --member="serviceAccount:trustvault-runner@[YOUR_PROJECT_ID].iam.gserviceaccount.com" \
     --role="roles/datastore.user"
   ```

---

## 7. Environment Secret Management

Store sensitive keys in Google Cloud Secret Manager:
```bash
# Generate 64-byte random hex secret for audit HMAC
AUDIT_SECRET=$(openssl rand -hex 32)

echo -n "$AUDIT_SECRET" | gcloud secrets create AUDIT_HMAC_SECRET --data-file=-
```

---

## 8. Container Build & Cloud Run Deployment

1. Build production image with Google Cloud Build:
   ```bash
   gcloud builds submit --tag gcr.io/[YOUR_PROJECT_ID]/trustvault:latest .
   ```
2. Deploy service to Google Cloud Run:
   ```bash
   gcloud run deploy trustvault \
     --image gcr.io/[YOUR_PROJECT_ID]/trustvault:latest \
     --platform managed \
     --region asia-east1 \
     --service-account trustvault-runner@[YOUR_PROJECT_ID].iam.gserviceaccount.com \
     --set-secrets AUDIT_HMAC_SECRET=AUDIT_HMAC_SECRET:latest \
     --set-env-vars NODE_ENV=production,STORAGE_BUCKET_NAME=[YOUR_PROJECT_ID]-vault-storage \
     --port 3000 \
     --allow-unauthenticated
   ```

---

## 9. Production Smoke Tests

Execute post-deployment verification against your Cloud Run URL:
1. **Health Check:** `curl -i https://[SERVICE_URL]/api/health` -> Expect `200 OK`
2. **Unauthenticated Check:** `curl -i https://[SERVICE_URL]/api/documents` -> Expect `401 Unauthorized`
3. **Audit Verification:** Authenticate as admin and POST to `/api/audit/verify` -> Expect `isValid: true`.
