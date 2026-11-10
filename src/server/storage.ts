/**
 * Private Object Storage & Strict File Validation Service
 * Enforces magic-byte inspection, MIME verification, path traversal prevention,
 * and isolated storage key generation.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';

export const MAX_UPLOAD_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

const DATA_DIR = process.env.DATA_DIR || process.cwd();
const VAULT_STORAGE_DIR = path.resolve(DATA_DIR, 'vault_storage_private');

// Ensure vault directory exists
if (!fs.existsSync(VAULT_STORAGE_DIR)) {
  fs.mkdirSync(VAULT_STORAGE_DIR, { recursive: true, mode: 0o700 });
}

export interface FileValidationResult {
  isValid: boolean;
  error?: string;
  detectedMimeType?: string;
  sha256Hash?: string;
  sanitizedFilename?: string;
}

const DANGEROUS_EXTENSIONS = new Set([
  'exe', 'bat', 'cmd', 'sh', 'bash', 'zsh', 'ps1', 'vbs', 'js', 'mjs',
  'cjs', 'py', 'rb', 'php', 'pl', 'bin', 'msi', 'scr', 'pif', 'com',
  'jar', 'elf', 'dll', 'so', 'dylib', 'app'
]);

const ALLOWED_MIME_TYPES = new Set([
  'application/pdf',
  'image/png',
  'image/jpeg',
  'text/plain',
  'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
  'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'
]);

/**
 * Inspects buffer magic bytes (file signatures) to verify actual file format
 */
export function detectMagicBytes(buffer: Buffer): string | null {
  if (buffer.length < 4) return null;

  // PDF: %PDF- (0x25 0x50 0x44 0x46 0x2D)
  if (
    buffer.length >= 5 &&
    buffer[0] === 0x25 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x44 &&
    buffer[3] === 0x46 &&
    buffer[4] === 0x2d
  ) {
    return 'application/pdf';
  }

  // PNG: 89 50 4E 47 0D 0A 1A 0A
  if (
    buffer.length >= 8 &&
    buffer[0] === 0x89 &&
    buffer[1] === 0x50 &&
    buffer[2] === 0x4e &&
    buffer[3] === 0x47 &&
    buffer[4] === 0x0d &&
    buffer[5] === 0x0a &&
    buffer[6] === 0x1a &&
    buffer[7] === 0x0a
  ) {
    return 'image/png';
  }

  // JPEG / JPG: FF D8 FF
  if (
    buffer.length >= 3 &&
    buffer[0] === 0xff &&
    buffer[1] === 0xd8 &&
    buffer[2] === 0xff
  ) {
    return 'image/jpeg';
  }

  // Check for PE executable (MZ header 0x4D 0x5A) or ELF (0x7F 0x45 0x4C 0x46) -> DANGEROUS!
  if (
    (buffer[0] === 0x4d && buffer[1] === 0x5a) ||
    (buffer[0] === 0x7f && buffer[1] === 0x45 && buffer[2] === 0x4c && buffer[3] === 0x46)
  ) {
    return 'application/x-executable-forbidden';
  }

  // ZIP format (DOCX, XLSX): 50 4B 03 04 or 50 4B 05 06
  if (
    buffer.length >= 4 &&
    buffer[0] === 0x50 &&
    buffer[1] === 0x4b &&
    (buffer[2] === 0x03 || buffer[2] === 0x05) &&
    (buffer[3] === 0x04 || buffer[3] === 0x06)
  ) {
    return 'application/zip-container';
  }

  // Text plain check: ensure no null bytes or binary control characters
  let isText = true;
  const sampleLength = Math.min(buffer.length, 4096);
  for (let i = 0; i < sampleLength; i++) {
    const byte = buffer[i];
    // NUL byte or control byte (except \t, \n, \r)
    if (byte === 0 || (byte < 7 && byte !== 0) || (byte > 14 && byte < 32 && byte !== 27)) {
      isText = false;
      break;
    }
  }

  if (isText) {
    return 'text/plain';
  }

  return null;
}

/**
 * Sanitizes filename to prevent directory traversal and header injection
 */
export function sanitizeFilename(filename: string): string {
  if (!filename) return 'document.bin';

  // Strip path traversal sequences and path separators
  let clean = path.basename(filename);
  clean = clean.replace(/[\0\r\n\t]/g, '');
  clean = clean.replace(/\.{2,}/g, '.');
  clean = clean.replace(/[^a-zA-Z0-9._\- ]/g, '_');
  clean = clean.trim();

  if (clean.length === 0 || clean === '.') {
    return 'document_' + Date.now() + '.bin';
  }

  // Limit filename length
  if (clean.length > 120) {
    const ext = path.extname(clean);
    clean = clean.substring(0, 110) + ext;
  }

  return clean;
}

/**
 * Comprehensive file validation
 */
export function validateUploadedFile(
  fileBuffer: Buffer,
  originalFilename: string,
  declaredMimeType: string
): FileValidationResult {
  // 1. Check empty file
  if (!fileBuffer || fileBuffer.length === 0) {
    return { isValid: false, error: 'File is empty (0 bytes). Upload rejected.' };
  }

  // 2. Check maximum size
  if (fileBuffer.length > MAX_UPLOAD_SIZE_BYTES) {
    return {
      isValid: false,
      error: `File size (${(fileBuffer.length / (1024 * 1024)).toFixed(2)} MB) exceeds the 10 MB limit.`
    };
  }

  // 3. Prevent path traversal in filename
  if (originalFilename.includes('..') || originalFilename.includes('/') || originalFilename.includes('\\')) {
    // Flag suspicious traversal
    return { isValid: false, error: 'Filename contains forbidden path traversal sequences.' };
  }

  // 4. Check dangerous extension
  const ext = path.extname(originalFilename).replace('.', '').toLowerCase();
  if (DANGEROUS_EXTENSIONS.has(ext)) {
    return {
      isValid: false,
      error: `Executable and dangerous file extensions (.${ext}) are strictly prohibited.`
    };
  }

  // 5. Detect magic bytes
  const detectedType = detectMagicBytes(fileBuffer);
  if (detectedType === 'application/x-executable-forbidden') {
    return {
      isValid: false,
      error: 'Binary executable signature detected. File rejected for security violation.'
    };
  }

  // 6. Verify declared MIME vs actual magic bytes (anti-MIME spoofing)
  let resolvedMime = declaredMimeType;

  if (ext === 'pdf') {
    if (detectedType !== 'application/pdf') {
      return {
        isValid: false,
        error: 'MIME Spoofing detected: File has .pdf extension but does not contain valid PDF magic bytes.'
      };
    }
    resolvedMime = 'application/pdf';
  } else if (ext === 'png') {
    if (detectedType !== 'image/png') {
      return {
        isValid: false,
        error: 'MIME Spoofing detected: File has .png extension but does not contain valid PNG magic bytes.'
      };
    }
    resolvedMime = 'image/png';
  } else if (ext === 'jpg' || ext === 'jpeg') {
    if (detectedType !== 'image/jpeg') {
      return {
        isValid: false,
        error: 'MIME Spoofing detected: File has .jpg extension but does not contain valid JPEG magic bytes.'
      };
    }
    resolvedMime = 'image/jpeg';
  } else if (ext === 'docx') {
    if (detectedType !== 'application/zip-container') {
      return {
        isValid: false,
        error: 'Invalid DOCX structure: Missing required container signature.'
      };
    }
    resolvedMime = 'application/vnd.openxmlformats-officedocument.wordprocessingml.document';
  } else if (ext === 'xlsx') {
    if (detectedType !== 'application/zip-container') {
      return {
        isValid: false,
        error: 'Invalid XLSX structure: Missing required container signature.'
      };
    }
    resolvedMime = 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet';
  } else if (ext === 'txt') {
    if (detectedType !== 'text/plain') {
      return {
        isValid: false,
        error: 'Invalid text file: Non-text binary data found.'
      };
    }
    resolvedMime = 'text/plain';
  } else {
    // If not one of the explicitly supported extensions
    return {
      isValid: false,
      error: `Unsupported file type: .${ext}. Allowed formats: PDF, DOCX, XLSX, PNG, JPG, TXT.`
    };
  }

  if (!ALLOWED_MIME_TYPES.has(resolvedMime)) {
    return {
      isValid: false,
      error: `Disallowed MIME type: ${resolvedMime}.`
    };
  }

  // Calculate SHA-256
  const sha256Hash = crypto.createHash('sha256').update(fileBuffer).digest('hex');
  const sanitized = sanitizeFilename(originalFilename);

  return {
    isValid: true,
    detectedMimeType: resolvedMime,
    sha256Hash,
    sanitizedFilename: sanitized
  };
}

/**
 * Saves a file buffer to private object storage using random key
 */
export async function saveToPrivateStorage(buffer: Buffer): Promise<string> {
  const storageKey = 'obj_' + crypto.randomUUID() + '.bin';
  const filePath = path.join(VAULT_STORAGE_DIR, storageKey);
  await fs.promises.writeFile(filePath, buffer, { mode: 0o600 });
  return storageKey;
}

/**
 * Retrieves a file buffer from private storage
 */
export async function getFromPrivateStorage(storageKey: string): Promise<Buffer | null> {
  // Prevent path traversal on storageKey
  const safeKey = path.basename(storageKey);
  const filePath = path.join(VAULT_STORAGE_DIR, safeKey);
  if (!fs.existsSync(filePath)) {
    return null;
  }
  return await fs.promises.readFile(filePath);
}

/**
 * Deletes a file from private storage
 */
export async function deleteFromPrivateStorage(storageKey: string): Promise<boolean> {
  const safeKey = path.basename(storageKey);
  const filePath = path.join(VAULT_STORAGE_DIR, safeKey);
  if (fs.existsSync(filePath)) {
    await fs.promises.unlink(filePath);
    return true;
  }
  return false;
}
