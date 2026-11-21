const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const { BadRequestError } = require("./errors");

// STORAGE_DIR env lets production point at a persistent disk (e.g. Render Disk mounted at /var/data).
// Defaults to backend/storage/private for local development.
const STORAGE_DIR = process.env.STORAGE_DIR
    ? path.resolve(process.env.STORAGE_DIR)
    : path.resolve(__dirname, "../../storage/private");

// Ensure private storage directory exists
if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// Strictly allowed extension-to-MIME pairs
const ALLOWED_FILE_TYPES = {
    ".pdf": ["application/pdf"],
    ".doc": ["application/msword"],
    ".docx": ["application/vnd.openxmlformats-officedocument.wordprocessingml.document"],
    ".xls": ["application/vnd.ms-excel"],
    ".xlsx": ["application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"],
    ".pptx": ["application/vnd.openxmlformats-officedocument.presentationml.presentation"],
    ".txt": ["text/plain"],
    ".zip": ["application/zip", "application/x-zip-compressed"]
};

// Storage key must be a UUID v4 plus an allowed extension, matching the generation strategy
const STORAGE_KEY_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(\.[a-zA-Z0-9]+)?$/i;

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

// Multer disk storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, STORAGE_DIR);
    },
    filename: (req, file, cb) => {
        // Generate random, unguessable storage key (UUID + lowercase extension)
        const uniqueSuffix = crypto.randomUUID();
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${uniqueSuffix}${ext}`);
    }
});

/**
 * Filter uploaded files based on strict extension and MIME type pair matching.
 */
function fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname || "").toLowerCase();
    const mime = (file.mimetype || "").toLowerCase();

    const allowedMimes = ALLOWED_FILE_TYPES[ext];
    if (!allowedMimes || !allowedMimes.includes(mime)) {
        return cb(
            new BadRequestError(
                `Unsupported file type or invalid MIME type for '${ext || "unknown"}'. Allowed formats: PDF, DOC, DOCX, XLS, XLSX, PPTX, TXT, ZIP`
            )
        );
    }
    cb(null, true);
}

/**
 * Validate file content signature (magic bytes) to verify actual file content.
 * @param {string} filePath - Absolute path to stored file
 * @param {string} ext - File extension (e.g. '.pdf')
 * @returns {Promise<boolean>}
 */
async function validateFileContentSignature(filePath, ext) {
    const extLower = (ext || "").toLowerCase();

    let fd;
    const buffer = Buffer.alloc(512);
    let bytesRead = 0;
    try {
        fd = fs.openSync(filePath, "r");
        bytesRead = fs.readSync(fd, buffer, 0, 512, 0);
    } catch {
        return false;
    } finally {
        if (fd !== undefined) {
            try {
                fs.closeSync(fd);
            } catch {
                // Ignore close error
            }
        }
    }

    if (bytesRead === 0) {
        return extLower === ".txt";
    }

    const header = buffer.subarray(0, bytesRead);

    // Block dangerous executable headers across all file types
    // PE (Windows EXE / DLL): 'MZ' (0x4D, 0x5A)
    if (header.length >= 2 && header[0] === 0x4D && header[1] === 0x5A) {
        return false;
    }
    // ELF (Linux executable): 0x7F, 'E', 'L', 'F' (0x7F, 0x45, 0x4C, 0x46)
    if (header.length >= 4 && header[0] === 0x7F && header[1] === 0x45 && header[2] === 0x4C && header[3] === 0x46) {
        return false;
    }

    switch (extLower) {
        case ".pdf":
            // PDF signature: '%PDF' (0x25, 0x50, 0x44, 0x46)
            return (
                header.length >= 4 &&
                header[0] === 0x25 &&
                header[1] === 0x50 &&
                header[2] === 0x44 &&
                header[3] === 0x46
            );

        case ".docx":
        case ".xlsx":
        case ".pptx":
            // OOXML packages are ZIP archives starting with PK\x03\x04
            return (
                header.length >= 4 &&
                header[0] === 0x50 &&
                header[1] === 0x4B &&
                header[2] === 0x03 &&
                header[3] === 0x04
            );

        case ".zip":
            // ZIP archives: PK\x03\x04 (standard), PK\x05\x06 (empty), PK\x07\x08 (spanned)
            return (
                header.length >= 4 &&
                header[0] === 0x50 &&
                header[1] === 0x4B &&
                (header[2] === 0x03 || header[2] === 0x05 || header[2] === 0x07)
            );

        case ".doc":
        case ".xls":
            // Microsoft Compound File Binary Format (CFBF/OLE2): D0 CF 11 E0 A1 B1 1A E1
            return (
                header.length >= 8 &&
                header[0] === 0xD0 &&
                header[1] === 0xCF &&
                header[2] === 0x11 &&
                header[3] === 0xE0 &&
                header[4] === 0xA1 &&
                header[5] === 0xB1 &&
                header[6] === 0x1A &&
                header[7] === 0xE1
            );

        case ".txt":
            // Plain text must not contain binary null bytes (0x00)
            for (let i = 0; i < bytesRead; i++) {
                if (header[i] === 0x00) {
                    return false;
                }
            }
            return true;

        default:
            return false;
    }
}

/**
 * Validate that a storage key is safe, properly formatted, and contains no directory traversal.
 * @param {string} storageKey 
 * @returns {boolean}
 */
function isValidStorageKey(storageKey) {
    if (!storageKey || typeof storageKey !== "string") {
        return false;
    }
    const trimmed = storageKey.trim();
    if (trimmed !== storageKey || trimmed.length === 0 || trimmed.length > 255) {
        return false;
    }
    if (
        storageKey.includes("/") ||
        storageKey.includes("\\") ||
        storageKey.includes("\0") ||
        storageKey.includes("..") ||
        path.basename(storageKey) !== storageKey
    ) {
        return false;
    }
    return STORAGE_KEY_REGEX.test(storageKey);
}

/**
 * Get the absolute path for a private storage key with path traversal prevention.
 * Uses path.relative boundary checks and storage key validation.
 * @param {string} storageKey 
 * @returns {string}
 */
function getPrivateFilePath(storageKey) {
    if (!isValidStorageKey(storageKey)) {
        throw new BadRequestError("Invalid storage file key");
    }

    const safeKey = path.basename(storageKey);
    const resolvedPath = path.resolve(STORAGE_DIR, safeKey);

    // Robust path-boundary check using path.relative()
    const relative = path.relative(STORAGE_DIR, resolvedPath);
    const isInsideStorage =
        !path.isAbsolute(relative) &&
        !relative.startsWith("..") &&
        !relative.includes("..") &&
        relative.length > 0 &&
        relative === safeKey;

    if (!isInsideStorage || !resolvedPath.startsWith(STORAGE_DIR + path.sep)) {
        throw new BadRequestError("Invalid storage file key");
    }

    return resolvedPath;
}

/**
 * Remove a file safely from private storage.
 * Enforces boundary checks so it cannot delete files outside the private storage directory.
 * @param {string} storageKey 
 */
function removeStoredFile(storageKey) {
    if (!storageKey) return;
    try {
        const safePath = getPrivateFilePath(storageKey);
        if (fs.existsSync(safePath)) {
            fs.unlinkSync(safePath);
        }
    } catch (err) {
        // Log safe message without exposing internal paths
        console.error(`[FileStorage] Warning: Failed to delete storage file '${storageKey}':`, err.message);
    }
}

const uploadMiddleware = multer({
    storage,
    limits: {
        fileSize: MAX_FILE_SIZE_BYTES
    },
    fileFilter
});

module.exports = {
    STORAGE_DIR,
    ALLOWED_FILE_TYPES,
    uploadMiddleware,
    removeStoredFile,
    getPrivateFilePath,
    validateFileContentSignature,
    isValidStorageKey,
    MAX_FILE_SIZE_BYTES
};
