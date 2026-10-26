const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const multer = require("multer");
const { BadRequestError } = require("./errors");

const STORAGE_DIR = path.resolve(__dirname, "../../storage/private");

// Ensure private storage directory exists
if (!fs.existsSync(STORAGE_DIR)) {
    fs.mkdirSync(STORAGE_DIR, { recursive: true });
}

// Allowed MIME types and extensions
const ALLOWED_MIME_TYPES = {
    "application/pdf": ".pdf",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "text/plain": ".txt",
    "application/zip": ".zip",
    "application/x-zip-compressed": ".zip"
};

const MAX_FILE_SIZE_BYTES = 50 * 1024 * 1024; // 50 MB

// Multer disk storage configuration
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, STORAGE_DIR);
    },
    filename: (req, file, cb) => {
        // Generate random, unguessable storage key
        const uniqueSuffix = crypto.randomUUID();
        const ext = path.extname(file.originalname).toLowerCase();
        cb(null, `${uniqueSuffix}${ext}`);
    }
});

function fileFilter(req, file, cb) {
    const ext = path.extname(file.originalname).toLowerCase();
    const isValidMime = Boolean(ALLOWED_MIME_TYPES[file.mimetype]);
    const allowedExtensions = Object.values(ALLOWED_MIME_TYPES);

    if (!isValidMime && !allowedExtensions.includes(ext)) {
        return cb(
            new BadRequestError(
                `Unsupported file type '${ext}'. Allowed types: PDF, DOCX, XLSX, PPTX, TXT, ZIP`
            )
        );
    }
    cb(null, true);
}

const uploadMiddleware = multer({
    storage,
    limits: {
        fileSize: MAX_FILE_SIZE_BYTES
    },
    fileFilter
});

/**
 * Remove a file safely from private storage.
 * @param {string} storageKey 
 */
function removeStoredFile(storageKey) {
    if (!storageKey) return;
    try {
        const safePath = path.resolve(STORAGE_DIR, path.basename(storageKey));
        if (fs.existsSync(safePath)) {
            fs.unlinkSync(safePath);
        }
    } catch (err) {
        console.error(`[FileStorage] Warning: Failed to delete storage file '${storageKey}':`, err.message);
    }
}

/**
 * Get the absolute path for a private storage key with path traversal prevention.
 * @param {string} storageKey 
 * @returns {string}
 */
function getPrivateFilePath(storageKey) {
    const safeKey = path.basename(storageKey);
    const resolvedPath = path.resolve(STORAGE_DIR, safeKey);

    // Guard against path traversal attacks
    if (!resolvedPath.startsWith(STORAGE_DIR)) {
        throw new BadRequestError("Invalid storage file key");
    }

    return resolvedPath;
}

module.exports = {
    STORAGE_DIR,
    uploadMiddleware,
    removeStoredFile,
    getPrivateFilePath,
    MAX_FILE_SIZE_BYTES
};
