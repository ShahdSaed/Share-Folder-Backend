/**
 * File storage operations used by the files module.
 *
 * Files live in STORAGE_DIR (see file-storage.js). In production on Render this
 * must point at a Persistent Disk (e.g. STORAGE_DIR=/var/data/private), otherwise
 * uploads are lost on every restart/redeploy.
 */
const fs = require("fs");
const { getPrivateFilePath, removeStoredFile } = require("./file-storage");
const { NotFoundError } = require("./errors");

/**
 * Open a readable stream for a stored file.
 * @param {string} storageKey
 * @returns {Promise<import("fs").ReadStream>}
 */
async function openFileStream(storageKey) {
    const filePath = getPrivateFilePath(storageKey);
    if (!fs.existsSync(filePath)) {
        throw new NotFoundError("Physical file is missing from private storage");
    }
    return fs.createReadStream(filePath);
}

/**
 * Delete a stored file. Failures are logged, not thrown.
 * @param {string} storageKey
 */
async function deleteStoredFile(storageKey) {
    removeStoredFile(storageKey);
}

module.exports = {
    openFileStream,
    deleteStoredFile
};
