/**
 * Persistent file storage abstraction.
 *
 * Drivers:
 *  - "local": files stay in storage/private on disk (development only — Render's disk is ephemeral).
 *  - "r2":    files are stored in a private Cloudflare R2 bucket (S3-compatible API).
 *
 * Uploads always land on local disk first (Multer), get their magic bytes validated,
 * and are then moved to the configured driver via persistUploadedFile().
 */
const fs = require("fs");
const env = require("../config/env");
const { getPrivateFilePath, removeStoredFile, isValidStorageKey } = require("./file-storage");
const { NotFoundError, BadRequestError } = require("./errors");

let s3Client = null;
let s3Commands = null;

function getS3() {
    if (!s3Client) {
        const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");
        s3Client = new S3Client({
            region: "auto",
            endpoint: `https://${env.storage.r2.accountId}.r2.cloudflarestorage.com`,
            credentials: {
                accessKeyId: env.storage.r2.accessKeyId,
                secretAccessKey: env.storage.r2.secretAccessKey
            }
        });
        s3Commands = { PutObjectCommand, GetObjectCommand, DeleteObjectCommand };
    }
    return { client: s3Client, ...s3Commands };
}

function isRemote() {
    return env.storage.driver === "r2";
}

function assertKey(storageKey) {
    if (!isValidStorageKey(storageKey)) {
        throw new BadRequestError("Invalid storage file key");
    }
}

/**
 * Move a validated upload from local temp storage to the persistent driver.
 * For "local" this is a no-op. For "r2" the local copy is removed afterwards.
 */
async function persistUploadedFile({ storageKey, mimeType, size }) {
    if (!isRemote()) return;
    assertKey(storageKey);

    const localPath = getPrivateFilePath(storageKey);
    const { client, PutObjectCommand } = getS3();
    try {
        await client.send(
            new PutObjectCommand({
                Bucket: env.storage.r2.bucket,
                Key: storageKey,
                Body: fs.createReadStream(localPath),
                ContentType: mimeType || "application/octet-stream",
                ContentLength: size
            })
        );
    } finally {
        // Never keep a copy on the ephemeral server disk
        removeStoredFile(storageKey);
    }
}

/**
 * Open a readable stream for a stored file.
 * @returns {Promise<import("stream").Readable>}
 */
async function openFileStream(storageKey) {
    assertKey(storageKey);

    if (!isRemote()) {
        const filePath = getPrivateFilePath(storageKey);
        if (!fs.existsSync(filePath)) {
            throw new NotFoundError("Physical file is missing from private storage");
        }
        return fs.createReadStream(filePath);
    }

    const { client, GetObjectCommand } = getS3();
    try {
        const result = await client.send(
            new GetObjectCommand({ Bucket: env.storage.r2.bucket, Key: storageKey })
        );
        return result.Body;
    } catch (error) {
        if (error?.name === "NoSuchKey" || error?.$metadata?.httpStatusCode === 404) {
            throw new NotFoundError("Physical file is missing from private storage");
        }
        throw error;
    }
}

/**
 * Delete a stored file. Failures are logged, not thrown (DB record is already gone).
 */
async function deleteStoredFile(storageKey) {
    if (!storageKey) return;

    if (!isRemote()) {
        removeStoredFile(storageKey);
        return;
    }

    try {
        assertKey(storageKey);
        const { client, DeleteObjectCommand } = getS3();
        await client.send(
            new DeleteObjectCommand({ Bucket: env.storage.r2.bucket, Key: storageKey })
        );
    } catch (error) {
        console.error(`[ObjectStorage] Warning: Failed to delete '${storageKey}' from R2:`, error.message);
    }
}

module.exports = {
    persistUploadedFile,
    openFileStream,
    deleteStoredFile,
    isRemote
};
