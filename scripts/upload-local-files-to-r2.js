#!/usr/bin/env node

/**
 * One-time migration: copy files from storage/private (local disk) to the R2 bucket.
 * Local files are NOT deleted, so it is safe to re-run.
 *
 * Usage (with R2_* variables set in .env):
 *   npm run storage:upload-local
 */

require("dotenv").config();
const fs = require("fs");
const path = require("path");
const { S3Client, PutObjectCommand, HeadObjectCommand } = require("@aws-sdk/client-s3");
const { STORAGE_DIR, isValidStorageKey } = require("../src/utils/file-storage");

const required = ["R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET"];
const missing = required.filter((key) => !process.env[key]);
if (missing.length > 0) {
    console.error(`Missing environment variables: ${missing.join(", ")}`);
    process.exit(1);
}

const client = new S3Client({
    region: "auto",
    endpoint: `https://${process.env.R2_ACCOUNT_ID}.r2.cloudflarestorage.com`,
    credentials: {
        accessKeyId: process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
    }
});
const Bucket = process.env.R2_BUCKET;

async function exists(Key) {
    try {
        await client.send(new HeadObjectCommand({ Bucket, Key }));
        return true;
    } catch {
        return false;
    }
}

async function main() {
    const keys = fs.readdirSync(STORAGE_DIR).filter(isValidStorageKey);
    console.log(`Found ${keys.length} file(s) in ${STORAGE_DIR}`);

    let uploaded = 0;
    for (const Key of keys) {
        if (await exists(Key)) {
            console.log(`skip     ${Key} (already in R2)`);
            continue;
        }
        const filePath = path.join(STORAGE_DIR, Key);
        await client.send(
            new PutObjectCommand({
                Bucket,
                Key,
                Body: fs.createReadStream(filePath),
                ContentLength: fs.statSync(filePath).size
            })
        );
        uploaded++;
        console.log(`uploaded ${Key}`);
    }
    console.log(`Done. Uploaded ${uploaded} file(s).`);
}

main().catch((error) => {
    console.error("Migration failed:", error.message);
    process.exit(1);
});
