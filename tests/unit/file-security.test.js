const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");

const {
    ALLOWED_FILE_TYPES,
    validateFileContentSignature,
    isValidStorageKey,
    getPrivateFilePath,
    removeStoredFile,
    STORAGE_DIR
} = require("../../src/utils/file-storage");

const {
    validateFilePassword,
    validateDisplayName,
    validateUploadInput,
    validateUpdateFileInput,
    validateFilePasswordInput,
    MIN_FILE_PASSWORD_LENGTH,
    MAX_FILE_PASSWORD_LENGTH,
    MAX_FILE_NAME_LENGTH
} = require("../../src/modules/files/file.validation");

const { BadRequestError } = require("../../src/utils/errors");

describe("File Storage & Security Unit Tests", () => {
    describe("MIME and Extension Allowed Pairs", () => {
        it("should contain all required file formats", () => {
            const expectedExtensions = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".pptx", ".txt", ".zip"];
            for (const ext of expectedExtensions) {
                assert.ok(ALLOWED_FILE_TYPES[ext], `Expected extension ${ext} to be allowed`);
            }
        });

        it("should support application/zip and application/x-zip-compressed for .zip", () => {
            assert.deepStrictEqual(ALLOWED_FILE_TYPES[".zip"], [
                "application/zip",
                "application/x-zip-compressed"
            ]);
        });
    });

    describe("Content Signature (Magic Bytes) Verification", () => {
        const tempFiles = [];

        function createTempFile(name, buffer) {
            const filePath = path.join(STORAGE_DIR, name);
            fs.writeFileSync(filePath, buffer);
            tempFiles.push(filePath);
            return filePath;
        }

        after(() => {
            for (const f of tempFiles) {
                if (fs.existsSync(f)) {
                    fs.unlinkSync(f);
                }
            }
        });

        it("should accept valid PDF file signature (%PDF)", async () => {
            const pdfBuffer = Buffer.from("%PDF-1.7\nSample PDF body content");
            const filePath = createTempFile(`${crypto.randomUUID()}.pdf`, pdfBuffer);
            const isValid = await validateFileContentSignature(filePath, ".pdf");
            assert.strictEqual(isValid, true);
        });

        it("should reject executable disguised as a PDF (starts with MZ)", async () => {
            const exeDisguised = Buffer.from([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00]); // MZ header
            const filePath = createTempFile(`${crypto.randomUUID()}.pdf`, exeDisguised);
            const isValid = await validateFileContentSignature(filePath, ".pdf");
            assert.strictEqual(isValid, false);
        });

        it("should accept valid OOXML / ZIP file signature (PK\x03\x04)", async () => {
            const zipBuffer = Buffer.from([0x50, 0x4B, 0x03, 0x04, 0x14, 0x00, 0x00, 0x00]);
            const filePathDocx = createTempFile(`${crypto.randomUUID()}.docx`, zipBuffer);
            const filePathXlsx = createTempFile(`${crypto.randomUUID()}.xlsx`, zipBuffer);
            const filePathZip = createTempFile(`${crypto.randomUUID()}.zip`, zipBuffer);

            assert.strictEqual(await validateFileContentSignature(filePathDocx, ".docx"), true);
            assert.strictEqual(await validateFileContentSignature(filePathXlsx, ".xlsx"), true);
            assert.strictEqual(await validateFileContentSignature(filePathZip, ".zip"), true);
        });

        it("should reject executable disguised as a DOCX", async () => {
            const exeDisguised = Buffer.from([0x4D, 0x5A, 0x00, 0x00]);
            const filePath = createTempFile(`${crypto.randomUUID()}.docx`, exeDisguised);
            assert.strictEqual(await validateFileContentSignature(filePath, ".docx"), false);
        });

        it("should accept valid OLECF binary signature for legacy .doc and .xls", async () => {
            const olecfBuffer = Buffer.from([0xD0, 0xCF, 0x11, 0xE0, 0xA1, 0xB1, 0x1A, 0xE1]);
            const filePathDoc = createTempFile(`${crypto.randomUUID()}.doc`, olecfBuffer);
            const filePathXls = createTempFile(`${crypto.randomUUID()}.xls`, olecfBuffer);

            assert.strictEqual(await validateFileContentSignature(filePathDoc, ".doc"), true);
            assert.strictEqual(await validateFileContentSignature(filePathXls, ".xls"), true);
        });

        it("should accept valid plain text file", async () => {
            const txtBuffer = Buffer.from("Hello world! This is a confidential memo.\r\nLine 2.");
            const filePath = createTempFile(`${crypto.randomUUID()}.txt`, txtBuffer);
            assert.strictEqual(await validateFileContentSignature(filePath, ".txt"), true);
        });

        it("should reject text file containing binary null bytes", async () => {
            const binaryBuffer = Buffer.from([0x48, 0x65, 0x6C, 0x00, 0x6C, 0x6F]); // contains \0
            const filePath = createTempFile(`${crypto.randomUUID()}.txt`, binaryBuffer);
            assert.strictEqual(await validateFileContentSignature(filePath, ".txt"), false);
        });

        it("should reject text file starting with Linux ELF signature", async () => {
            const elfBuffer = Buffer.from([0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]);
            const filePath = createTempFile(`${crypto.randomUUID()}.txt`, elfBuffer);
            assert.strictEqual(await validateFileContentSignature(filePath, ".txt"), false);
        });
    });

    describe("Storage Path Traversal Protection & Boundary Checks", () => {
        it("should validate legitimate UUID-based storage keys", () => {
            const validKey = `${crypto.randomUUID()}.pdf`;
            assert.strictEqual(isValidStorageKey(validKey), true);
        });

        it("should reject storage keys containing path traversal attempts", () => {
            assert.strictEqual(isValidStorageKey("../../etc/passwd"), false);
            assert.strictEqual(isValidStorageKey("..\\..\\windows\\system32\\cmd.exe"), false);
            assert.strictEqual(isValidStorageKey("/etc/shadow"), false);
            assert.strictEqual(isValidStorageKey("C:\\boot.ini"), false);
            assert.strictEqual(isValidStorageKey("file\0name.pdf"), false);
            assert.strictEqual(isValidStorageKey(""), false);
            assert.strictEqual(isValidStorageKey(null), false);
            assert.strictEqual(isValidStorageKey(12345), false);
        });

        it("should resolve valid storage keys strictly inside STORAGE_DIR", () => {
            const validKey = `${crypto.randomUUID()}.txt`;
            const resolved = getPrivateFilePath(validKey);
            const expected = path.resolve(STORAGE_DIR, validKey);
            assert.strictEqual(resolved, expected);
        });

        it("should throw BadRequestError on path traversal keys in getPrivateFilePath", () => {
            assert.throws(
                () => getPrivateFilePath("../../etc/passwd"),
                (err) => err instanceof BadRequestError && err.statusCode === 400
            );

            assert.throws(
                () => getPrivateFilePath("..\\..\\windows\\system32\\cmd.exe"),
                (err) => err instanceof BadRequestError && err.statusCode === 400
            );
        });

        it("should safely ignore traversal attempts in removeStoredFile without deleting arbitrary files", () => {
            // Attempting to delete a file outside storage must not throw unhandled and must not delete outside
            assert.doesNotThrow(() => {
                removeStoredFile("../../package.json");
            });
            // Ensure package.json was not deleted
            assert.ok(fs.existsSync(path.resolve(__dirname, "../../package.json")));
        });
    });

    describe("File Password Validation", () => {
        it("should accept passwords between 8 and 128 characters", () => {
            assert.strictEqual(validateFilePassword("Pass1234"), "Pass1234");
            const longPass = "A".repeat(128);
            assert.strictEqual(validateFilePassword(longPass), longPass);
        });

        it("should reject passwords shorter than 8 characters", () => {
            assert.throws(
                () => validateFilePassword("Short12"),
                (err) => err instanceof BadRequestError && err.message.includes("between 8 and 128")
            );
            assert.throws(
                () => validateFilePassword("1234567"),
                (err) => err instanceof BadRequestError
            );
        });

        it("should reject passwords longer than 128 characters", () => {
            const tooLong = "A".repeat(129);
            assert.throws(
                () => validateFilePassword(tooLong),
                (err) => err instanceof BadRequestError && err.message.includes("between 8 and 128")
            );
        });

        it("should reject non-string and empty passwords", () => {
            assert.throws(
                () => validateFilePassword(""),
                (err) => err instanceof BadRequestError && err.message.includes("cannot be empty")
            );
            assert.throws(
                () => validateFilePassword(null),
                (err) => err instanceof BadRequestError
            );
            assert.throws(
                () => validateFilePassword(12345678),
                (err) => err instanceof BadRequestError && err.message.includes("must be a string")
            );
        });

        it("should apply consistent password rules to upload, update, and verify inputs", () => {
            // Upload input
            assert.throws(
                () => validateUploadInput({ originalname: "file.txt" }, { password: "short" }),
                (err) => err instanceof BadRequestError
            );

            // Verify password input
            assert.throws(
                () => validateFilePasswordInput({ password: "short" }),
                (err) => err instanceof BadRequestError
            );

            // Valid inputs
            const uploadResult = validateUploadInput(
                { originalname: "file.txt" },
                { password: "ValidPassword123" }
            );
            assert.strictEqual(uploadResult.password, "ValidPassword123");

            const verifyResult = validateFilePasswordInput({ password: "ValidPassword123" });
            assert.strictEqual(verifyResult.password, "ValidPassword123");
        });
    });

    describe("File Display Name Validation", () => {
        it("should trim whitespace from display names", () => {
            const trimmed = validateDisplayName("   My Q3 Report.pdf   ");
            assert.strictEqual(trimmed, "My Q3 Report.pdf");
        });

        it("should reject empty or whitespace-only display names", () => {
            assert.throws(
                () => validateDisplayName(""),
                (err) => err instanceof BadRequestError && err.message.includes("cannot be empty")
            );
            assert.throws(
                () => validateDisplayName("    "),
                (err) => err instanceof BadRequestError && err.message.includes("cannot be empty")
            );
        });

        it("should reject display names exceeding 255 characters", () => {
            const longName = "A".repeat(256) + ".pdf";
            assert.throws(
                () => validateDisplayName(longName),
                (err) => err instanceof BadRequestError && err.message.includes("must not exceed 255")
            );
        });

        it("should fallback to original filename when name is not provided in upload", () => {
            const result = validateUploadInput(
                { originalname: "FinancialSummary.xlsx" },
                { password: "SecurePassword123" }
            );
            assert.strictEqual(result.name, "FinancialSummary.xlsx");
        });

        it("should validate and trim update file name", () => {
            const result = validateUpdateFileInput({ name: "  New Title.pdf  " });
            assert.strictEqual(result.name, "New Title.pdf");
        });
    });

    describe("File Description Validation", () => {
        it("should store a trimmed description on upload and default to null when absent", () => {
            const withDesc = validateUploadInput(
                { originalname: "Report.pdf" },
                { password: "SecurePassword123", description: "  Quarterly report  " }
            );
            assert.strictEqual(withDesc.description, "Quarterly report");

            const withoutDesc = validateUploadInput(
                { originalname: "Report.pdf" },
                { password: "SecurePassword123" }
            );
            assert.strictEqual(withoutDesc.description, null);
        });

        it("should reject descriptions longer than 1000 characters", () => {
            assert.throws(
                () => validateUploadInput(
                    { originalname: "Report.pdf" },
                    { password: "SecurePassword123", description: "a".repeat(1001) }
                ),
                (err) => err instanceof BadRequestError && err.message.includes("1000")
            );
        });

        it("should allow updating only the description, and clear it with an empty string", () => {
            assert.deepStrictEqual(validateUpdateFileInput({ description: "New notes" }), { description: "New notes" });
            assert.deepStrictEqual(validateUpdateFileInput({ description: "   " }), { description: null });
        });

        it("should reject an update with neither name nor description", () => {
            assert.throws(
                () => validateUpdateFileInput({}),
                (err) => err instanceof BadRequestError
            );
        });
    });
});
