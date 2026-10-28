const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const path = require("path");
const fs = require("fs");
const { app } = require("../../server");
const prismaPromise = require("../../src/config/prisma");
const { hashPassword } = require("../../src/utils/password");

describe("Users and Files Integration Tests", () => {
    let server;
    let baseUrl;
    let prisma;

    let adminToken;
    let viewerToken;
    let testAdminId;
    let testViewerId;
    let uploadedFileId;
    let unlockToken;

    const ADMIN_EMAIL = "test-files-admin@company.com";
    const VIEWER_EMAIL = "test-files-viewer@company.com";
    const PASSWORD = "SecurePassword123!";
    const FILE_PASSWORD = "FileSecretPassword123!";

    before(async () => {
        prisma = await prismaPromise;

        // Cleanup any leftovers from prior runs
        const existingUsers = await prisma.user.findMany({
            where: { email: { in: [ADMIN_EMAIL, VIEWER_EMAIL, "created-viewer@company.com"] } }
        });
        const userIds = existingUsers.map((u) => u.id);

        if (userIds.length > 0) {
            await prisma.fileAccessGrant.deleteMany({ where: { userId: { in: userIds } } });
            await prisma.auditLog.deleteMany({ where: { userId: { in: userIds } } });
            await prisma.file.deleteMany({ where: { uploadedBy: { in: userIds } } });
            await prisma.user.deleteMany({ where: { id: { in: userIds } } });
        }

        const passwordHash = await hashPassword(PASSWORD);

        const admin = await prisma.user.create({
            data: {
                name: "Files Test Admin",
                email: ADMIN_EMAIL,
                passwordHash,
                role: "ADMIN",
                isActive: true
            }
        });
        testAdminId = admin.id;

        const viewer = await prisma.user.create({
            data: {
                name: "Files Test Viewer",
                email: VIEWER_EMAIL,
                passwordHash,
                role: "VIEWER",
                isActive: true
            }
        });
        testViewerId = viewer.id;

        // Start server on ephemeral port
        await new Promise((resolve) => {
            server = app.listen(0, () => {
                const port = server.address().port;
                baseUrl = `http://127.0.0.1:${port}`;
                resolve();
            });
        });

        // Login as admin
        const adminLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: ADMIN_EMAIL, password: PASSWORD })
        });
        const adminLoginData = await adminLoginRes.json();
        adminToken = adminLoginData.data.token;

        // Login as viewer
        const viewerLoginRes = await fetch(`${baseUrl}/api/v1/auth/login`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ email: VIEWER_EMAIL, password: PASSWORD })
        });
        const viewerLoginData = await viewerLoginRes.json();
        viewerToken = viewerLoginData.data.token;
    });

    after(async () => {
        if (prisma) {
            const users = await prisma.user.findMany({
                where: { email: { in: [ADMIN_EMAIL, VIEWER_EMAIL, "created-viewer@company.com"] } }
            });
            const userIds = users.map((u) => u.id);

            if (userIds.length > 0) {
                await prisma.fileAccessGrant.deleteMany({ where: { userId: { in: userIds } } });
                await prisma.auditLog.deleteMany({ where: { userId: { in: userIds } } });
                await prisma.file.deleteMany({ where: { uploadedBy: { in: userIds } } });
                await prisma.user.deleteMany({ where: { id: { in: userIds } } });
            }
        }

        await new Promise((resolve) => server.close(resolve));
        if (prisma) {
            await prisma.$disconnect();
        }
    });

    describe("User Management Endpoints", () => {
        let createdUserId;

        it("should allow ADMIN to create a new user (POST /api/v1/users)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/users`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`
                },
                body: JSON.stringify({
                    name: "Created Viewer",
                    email: "created-viewer@company.com",
                    password: "Password123!",
                    role: "VIEWER"
                })
            });

            assert.strictEqual(res.status, 201);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.strictEqual(data.data.user.email, "created-viewer@company.com");
            assert.strictEqual(data.data.user.passwordHash, undefined, "passwordHash must never be exposed");
            createdUserId = data.data.user.id;
        });

        it("should reject VIEWER attempting to create a user with 403 Forbidden", async () => {
            const res = await fetch(`${baseUrl}/api/v1/users`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${viewerToken}`
                },
                body: JSON.stringify({
                    name: "Hacker Account",
                    email: "hacker@company.com",
                    password: "Password123!",
                    role: "ADMIN"
                })
            });

            assert.strictEqual(res.status, 403);
        });

        it("should allow ADMIN to list users with pagination (GET /api/v1/users)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/users?page=1&limit=10`, {
                headers: { Authorization: `Bearer ${adminToken}` }
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.ok(Array.isArray(data.data.users));
            assert.ok(data.data.pagination);
        });

        it("should reject VIEWER attempting to list all users with 403 Forbidden", async () => {
            const res = await fetch(`${baseUrl}/api/v1/users`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });

            assert.strictEqual(res.status, 403);
        });

        it("should allow ADMIN to toggle user account status (PATCH /api/v1/users/:id/status)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/users/${createdUserId}/status`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`
                },
                body: JSON.stringify({ isActive: false })
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.data.user.isActive, false);
        });
    });

    describe("File Management, Password Protection, and Access Grants", () => {
        it("should allow ADMIN to upload a password-protected file (POST /api/v1/files)", async () => {
            const formData = new FormData();
            const fileBlob = new Blob(["Confidential financial audit data for Q3."], {
                type: "text/plain"
            });
            formData.append("file", fileBlob, "AuditReport.txt");
            formData.append("password", FILE_PASSWORD);
            formData.append("name", "Q3 Financial Audit.txt");

            const res = await fetch(`${baseUrl}/api/v1/files`, {
                method: "POST",
                headers: { Authorization: `Bearer ${adminToken}` },
                body: formData
            });

            assert.strictEqual(res.status, 201);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.strictEqual(data.data.file.name, "Q3 Financial Audit.txt");
            assert.strictEqual(data.data.file.passwordHash, undefined, "passwordHash must never be exposed");
            assert.strictEqual(typeof data.data.file.size, "number", "size must be serialized as number, not BigInt");

            uploadedFileId = data.data.file.id;
        });

        it("should reject file upload when password is shorter than 8 characters and leave no orphaned files", async () => {
            const privateStorageDir = path.resolve(__dirname, "../../storage/private");
            const filesBefore = fs.readdirSync(privateStorageDir);

            const formData = new FormData();
            const fileBlob = new Blob(["Short password test file content"], { type: "text/plain" });
            formData.append("file", fileBlob, "ShortPass.txt");
            formData.append("password", "short1"); // 6 chars < 8

            const res = await fetch(`${baseUrl}/api/v1/files`, {
                method: "POST",
                headers: { Authorization: `Bearer ${adminToken}` },
                body: formData
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.ok(data.message.includes("between 8 and 128"));

            // Verify no file was left on disk
            const filesAfter = fs.readdirSync(privateStorageDir);
            assert.strictEqual(filesAfter.length, filesBefore.length, "No orphaned file should remain in private storage");
        });

        it("should reject file upload with extension and MIME type mismatch", async () => {
            const formData = new FormData();
            // .pdf with text/plain mime type
            const fileBlob = new Blob(["Hello"], { type: "text/plain" });
            formData.append("file", fileBlob, "fake.pdf");
            formData.append("password", "SecurePassword123!");

            const res = await fetch(`${baseUrl}/api/v1/files`, {
                method: "POST",
                headers: { Authorization: `Bearer ${adminToken}` },
                body: formData
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.ok(data.message.includes("Unsupported file type or invalid MIME type"));
        });

        it("should reject file upload when content signature does not match declared type and clean up disk", async () => {
            const privateStorageDir = path.resolve(__dirname, "../../storage/private");
            const filesBefore = fs.readdirSync(privateStorageDir);

            const formData = new FormData();
            // Declared as application/pdf, but content is Windows executable MZ header
            const fakePdfBlob = new Blob([new Uint8Array([0x4D, 0x5A, 0x90, 0x00, 0x03, 0x00])], {
                type: "application/pdf"
            });
            formData.append("file", fakePdfBlob, "disguised_exe.pdf");
            formData.append("password", "SecurePassword123!");

            const res = await fetch(`${baseUrl}/api/v1/files`, {
                method: "POST",
                headers: { Authorization: `Bearer ${adminToken}` },
                body: formData
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.ok(data.message.includes("File content does not match its declared type"));

            // Verify orphaned file was cleaned up immediately
            const filesAfter = fs.readdirSync(privateStorageDir);
            assert.strictEqual(filesAfter.length, filesBefore.length, "Uploaded file with invalid signature must be deleted");
        });

        it("should reject file password verification when password is shorter than 8 characters", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/verify-password`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${viewerToken}`
                },
                body: JSON.stringify({ password: "123" })
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.ok(data.message.includes("between 8 and 128"));
        });

        it("should reject updating file name when name is empty", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`
                },
                body: JSON.stringify({ name: "   " })
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.ok(data.message.includes("cannot be empty"));
        });

        it("should reject VIEWER attempting to upload a file with 403 Forbidden", async () => {
            const formData = new FormData();
            const fileBlob = new Blob(["Malicious upload attempt"], { type: "text/plain" });
            formData.append("file", fileBlob, "exploit.txt");
            formData.append("password", "Pass123!");

            const res = await fetch(`${baseUrl}/api/v1/files`, {
                method: "POST",
                headers: { Authorization: `Bearer ${viewerToken}` },
                body: formData
            });

            assert.strictEqual(res.status, 403);
        });

        it("should return empty list for VIEWER before file access is granted", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.data.files.length, 0, "VIEWER must see zero files without an explicit grant");
        });

        it("should allow ADMIN to grant file access to VIEWER (POST /api/v1/files/:id/access)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/access`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`
                },
                body: JSON.stringify({
                    userId: testViewerId,
                    expiresInDays: 7
                })
            });

            assert.strictEqual(res.status, 201);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.strictEqual(data.data.grant.userId, testViewerId);
        });

        it("should now show the assigned file in the VIEWER's file list", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.data.files.length, 1);
            assert.strictEqual(data.data.files[0].id, uploadedFileId);
        });

        it("should reject incorrect file password attempt (POST /api/v1/files/:id/verify-password)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/verify-password`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${viewerToken}`
                },
                body: JSON.stringify({ password: "WrongFilePassword!" })
            });

            assert.strictEqual(res.status, 401);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
        });

        it("should verify correct file password and return short-lived unlock token", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/verify-password`, {
                method: "POST",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${viewerToken}`
                },
                body: JSON.stringify({ password: FILE_PASSWORD })
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.ok(data.data.unlockToken, "Unlock grant token must be returned");

            unlockToken = data.data.unlockToken;
        });

        it("should reject file content request without unlock token for VIEWER", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/content`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });

            assert.strictEqual(res.status, 403);
        });

        it("should stream file content successfully when unlock token is provided", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/content?token=${unlockToken}`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });

            assert.strictEqual(res.status, 200);
            const text = await res.text();
            assert.strictEqual(text, "Confidential financial audit data for Q3.");
        });

        it("should allow ADMIN to update file metadata (PATCH /api/v1/files/:id)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}`, {
                method: "PATCH",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: `Bearer ${adminToken}`
                },
                body: JSON.stringify({ name: "Q3 Financial Audit - Final.txt" })
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.data.file.name, "Q3 Financial Audit - Final.txt");
        });

        it("should allow ADMIN to revoke access grant (DELETE /api/v1/files/:id/access/:userId)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}/access/${testViewerId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${adminToken}` }
            });

            assert.strictEqual(res.status, 200);

            // VIEWER should now see 0 files again
            const listRes = await fetch(`${baseUrl}/api/v1/files`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });
            const listData = await listRes.json();
            assert.strictEqual(listData.data.files.length, 0);
        });

        it("should allow ADMIN to delete the file (DELETE /api/v1/files/:id)", async () => {
            const res = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}`, {
                method: "DELETE",
                headers: { Authorization: `Bearer ${adminToken}` }
            });

            assert.strictEqual(res.status, 200);

            // Confirm file is gone
            const getRes = await fetch(`${baseUrl}/api/v1/files/${uploadedFileId}`, {
                headers: { Authorization: `Bearer ${adminToken}` }
            });
            assert.strictEqual(getRes.status, 404);
        });
    });
});
