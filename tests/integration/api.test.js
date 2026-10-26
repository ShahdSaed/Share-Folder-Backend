const { describe, it, before, after } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const { app } = require("../../server");
const prismaPromise = require("../../src/config/prisma");
const { hashPassword } = require("../../src/utils/password");

describe("API Integration Tests", () => {
    let server;
    let baseUrl;
    let prisma;
    let testAdminUser;
    let testViewerUser;
    let adminToken;
    let viewerToken;

    before(async () => {
        prisma = await prismaPromise;

        // Start Express app on ephemeral port for isolated testing
        server = http.createServer(app);
        await new Promise((resolve) => server.listen(0, resolve));
        const port = server.address().port;
        baseUrl = `http://127.0.0.1:${port}`;

        // Create isolated test users
        const passwordHash = await hashPassword("TestPassword123!");

        // Remove any prior test users with these emails
        await prisma.auditLog.deleteMany({
            where: {
                user: {
                    email: { in: ["test-admin-integration@company.com", "test-viewer-integration@company.com"] }
                }
            }
        });
        await prisma.user.deleteMany({
            where: {
                email: { in: ["test-admin-integration@company.com", "test-viewer-integration@company.com"] }
            }
        });

        testAdminUser = await prisma.user.create({
            data: {
                name: "Integration Admin",
                email: "test-admin-integration@company.com",
                passwordHash,
                role: "ADMIN",
                isActive: true
            }
        });

        testViewerUser = await prisma.user.create({
            data: {
                name: "Integration Viewer",
                email: "test-viewer-integration@company.com",
                passwordHash,
                role: "VIEWER",
                isActive: true
            }
        });
    });

    after(async () => {
        // Clean up test data
        if (prisma) {
            await prisma.auditLog.deleteMany({
                where: {
                    user: {
                        email: { in: ["test-admin-integration@company.com", "test-viewer-integration@company.com"] }
                    }
                }
            });
            await prisma.user.deleteMany({
                where: {
                    email: { in: ["test-admin-integration@company.com", "test-viewer-integration@company.com"] }
                }
            });
        }

        // Close test server
        await new Promise((resolve) => server.close(resolve));

        // Disconnect Prisma
        if (prisma) {
            await prisma.$disconnect();
        }
    });

    describe("GET /api/health", () => {
        it("should return 200 ok and confirm database connection", async () => {
            const res = await fetch(`${baseUrl}/api/health`);
            assert.strictEqual(res.status, 200);

            const data = await res.json();
            assert.strictEqual(data.status, "ok");
            assert.strictEqual(data.message, "Backend and database are connected");
        });
    });

    describe("POST /api/auth/login", () => {
        it("should reject malformed JSON with 400 Bad Request", async () => {
            const res = await fetch(`${baseUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: "invalid-json{"
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.strictEqual(data.code, "INVALID_JSON");
        });

        it("should reject missing password with 400 Bad Request", async () => {
            const res = await fetch(`${baseUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email: "admin@company.com" })
            });

            assert.strictEqual(res.status, 400);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
        });

        it("should reject non-existent user with generic 401 Unauthorized", async () => {
            const res = await fetch(`${baseUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: "non-existent-user@company.com",
                    password: "Password123!"
                })
            });

            assert.strictEqual(res.status, 401);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.strictEqual(data.message, "Invalid email or password");
        });

        it("should reject incorrect password with the same generic 401 Unauthorized", async () => {
            const res = await fetch(`${baseUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: "test-admin-integration@company.com",
                    password: "WrongPassword999!"
                })
            });

            assert.strictEqual(res.status, 401);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.strictEqual(data.message, "Invalid email or password");
        });

        it("should authenticate ADMIN successfully, return JWT, and never expose password hash", async () => {
            const res = await fetch(`${baseUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: "test-admin-integration@company.com",
                    password: "TestPassword123!"
                })
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.ok(data.data.token, "JWT token must be returned");
            assert.strictEqual(data.data.user.email, "test-admin-integration@company.com");
            assert.strictEqual(data.data.user.role, "ADMIN");
            assert.strictEqual(data.data.user.passwordHash, undefined, "passwordHash must never be exposed");

            adminToken = data.data.token;
        });

        it("should authenticate VIEWER successfully and return JWT", async () => {
            const res = await fetch(`${baseUrl}/api/auth/login`, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({
                    email: "test-viewer-integration@company.com",
                    password: "TestPassword123!"
                })
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.ok(data.data.token);
            assert.strictEqual(data.data.user.role, "VIEWER");

            viewerToken = data.data.token;
        });
    });

    describe("GET /api/auth/me", () => {
        it("should reject unauthenticated request with 401", async () => {
            const res = await fetch(`${baseUrl}/api/auth/me`);
            assert.strictEqual(res.status, 401);
        });

        it("should return safe profile for authenticated admin", async () => {
            const res = await fetch(`${baseUrl}/api/auth/me`, {
                headers: { Authorization: `Bearer ${adminToken}` }
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.strictEqual(data.data.user.email, "test-admin-integration@company.com");
            assert.strictEqual(data.data.user.role, "ADMIN");
            assert.strictEqual(data.data.user.passwordHash, undefined);
        });
    });

    describe("GET /api/admin/audit-logs", () => {
        it("should reject unauthenticated request with 401", async () => {
            const res = await fetch(`${baseUrl}/api/admin/audit-logs`);
            assert.strictEqual(res.status, 401);
        });

        it("should reject VIEWER user with 403 Forbidden", async () => {
            const res = await fetch(`${baseUrl}/api/admin/audit-logs`, {
                headers: { Authorization: `Bearer ${viewerToken}` }
            });

            assert.strictEqual(res.status, 403);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.strictEqual(data.code, "FORBIDDEN");
        });

        it("should allow ADMIN user to view paginated audit logs with 200 OK", async () => {
            const res = await fetch(`${baseUrl}/api/admin/audit-logs?page=1&limit=10`, {
                headers: { Authorization: `Bearer ${adminToken}` }
            });

            assert.strictEqual(res.status, 200);
            const data = await res.json();
            assert.strictEqual(data.status, "success");
            assert.ok(Array.isArray(data.data.logs), "logs must be an array");
            assert.ok(data.data.pagination, "pagination metadata must be present");
            assert.strictEqual(data.data.pagination.page, 1);
            assert.strictEqual(data.data.pagination.limit, 10);
        });
    });

    describe("404 Not Found Handler", () => {
        it("should return clean JSON 404 for non-existent endpoint", async () => {
            const res = await fetch(`${baseUrl}/api/non-existent-endpoint`);
            assert.strictEqual(res.status, 404);
            const data = await res.json();
            assert.strictEqual(data.status, "error");
            assert.strictEqual(data.code, "ROUTE_NOT_FOUND");
        });
    });
});
