const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { signToken, signFileUnlockToken } = require("../../src/utils/jwt");
const { authenticate } = require("../../src/middlewares/auth.middleware");
const { authorizeRoles } = require("../../src/middlewares/role.middleware");
const userRepository = require("../../src/modules/users/user.repository");
const auditLogService = require("../../src/modules/audit-logs/audit-log.service");

describe("Middleware Unit Tests", () => {
    describe("authenticate middleware", () => {
        let originalFindById;

        beforeEach(() => {
            originalFindById = userRepository.findById;
        });

        it("should reject when Authorization header is missing", async () => {
            const req = { headers: {} };
            const res = {};
            let nextError;
            await authenticate(req, res, (err) => { nextError = err; });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 401);
            assert.ok(nextError.message.includes("missing"));
        });

        it("should reject when Authorization header is not Bearer format", async () => {
            const req = { headers: { authorization: "Basic 123456" } };
            const res = {};
            let nextError;
            await authenticate(req, res, (err) => { nextError = err; });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 401);
            assert.ok(nextError.message.includes("Bearer"));
        });

        it("should reject when token is invalid or corrupted", async () => {
            const req = { headers: { authorization: "Bearer invalid.corrupted.token" } };
            const res = {};
            let nextError;
            await authenticate(req, res, (err) => { nextError = err; });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 401);
        });

        it("should reject when user no longer exists in database", async () => {
            const token = signToken({ sub: "deleted-user-id", role: "VIEWER" });
            userRepository.findById = async () => null;

            const req = { headers: { authorization: `Bearer ${token}` } };
            const res = {};
            let nextError;
            await authenticate(req, res, (err) => { nextError = err; });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 401);
            assert.ok(nextError.message.includes("no longer exists"));

            userRepository.findById = originalFindById;
        });

        it("should reject when user is deactivated in database", async () => {
            const token = signToken({ sub: "deactivated-user-id", role: "VIEWER" });
            userRepository.findById = async () => ({
                id: "deactivated-user-id",
                email: "deactivated@company.com",
                role: "VIEWER",
                isActive: false
            });

            const req = { headers: { authorization: `Bearer ${token}` } };
            const res = {};
            let nextError;
            await authenticate(req, res, (err) => { nextError = err; });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 401);
            assert.ok(nextError.message.includes("deactivated"));

            userRepository.findById = originalFindById;
        });

        it("should attach safe user to req and call next on valid token and active user", async () => {
            const token = signToken({ sub: "active-user-id", role: "VIEWER" });
            const mockUser = {
                id: "active-user-id",
                email: "active@company.com",
                role: "VIEWER",
                isActive: true
            };
            userRepository.findById = async () => mockUser;

            const req = { headers: { authorization: `Bearer ${token}` } };
            const res = {};
            let nextCalled = false;
            await authenticate(req, res, (err) => {
                assert.ifError(err);
                nextCalled = true;
            });

            assert.strictEqual(nextCalled, true);
            assert.deepStrictEqual(req.user, mockUser);

            userRepository.findById = originalFindById;
        });

        it("should reject FILE_UNLOCK tokens as normal authentication", async () => {
            const unlockToken = signFileUnlockToken({
                userId: "active-user-id",
                fileId: "file-1"
            });
            const req = { headers: { authorization: `Bearer ${unlockToken}` } };
            const res = {};
            let nextError;
            await authenticate(req, res, (err) => { nextError = err; });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 401);
            assert.ok(nextError.message.includes("invalid"));
        });
    });

    describe("authorizeRoles middleware", () => {
        let originalLogEvent;
        let loggedEvents = [];

        beforeEach(() => {
            loggedEvents = [];
            originalLogEvent = auditLogService.logEvent;
            auditLogService.logEvent = async (evt) => {
                loggedEvents.push(evt);
                return evt;
            };
        });

        it("should allow request when user has authorized role", async () => {
            const middleware = authorizeRoles("ADMIN");
            const req = { user: { id: "admin-1", role: "ADMIN" } };
            const res = {};
            let nextCalled = false;

            await middleware(req, res, (err) => {
                assert.ifError(err);
                nextCalled = true;
            });

            assert.strictEqual(nextCalled, true);
        });

        it("should reject request with 403 Forbidden and record audit when user has insufficient role", async () => {
            const middleware = authorizeRoles("ADMIN");
            const req = {
                user: { id: "viewer-1", role: "VIEWER" },
                originalUrl: "/api/admin/audit-logs",
                headers: { "user-agent": "Mozilla" }
            };
            const res = {};
            let nextError;

            await middleware(req, res, (err) => {
                nextError = err;
            });

            assert.ok(nextError);
            assert.strictEqual(nextError.statusCode, 403);
            assert.ok(nextError.message.includes("Access forbidden"));

            // Check audit log
            assert.strictEqual(loggedEvents.length, 1);
            assert.strictEqual(loggedEvents[0].action, "FORBIDDEN_ACCESS_ATTEMPT");
            assert.strictEqual(loggedEvents[0].userId, "viewer-1");

            auditLogService.logEvent = originalLogEvent;
        });
    });

    describe("upload.middleware", () => {
        const { handleFileUpload, uploadSingle } = require("../../src/middlewares/upload.middleware");

        it("should export handleFileUpload middleware function and uploadSingle factory", () => {
            assert.strictEqual(typeof handleFileUpload, "function");
            assert.strictEqual(typeof uploadSingle, "function");
            assert.strictEqual(typeof uploadSingle("customField"), "function");
        });
    });
});
