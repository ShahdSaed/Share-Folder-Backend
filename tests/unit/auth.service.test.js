const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { hashPassword } = require("../../src/utils/password");
const { verifyToken } = require("../../src/utils/jwt");

// Create AuthService with injected mocks
const AuthService = require("../../src/modules/auth/auth.service").constructor;

describe("AuthService (Unit Tests with Mocks)", () => {
    let mockUserRepo;
    let mockAuditService;
    let authService;
    let testPasswordHash;

    beforeEach(async () => {
        testPasswordHash = await hashPassword("ValidPassword123!");

        mockAuditService = {
            events: [],
            logEvent: async function (evt) {
                this.events.push(evt);
                return evt;
            }
        };

        mockUserRepo = {
            users: [
                {
                    id: "admin-uuid-1",
                    name: "Admin User",
                    email: "admin@company.com",
                    passwordHash: testPasswordHash,
                    role: "ADMIN",
                    isActive: true,
                    createdAt: new Date()
                },
                {
                    id: "inactive-uuid-2",
                    name: "Inactive User",
                    email: "inactive@company.com",
                    passwordHash: testPasswordHash,
                    role: "VIEWER",
                    isActive: false,
                    createdAt: new Date()
                }
            ],
            findByEmailWithPassword: async function (email) {
                return this.users.find(u => u.email === email) || null;
            },
            findById: async function (id) {
                const u = this.users.find(u => u.id === id);
                if (!u) return null;
                const { passwordHash, ...safe } = u;
                return safe;
            }
        };

        authService = new AuthService(mockUserRepo, mockAuditService);
    });

    it("should successfully authenticate valid credentials, return a token, and never leak passwordHash", async () => {
        const result = await authService.login({
            email: "admin@company.com",
            password: "ValidPassword123!",
            ipAddress: "127.0.0.1",
            userAgent: "TestAgent"
        });

        assert.ok(result.token, "Result must contain token");
        assert.ok(result.user, "Result must contain user object");
        assert.strictEqual(result.user.id, "admin-uuid-1");
        assert.strictEqual(result.user.role, "ADMIN");
        assert.strictEqual(result.user.passwordHash, undefined, "passwordHash must never be returned");

        const decoded = verifyToken(result.token);
        assert.strictEqual(decoded.sub, "admin-uuid-1");
        assert.strictEqual(decoded.role, "ADMIN");

        // Verify audit log
        const successEvent = mockAuditService.events.find(e => e.action === "LOGIN_SUCCESS");
        assert.ok(successEvent, "Must record LOGIN_SUCCESS audit event");
        assert.strictEqual(successEvent.userId, "admin-uuid-1");
        assert.strictEqual(successEvent.result, "Success");
    });

    it("should reject invalid password with generic error and record LOGIN_FAILED audit log", async () => {
        await assert.rejects(
            () => authService.login({
                email: "admin@company.com",
                password: "WrongPassword999!",
                ipAddress: "127.0.0.1",
                userAgent: "TestAgent"
            }),
            (err) => {
                assert.strictEqual(err.statusCode, 401);
                assert.strictEqual(err.message, "Invalid email or password");
                return true;
            }
        );

        const failEvent = mockAuditService.events.find(e => e.action === "LOGIN_FAILED");
        assert.ok(failEvent, "Must record LOGIN_FAILED audit event");
        assert.strictEqual(failEvent.userId, "admin-uuid-1");
        assert.strictEqual(failEvent.result, "Failed");
    });

    it("should reject unknown email with the SAME generic error to prevent account enumeration", async () => {
        await assert.rejects(
            () => authService.login({
                email: "unknown@company.com",
                password: "AnyPassword123!",
                ipAddress: "127.0.0.1",
                userAgent: "TestAgent"
            }),
            (err) => {
                assert.strictEqual(err.statusCode, 401);
                assert.strictEqual(err.message, "Invalid email or password");
                return true;
            }
        );

        const failEvent = mockAuditService.events.find(e => e.action === "LOGIN_FAILED");
        assert.ok(failEvent, "Must record LOGIN_FAILED audit event");
        assert.strictEqual(failEvent.userId, null, "userId should be null for non-existent account");
        assert.strictEqual(failEvent.result, "Failed");
    });

    it("should reject inactive users and record LOGIN_REJECTED_INACTIVE audit log", async () => {
        await assert.rejects(
            () => authService.login({
                email: "inactive@company.com",
                password: "ValidPassword123!",
                ipAddress: "127.0.0.1",
                userAgent: "TestAgent"
            }),
            (err) => {
                assert.strictEqual(err.statusCode, 401);
                assert.ok(err.message.includes("deactivated"), "Should inform about deactivated account");
                return true;
            }
        );

        const inactiveEvent = mockAuditService.events.find(e => e.action === "LOGIN_REJECTED_INACTIVE");
        assert.ok(inactiveEvent, "Must record LOGIN_REJECTED_INACTIVE audit event");
        assert.strictEqual(inactiveEvent.userId, "inactive-uuid-2");
        assert.strictEqual(inactiveEvent.result, "Failed");
    });

    it("should retrieve safe user profile via getMe", async () => {
        const user = await authService.getMe("admin-uuid-1");
        assert.strictEqual(user.id, "admin-uuid-1");
        assert.strictEqual(user.email, "admin@company.com");
        assert.strictEqual(user.passwordHash, undefined, "passwordHash must not be exposed");
    });
});
