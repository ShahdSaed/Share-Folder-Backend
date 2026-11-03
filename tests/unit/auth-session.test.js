const { describe, it, beforeEach } = require("node:test");
const assert = require("node:assert/strict");
const { hashPassword } = require("../../src/utils/password");
const { verifyAccessToken, signFileUnlockToken } = require("../../src/utils/jwt");
const { hashRefreshToken } = require("../../src/utils/refresh-token");
const { validateExpiresInDays } = require("../../src/modules/file-access/file-access.validation");
const AuthService = require("../../src/modules/auth/auth.service").constructor;

describe("Refresh token hashing", () => {
    it("should hash refresh tokens with SHA-256 and never equal the raw token", () => {
        const raw = "plain-refresh-token-value";
        const hashed = hashRefreshToken(raw);
        assert.strictEqual(hashed.length, 64);
        assert.notEqual(hashed, raw);
        assert.strictEqual(hashRefreshToken(raw), hashed);
    });
});

describe("AuthService session lifecycle", () => {
    let authService;
    let mockSessionRepo;
    let user;

    beforeEach(async () => {
        const passwordHash = await hashPassword("ValidPassword123!");
        user = {
            id: "user-1",
            name: "Viewer",
            email: "viewer@company.com",
            passwordHash,
            role: "VIEWER",
            isActive: true,
            createdAt: new Date()
        };

        mockSessionRepo = {
            rotateCalls: 0,
            revokedUsers: [],
            revokedTokens: [],
            createSession: async () => ({ id: "sess-1" }),
            rotateSession: async function ({ rawToken, newRawToken }) {
                this.rotateCalls += 1;
                if (rawToken === "reused-token") {
                    return { reused: true, userId: user.id };
                }
                if (rawToken === "expired-token" || rawToken === "missing-token") {
                    return { invalid: true };
                }
                return {
                    rotated: true,
                    user,
                    newRawToken,
                    newSession: { id: "sess-2" }
                };
            },
            revokeByRawToken: async function (raw) {
                this.revokedTokens.push(raw);
                return { count: raw ? 1 : 0 };
            },
            revokeAllForUser: async function (userId) {
                this.revokedUsers.push(userId);
                return { count: 1 };
            }
        };

        authService = new AuthService(
            {
                findByEmailWithPassword: async () => user,
                findById: async () => {
                    const { passwordHash: _ignored, ...safe } = user;
                    return safe;
                },
                findByIdWithPassword: async () => user,
                updatePassword: async () => {
                    const { passwordHash: _ignored, ...safe } = user;
                    return safe;
                }
            },
            { logEvent: async () => null },
            mockSessionRepo
        );
    });

    it("should rotate a refresh token and issue a new access token", async () => {
        const result = await authService.refresh({
            rawToken: "active-refresh",
            ipAddress: "127.0.0.1",
            userAgent: "test"
        });

        assert.ok(result.accessToken);
        assert.ok(result.refreshToken);
        assert.notEqual(result.refreshToken, "active-refresh");
        const decoded = verifyAccessToken(result.accessToken);
        assert.strictEqual(decoded.sub, "user-1");
        assert.strictEqual(mockSessionRepo.rotateCalls, 1);
    });

    it("should reject refresh token reuse with a generic error", async () => {
        await assert.rejects(
            () => authService.refresh({ rawToken: "reused-token" }),
            (err) => err.statusCode === 401 && err.message === "Invalid refresh token"
        );
    });

    it("should reject expired or unknown refresh tokens generically", async () => {
        await assert.rejects(
            () => authService.refresh({ rawToken: "expired-token" }),
            (err) => err.statusCode === 401 && err.message === "Invalid refresh token"
        );
    });

    it("should reject refresh if the user is inactive and revoke all sessions", async () => {
        user.isActive = false;
        await assert.rejects(
            () => authService.refresh({ rawToken: "active-refresh" }),
            (err) => err.statusCode === 401 && err.message === "Invalid refresh token"
        );
        assert.deepStrictEqual(mockSessionRepo.revokedUsers, ["user-1"]);
    });

    it("should safely handle concurrent refresh requests where one claims the token first", async () => {
        let claims = 0;
        mockSessionRepo.rotateSession = async function ({ newRawToken }) {
            claims += 1;
            if (claims === 1) {
                return { rotated: true, user, newRawToken, newSession: { id: "sess-1" } };
            }
            // Second concurrent call loses race
            return { invalid: true };
        };

        const firstPromise = authService.refresh({ rawToken: "shared-token" });
        const secondPromise = authService.refresh({ rawToken: "shared-token" });

        const results = await Promise.allSettled([firstPromise, secondPromise]);
        const fulfilled = results.filter((r) => r.status === "fulfilled");
        const rejected = results.filter((r) => r.status === "rejected");

        assert.strictEqual(fulfilled.length, 1, "Exactly one concurrent refresh must succeed");
        assert.strictEqual(rejected.length, 1, "Concurrent duplicate refresh must be rejected");
        assert.strictEqual(rejected[0].reason.statusCode, 401);
    });

    it("should revoke the current session on logout", async () => {
        await authService.logout({ rawToken: "active-refresh" });
        assert.deepStrictEqual(mockSessionRepo.revokedTokens, ["active-refresh"]);
    });

    it("should revoke all sessions on logout-all", async () => {
        await authService.logoutAll({ userId: "user-1" });
        assert.deepStrictEqual(mockSessionRepo.revokedUsers, ["user-1"]);
    });

    it("should change password and revoke all sessions", async () => {
        const updated = await authService.changePassword({
            userId: "user-1",
            currentPassword: "ValidPassword123!",
            newPassword: "BrandNewPassword123!"
        });
        assert.strictEqual(updated.passwordHash, undefined);
        assert.deepStrictEqual(mockSessionRepo.revokedUsers, ["user-1"]);
    });
});

describe("FILE_UNLOCK tokens cannot be used as access tokens", () => {
    it("should fail verifyAccessToken for an unlock token", () => {
        const unlock = signFileUnlockToken({ userId: "user-1", fileId: "file-1" });
        assert.throws(
            () => verifyAccessToken(unlock),
            (err) => err.statusCode === 401
        );
    });
});

describe("expiresInDays validation", () => {
    it("should default to 30 days when omitted", () => {
        assert.strictEqual(validateExpiresInDays(undefined), 30);
    });

    it("should reject zero, negatives, and non-integers", () => {
        assert.throws(() => validateExpiresInDays(0), /positive integer|between/);
        assert.throws(() => validateExpiresInDays(-1), /between/);
        assert.throws(() => validateExpiresInDays(1.5), /positive integer/);
        assert.throws(() => validateExpiresInDays(400), /between/);
    });

    it("should accept a valid integer in range", () => {
        assert.strictEqual(validateExpiresInDays(7), 7);
    });
});
