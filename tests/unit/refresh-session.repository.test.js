const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const RefreshSessionRepository = require("../../src/modules/auth/refresh-session.repository").constructor;
const { hashRefreshToken } = require("../../src/utils/refresh-token");

describe("RefreshSessionRepository - Unit Tests", () => {
    function createMockPrisma({ existingSession = null, updateManyCount = 1 } = {}) {
        let createdSession = null;
        let updateReplacedBy = null;
        let massRevokedWhere = null;

        const tx = {
            refreshSession: {
                findUnique: async () => existingSession,
                updateMany: async ({ where, data }) => {
                    if (where.userId) {
                        massRevokedWhere = where;
                        return { count: 2 };
                    }
                    return { count: updateManyCount };
                },
                create: async ({ data }) => {
                    createdSession = { id: "new-session-id", ...data };
                    return createdSession;
                },
                update: async ({ where, data }) => {
                    updateReplacedBy = { where, data };
                    return { ...existingSession, ...data };
                }
            }
        };

        const mockPrisma = {
            $transaction: async (callback) => callback(tx),
            refreshSession: {
                create: async ({ data }) => ({ id: "sess-created", ...data }),
                findUnique: async () => existingSession,
                updateMany: async ({ where, data }) => ({ count: 1 })
            }
        };

        return { mockPrisma, getTxState: () => ({ createdSession, updateReplacedBy, massRevokedWhere }) };
    }

    it("should successfully rotate an active session atomically", async () => {
        const rawToken = "current-valid-raw-token";
        const newRawToken = "brand-new-raw-token";
        const user = { id: "user-1", email: "user@company.com", isActive: true };

        const existingSession = {
            id: "old-session-id",
            userId: "user-1",
            tokenHash: hashRefreshToken(rawToken),
            expiresAt: new Date(Date.now() + 600000),
            revokedAt: null,
            replacedBy: null,
            user
        };

        const { mockPrisma, getTxState } = createMockPrisma({ existingSession, updateManyCount: 1 });
        const repo = new RefreshSessionRepository();
        repo.getPrisma = async () => mockPrisma;

        const result = await repo.rotateSession({
            rawToken,
            newRawToken,
            expiresAt: new Date(Date.now() + 86400000),
            ipAddress: "127.0.0.1",
            userAgent: "TestAgent"
        });

        assert.strictEqual(result.rotated, true);
        assert.strictEqual(result.newRawToken, newRawToken);
        assert.strictEqual(result.user.id, "user-1");

        const { createdSession, updateReplacedBy } = getTxState();
        assert.ok(createdSession);
        assert.strictEqual(createdSession.tokenHash, hashRefreshToken(newRawToken));
        assert.strictEqual(updateReplacedBy.data.replacedBy, "new-session-id");
    });

    it("should detect token reuse and revoke all sessions for that user", async () => {
        const rawToken = "already-rotated-raw-token";
        const newRawToken = "attempted-new-token";

        const existingSession = {
            id: "old-session-id",
            userId: "victim-user-id",
            tokenHash: hashRefreshToken(rawToken),
            expiresAt: new Date(Date.now() + 600000),
            revokedAt: new Date(Date.now() - 5000), // Already rotated
            replacedBy: "newer-session-id", // Already has a replacement!
            user: { id: "victim-user-id", isActive: true }
        };

        const { mockPrisma, getTxState } = createMockPrisma({ existingSession });
        const repo = new RefreshSessionRepository();
        repo.getPrisma = async () => mockPrisma;

        const result = await repo.rotateSession({
            rawToken,
            newRawToken,
            expiresAt: new Date(Date.now() + 86400000)
        });

        assert.strictEqual(result.reused, true);
        assert.strictEqual(result.userId, "victim-user-id");

        const { massRevokedWhere } = getTxState();
        assert.ok(massRevokedWhere);
        assert.strictEqual(massRevokedWhere.userId, "victim-user-id");
        assert.strictEqual(massRevokedWhere.revokedAt, null);
    });

    it("should reject concurrent rotation if token was already claimed during race condition", async () => {
        const rawToken = "racing-raw-token";
        const newRawToken = "racing-new-token";

        const existingSession = {
            id: "session-being-raced",
            userId: "user-1",
            tokenHash: hashRefreshToken(rawToken),
            expiresAt: new Date(Date.now() + 600000),
            revokedAt: null,
            replacedBy: null,
            user: { id: "user-1", isActive: true }
        };

        // Simulate updateMany returning 0 because a concurrent request claimed it first
        const { mockPrisma, getTxState } = createMockPrisma({ existingSession, updateManyCount: 0 });
        const repo = new RefreshSessionRepository();
        repo.getPrisma = async () => mockPrisma;

        const result = await repo.rotateSession({
            rawToken,
            newRawToken,
            expiresAt: new Date(Date.now() + 86400000)
        });

        assert.strictEqual(result.invalid, true);
        const { createdSession } = getTxState();
        assert.strictEqual(createdSession, null, "No new session should be created on race loss");
    });

    it("should reject expired refresh tokens", async () => {
        const rawToken = "expired-token";
        const newRawToken = "new-token";

        const existingSession = {
            id: "expired-sess",
            userId: "user-1",
            tokenHash: hashRefreshToken(rawToken),
            expiresAt: new Date(Date.now() - 10000), // Expired in past
            revokedAt: null,
            replacedBy: null,
            user: { id: "user-1", isActive: true }
        };

        const { mockPrisma } = createMockPrisma({ existingSession });
        const repo = new RefreshSessionRepository();
        repo.getPrisma = async () => mockPrisma;

        const result = await repo.rotateSession({
            rawToken,
            newRawToken,
            expiresAt: new Date(Date.now() + 86400000)
        });

        assert.strictEqual(result.invalid, true);
    });
});

