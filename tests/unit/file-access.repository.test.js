const { describe, it, beforeEach, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const fileAccessRepository = require("../../src/modules/file-access/file-access.repository");

describe("FileAccessRepository grant uniqueness", () => {
    let originalGetPrisma;
    let stored;
    let upsertCalls;
    let createCalls;
    let mockPrisma;

    function uniqueWhere({ userId, fileId }) {
        return stored.find((row) => row.userId === userId && row.fileId === fileId) || null;
    }

    beforeEach(() => {
        originalGetPrisma = fileAccessRepository.getPrisma;
        stored = [];
        upsertCalls = 0;
        createCalls = 0;

        mockPrisma = {
            fileAccessGrant: {
                findUnique: async ({ where }) => {
                    const pair = where.userId_fileId;
                    assert.ok(pair, "findUnique must use the composite unique key userId_fileId");
                    return uniqueWhere(pair);
                },
                findMany: async ({ where }) => stored.filter((row) => row.fileId === where.fileId),
                upsert: async ({ where, update, create }) => {
                    upsertCalls += 1;
                    const pair = where.userId_fileId;
                    assert.ok(pair, "upsert must use the composite unique key userId_fileId");
                    const existing = uniqueWhere(pair);
                    if (existing) {
                        existing.expiresAt = update.expiresAt;
                        return { ...existing, user: { id: existing.userId, role: "VIEWER" } };
                    }
                    const created = {
                        id: `grant-${stored.length + 1}`,
                        userId: create.userId,
                        fileId: create.fileId,
                        expiresAt: create.expiresAt,
                        createdAt: new Date()
                    };
                    stored.push(created);
                    createCalls += 1;
                    return { ...created, user: { id: created.userId, role: "VIEWER" } };
                },
                deleteMany: async ({ where }) => {
                    const before = stored.length;
                    stored = stored.filter(
                        (row) => !(row.fileId === where.fileId && row.userId === where.userId)
                    );
                    return { count: before - stored.length };
                },
                create: async () => {
                    throw new Error("create must not be used for grants; use upsert");
                }
            }
        };

        fileAccessRepository.getPrisma = async () => mockPrisma;
    });

    afterEach(() => {
        fileAccessRepository.getPrisma = originalGetPrisma;
    });

    it("should create a grant for a new user/file pair", async () => {
        const expiresAt = new Date("2026-12-01T00:00:00.000Z");
        const { grant, created } = await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt
        });

        assert.strictEqual(created, true);
        assert.strictEqual(grant.fileId, "file-1");
        assert.strictEqual(grant.userId, "user-1");
        assert.strictEqual(grant.expiresAt.toISOString(), expiresAt.toISOString());
        assert.strictEqual(stored.length, 1);
        assert.strictEqual(createCalls, 1);
    });

    it("should update the existing grant instead of inserting a duplicate", async () => {
        const firstExpiry = new Date("2026-12-01T00:00:00.000Z");
        const secondExpiry = new Date("2027-01-15T00:00:00.000Z");

        const first = await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: firstExpiry
        });
        const second = await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: secondExpiry
        });

        assert.strictEqual(stored.length, 1);
        assert.strictEqual(first.created, true);
        assert.strictEqual(second.created, false);
        assert.strictEqual(first.grant.id, second.grant.id);
        assert.strictEqual(second.grant.expiresAt.toISOString(), secondExpiry.toISOString());
        assert.strictEqual(upsertCalls, 2);
    });

    it("should allow the same user to receive access to different files", async () => {
        await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });
        await fileAccessRepository.grantAccess({
            fileId: "file-2",
            userId: "user-1",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });

        assert.strictEqual(stored.length, 2);
    });

    it("should allow different users to receive access to the same file", async () => {
        await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });
        await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-2",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });

        assert.strictEqual(stored.length, 2);
    });

    it("should retry upsert when a concurrent unique constraint error occurs", async () => {
        let attempts = 0;
        mockPrisma.fileAccessGrant.upsert = async ({ where, update, create }) => {
            attempts += 1;
            const pair = where.userId_fileId;
            if (attempts === 1) {
                const error = new Error("Unique constraint failed");
                error.code = "P2002";
                throw error;
            }
            const created = {
                id: "grant-after-retry",
                userId: create.userId,
                fileId: create.fileId,
                expiresAt: update.expiresAt || create.expiresAt
            };
            stored = [created];
            return created;
        };

        const { grant } = await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });

        assert.strictEqual(attempts, 2);
        assert.strictEqual(grant.id, "grant-after-retry");
        assert.strictEqual(stored.length, 1);
    });

    it("should reject a second insert for the same user/file pair when the unique constraint fires", async () => {
        mockPrisma.fileAccessGrant.upsert = async () => {
            const error = new Error("Unique constraint failed on the fields: (`user_id`,`file_id`)");
            error.code = "P2002";
            throw error;
        };

        await assert.rejects(
            () => fileAccessRepository.grantAccess({
                fileId: "file-1",
                userId: "user-1",
                expiresAt: new Date("2026-12-01T00:00:00.000Z")
            }),
            (error) => error.code === "P2002"
        );
    });

    it("should revoke grants for a user/file pair", async () => {
        await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });
        await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-2",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });

        const result = await fileAccessRepository.revokeAccess("file-1", "user-1");
        assert.strictEqual(result.count, 1);
        assert.strictEqual(stored.length, 1);
        assert.strictEqual(stored[0].userId, "user-2");
    });

    it("should look up a grant by the composite unique key", async () => {
        await fileAccessRepository.grantAccess({
            fileId: "file-1",
            userId: "user-1",
            expiresAt: new Date("2026-12-01T00:00:00.000Z")
        });

        const found = await fileAccessRepository.findGrant("file-1", "user-1");
        assert.ok(found);
        assert.strictEqual(found.userId, "user-1");
        assert.equal(await fileAccessRepository.findGrant("file-1", "missing"), null);
    });
});

describe("FileAccessService grant uniqueness", () => {
    const { FileAccessService } = { FileAccessService: require("../../src/modules/file-access/file-access.service").constructor };

    it("should grant a new pair and update expiration on repeat without creating a second row", async () => {
        const grants = [];
        const repo = {
            grantAccess: async ({ fileId, userId, expiresAt }) => {
                const existing = grants.find((g) => g.fileId === fileId && g.userId === userId);
                if (existing) {
                    existing.expiresAt = expiresAt;
                    return { grant: existing, created: false };
                }
                const created = { id: `g-${grants.length + 1}`, fileId, userId, expiresAt };
                grants.push(created);
                return { grant: created, created: true };
            },
            revokeAccess: async (fileId, userId) => {
                const before = grants.length;
                const remaining = grants.filter((g) => !(g.fileId === fileId && g.userId === userId));
                grants.length = 0;
                grants.push(...remaining);
                return { count: before - grants.length };
            }
        };

        const service = new FileAccessService(
            repo,
            { findById: async (id) => ({ id, name: "File" }) },
            {
                findById: async (id) => ({
                    id,
                    role: "VIEWER",
                    isActive: true
                })
            },
            { logEvent: async () => null }
        );

        const first = await service.grantAccess({
            fileId: "file-1",
            userId: "viewer-1",
            expiresInDays: 7,
            adminUser: { id: "admin-1" }
        });
        const firstExpiryMs = first.grant.expiresAt.getTime();
        const second = await service.grantAccess({
            fileId: "file-1",
            userId: "viewer-1",
            expiresInDays: 30,
            adminUser: { id: "admin-1" }
        });

        assert.strictEqual(grants.length, 1);
        assert.strictEqual(first.created, true);
        assert.strictEqual(second.created, false);
        assert.strictEqual(first.grant.id, second.grant.id);
        assert.ok(second.grant.expiresAt.getTime() >= firstExpiryMs);

        const revoked = await service.revokeAccess({
            fileId: "file-1",
            userId: "viewer-1",
            adminUser: { id: "admin-1" }
        });
        assert.strictEqual(revoked.revoked, true);
        assert.strictEqual(grants.length, 0);
    });
});
