const { describe, it } = require("node:test");
const assert = require("node:assert");
const { UserService } = require("../../src/modules/users/user.service").constructor;
const { ConflictError, BadRequestError, NotFoundError } = require("../../src/utils/errors");

describe("UserService (Unit Tests with Mocks)", () => {
    function createMockRepo(users = []) {
        const list = [...users];
        return {
            findByEmailWithPassword: async (email) => list.find((u) => u.email === email) || null,
            findById: async (id) => list.find((u) => u.id === id) || null,
            findPaginated: async () => ({ users: list, total: list.length }),
            create: async (data) => {
                const u = { id: "usr-" + (list.length + 1), ...data, createdAt: new Date() };
                delete u.passwordHash;
                list.push(u);
                return u;
            },
            update: async (id, data) => {
                const idx = list.findIndex((u) => u.id === id);
                if (idx === -1) return null;
                list[idx] = { ...list[idx], ...data };
                return list[idx];
            },
            updateStatus: async (id, isActive) => {
                const idx = list.findIndex((u) => u.id === id);
                if (idx === -1) return null;
                list[idx].isActive = isActive;
                return list[idx];
            },
            updatePassword: async (id) => list.find((u) => u.id === id) || null
        };
    }

    const mockAuditService = {
        logEvent: async () => ({ id: "audit-1" })
    };

    const adminUser = { id: "admin-1", email: "admin@company.com", role: "ADMIN" };

    it("should successfully create a new user and never return password hash", async () => {
        const repo = createMockRepo();
        const service = new (require("../../src/modules/users/user.service").constructor)(repo, mockAuditService);

        const newUser = await service.createUser({
            name: "Jane Viewer",
            email: "jane@company.com",
            password: "SecurePassword123!",
            role: "VIEWER",
            adminUser,
            ipAddress: "127.0.0.1",
            userAgent: "TestRunner"
        });

        assert.strictEqual(newUser.name, "Jane Viewer");
        assert.strictEqual(newUser.email, "jane@company.com");
        assert.strictEqual(newUser.role, "VIEWER");
        assert.strictEqual(newUser.passwordHash, undefined, "Must NEVER return passwordHash");
    });

    it("should reject duplicate email with ConflictError", async () => {
        const repo = createMockRepo([{ id: "u-1", email: "existing@company.com" }]);
        const service = new (require("../../src/modules/users/user.service").constructor)(repo, mockAuditService);

        await assert.rejects(
            async () => {
                await service.createUser({
                    name: "Existing",
                    email: "existing@company.com",
                    password: "SecurePassword123!",
                    role: "VIEWER",
                    adminUser
                });
            },
            ConflictError
        );
    });

    it("should prevent an administrator from deactivating their own account", async () => {
        const repo = createMockRepo([adminUser]);
        const service = new (require("../../src/modules/users/user.service").constructor)(repo, mockAuditService);

        await assert.rejects(
            async () => {
                await service.updateUserStatus("admin-1", false, adminUser);
            },
            BadRequestError
        );
    });

    it("should prevent an administrator from removing their own ADMIN role", async () => {
        const repo = createMockRepo([adminUser]);
        const service = new (require("../../src/modules/users/user.service").constructor)(repo, mockAuditService);

        await assert.rejects(
            async () => {
                await service.updateUser("admin-1", { role: "VIEWER" }, adminUser);
            },
            BadRequestError
        );
    });
});
