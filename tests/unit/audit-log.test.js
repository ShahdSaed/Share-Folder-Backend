const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const AuditLogController = require("../../src/modules/audit-logs/audit-log.controller").constructor;
const AuditLogService = require("../../src/modules/audit-logs/audit-log.service").constructor;
const AuditLogRepository = require("../../src/modules/audit-logs/audit-log.repository").constructor;
const { BadRequestError } = require("../../src/utils/errors");

describe("Audit Logs Module - Unit Tests", () => {
    describe("AuditLogController Validation & Behavior", () => {
        it("should accept valid pagination and filter queries", async () => {
            let capturedParams = null;
            const mockService = {
                getAuditLogs: async (params) => {
                    capturedParams = params;
                    return {
                        logs: [],
                        pagination: { page: 2, limit: 10, total: 0, totalPages: 1, hasNext: false, hasPrev: true }
                    };
                }
            };

            const controller = new AuditLogController(mockService);
            const req = {
                query: {
                    page: "2",
                    limit: "10",
                    action: "LOGIN_SUCCESS",
                    result: "SUCCESS",
                    userId: "usr-12345",
                    targetType: "FILE",
                    fromDate: "2026-01-01T00:00:00.000Z",
                    toDate: "2026-01-02T00:00:00.000Z"
                }
            };

            let jsonOutput = null;
            let statusCode = null;
            const res = {
                status: (code) => {
                    statusCode = code;
                    return {
                        json: (data) => {
                            jsonOutput = data;
                        }
                    };
                }
            };

            await controller.listAuditLogs(req, res, (err) => {
                if (err) throw err;
            });

            assert.strictEqual(statusCode, 200);
            assert.strictEqual(jsonOutput.status, "success");
            assert.strictEqual(capturedParams.page, 2);
            assert.strictEqual(capturedParams.limit, 10);
            assert.strictEqual(capturedParams.action, "LOGIN_SUCCESS");
            assert.strictEqual(capturedParams.result, "SUCCESS");
            assert.strictEqual(capturedParams.userId, "usr-12345");
            assert.strictEqual(capturedParams.targetType, "FILE");
            assert.ok(capturedParams.fromDate instanceof Date);
            assert.ok(capturedParams.toDate instanceof Date);
        });

        it("should reject non-string filter parameters with BadRequestError", async () => {
            const controller = new AuditLogController({});
            const req = { query: { action: ["LOGIN", "LOGOUT"] } };
            let capturedError = null;

            await controller.listAuditLogs(req, {}, (err) => {
                capturedError = err;
            });

            assert.ok(capturedError instanceof BadRequestError);
            assert.match(capturedError.message, /action must be a string/);
        });

        it("should reject strings exceeding maximum length with BadRequestError", async () => {
            const controller = new AuditLogController({});
            const req = { query: { result: "A".repeat(51) } };
            let capturedError = null;

            await controller.listAuditLogs(req, {}, (err) => {
                capturedError = err;
            });

            assert.ok(capturedError instanceof BadRequestError);
            assert.match(capturedError.message, /result must not exceed 50 characters/);
        });

        it("should reject invalid date strings with BadRequestError", async () => {
            const controller = new AuditLogController({});
            const req = { query: { fromDate: "not-a-valid-date" } };
            let capturedError = null;

            await controller.listAuditLogs(req, {}, (err) => {
                capturedError = err;
            });

            assert.ok(capturedError instanceof BadRequestError);
            assert.match(capturedError.message, /fromDate must be a valid ISO 8601 date/);
        });

        it("should reject when fromDate is later than toDate", async () => {
            const controller = new AuditLogController({});
            const req = {
                query: {
                    fromDate: "2026-02-01T00:00:00.000Z",
                    toDate: "2026-01-01T00:00:00.000Z"
                }
            };
            let capturedError = null;

            await controller.listAuditLogs(req, {}, (err) => {
                capturedError = err;
            });

            assert.ok(capturedError instanceof BadRequestError);
            assert.match(capturedError.message, /fromDate must be earlier than or equal to toDate/);
        });
    });

    describe("AuditLogService", () => {
        it("should safely handle repository failure during logEvent without throwing", async () => {
            const failingRepo = {
                create: async () => {
                    throw new Error("Database disk full or connection dropped");
                }
            };
            const service = new AuditLogService(failingRepo);

            // Must NOT throw
            const result = await service.logEvent({
                action: "SECURITY_ALERT",
                result: "FAILURE"
            });

            assert.strictEqual(result, null);
        });

        it("should successfully persist event via logEvent", async () => {
            let created = null;
            const successRepo = {
                create: async (data) => {
                    created = data;
                    return { id: "log-1", ...data };
                }
            };
            const service = new AuditLogService(successRepo);

            const result = await service.logEvent({
                userId: "user-1",
                action: "PASSWORD_CHANGED",
                result: "SUCCESS"
            });

            assert.strictEqual(result.id, "log-1");
            assert.strictEqual(created.action, "PASSWORD_CHANGED");
            assert.strictEqual(created.result, "SUCCESS");
        });

        it("should calculate pagination metadata correctly in getAuditLogs", async () => {
            const mockRepo = {
                findPaginated: async ({ skip, limit }) => ({
                    logs: [{ id: "log-1" }, { id: "log-2" }],
                    total: 25
                })
            };
            const service = new AuditLogService(mockRepo);

            const result = await service.getAuditLogs({ page: 2, limit: 10, skip: 10 });
            assert.strictEqual(result.logs.length, 2);
            assert.strictEqual(result.pagination.page, 2);
            assert.strictEqual(result.pagination.limit, 10);
            assert.strictEqual(result.pagination.total, 25);
            assert.strictEqual(result.pagination.totalPages, 3);
            assert.strictEqual(result.pagination.hasNext, true);
            assert.strictEqual(result.pagination.hasPrev, true);
        });
    });

    describe("AuditLogRepository Query Building", () => {
        it("should construct proper Prisma query filters including date range", async () => {
            let capturedQuery = null;
            const mockPrisma = {
                auditLog: {
                    findMany: async (query) => {
                        capturedQuery = query;
                        return [];
                    },
                    count: async (query) => 0
                }
            };

            const repo = new AuditLogRepository();
            repo.getPrisma = async () => mockPrisma;

            const fromDate = new Date("2026-01-01T00:00:00.000Z");
            const toDate = new Date("2026-01-31T23:59:59.999Z");

            await repo.findPaginated({
                skip: 0,
                limit: 15,
                action: "FILE_UPLOAD",
                result: "SUCCESS",
                userId: "user-42",
                targetType: "FILE",
                fromDate,
                toDate
            });

            assert.strictEqual(capturedQuery.where.action, "FILE_UPLOAD");
            assert.strictEqual(capturedQuery.where.result, "SUCCESS");
            assert.strictEqual(capturedQuery.where.userId, "user-42");
            assert.strictEqual(capturedQuery.where.targetType, "FILE");
            assert.strictEqual(capturedQuery.where.createdAt.gte, fromDate);
            assert.strictEqual(capturedQuery.where.createdAt.lte, toDate);
            assert.strictEqual(capturedQuery.skip, 0);
            assert.strictEqual(capturedQuery.take, 15);
            // Verify safe user projection (no passwordHash)
            assert.deepStrictEqual(capturedQuery.include.user.select, {
                id: true,
                name: true,
                username: true,
                role: true
            });
        });
    });
});

