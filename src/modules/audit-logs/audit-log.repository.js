const prismaPromise = require("../../config/prisma");

class AuditLogRepository {
    async getPrisma() {
        return await prismaPromise;
    }

    /**
     * Create an audit log record.
     * @param {object} logData
     * @returns {Promise<object>}
     */
    async create(logData) {
        const prisma = await this.getPrisma();
        return await prisma.auditLog.create({
            data: {
                userId: logData.userId || null,
                action: logData.action,
                targetType: logData.targetType || null,
                targetId: logData.targetId || null,
                ipAddress: logData.ipAddress || null,
                userAgent: logData.userAgent || null,
                result: logData.result
            }
        });
    }

    /**
     * Retrieve paginated audit logs with optional filters.
     * @param {object} params
     * @returns {Promise<{ logs: Array, total: number }>}
     */
    async findPaginated({ skip = 0, limit = 20, action, result, userId }) {
        const prisma = await this.getPrisma();

        const where = {};
        if (action) where.action = action;
        if (result) where.result = result;
        if (userId) where.userId = userId;

        const [logs, total] = await Promise.all([
            prisma.auditLog.findMany({
                where,
                skip,
                take: limit,
                orderBy: { createdAt: "desc" },
                include: {
                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            role: true
                        }
                    }
                }
            }),
            prisma.auditLog.count({ where })
        ]);

        return { logs, total };
    }
}

module.exports = new AuditLogRepository();
