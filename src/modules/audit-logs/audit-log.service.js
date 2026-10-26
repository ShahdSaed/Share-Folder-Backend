const auditLogRepository = require("./audit-log.repository");

class AuditLogService {
    constructor(repository = auditLogRepository) {
        this.repository = repository;
    }

    /**
     * Log a security event safely without breaking critical operations if audit persistence fails.
     * @param {object} eventData
     */
    async logEvent({ userId = null, action, targetType = null, targetId = null, ipAddress = null, userAgent = null, result }) {
        try {
            return await this.repository.create({
                userId,
                action,
                targetType,
                targetId,
                ipAddress,
                userAgent,
                result
            });
        } catch (error) {
            // Diagnostic logging only - do not expose secrets or break user flow
            console.error("[AuditLogService] Warning: Failed to persist audit log:", error.message);
            return null;
        }
    }

    /**
     * Get paginated audit logs for administrators.
     * @param {object} params 
     */
    async getAuditLogs({ page = 1, limit = 20, skip = 0, action, result, userId }) {
        const { logs, total } = await this.repository.findPaginated({
            skip,
            limit,
            action,
            result,
            userId
        });

        const totalPages = Math.ceil(total / limit) || 1;

        return {
            logs,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        };
    }
}

module.exports = new AuditLogService();
