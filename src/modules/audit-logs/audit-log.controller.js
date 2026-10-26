const auditLogService = require("./audit-log.service");
const { validatePagination } = require("../../utils/validator");

class AuditLogController {
    constructor(service = auditLogService) {
        this.auditLogService = service;
    }

    /**
     * List paginated audit logs for administrators.
     * GET /api/admin/audit-logs
     */
    listAuditLogs = async (req, res, next) => {
        try {
            const { page, limit, skip } = validatePagination(req.query);

            const { action, result, userId } = req.query;

            const data = await this.auditLogService.getAuditLogs({
                page,
                limit,
                skip,
                action: action ? String(action).trim() : undefined,
                result: result ? String(result).trim() : undefined,
                userId: userId ? String(userId).trim() : undefined
            });

            return res.status(200).json({
                status: "success",
                data
            });
        } catch (error) {
            next(error);
        }
    };
}

module.exports = new AuditLogController();
