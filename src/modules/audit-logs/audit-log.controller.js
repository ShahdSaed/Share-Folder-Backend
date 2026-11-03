const auditLogService = require("./audit-log.service");
const { validatePagination } = require("../../utils/validator");
const { BadRequestError } = require("../../utils/errors");

function optionalString(value, fieldName, maxLength = 100) {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }
    if (typeof value !== "string") {
        throw new BadRequestError(`${fieldName} must be a string`);
    }
    const trimmed = value.trim();
    if (trimmed.length === 0) {
        return undefined;
    }
    if (trimmed.length > maxLength) {
        throw new BadRequestError(`${fieldName} must not exceed ${maxLength} characters`);
    }
    return trimmed;
}

function optionalDate(value, fieldName) {
    if (value === undefined || value === null || value === "") {
        return undefined;
    }
    if (typeof value !== "string") {
        throw new BadRequestError(`${fieldName} must be a valid ISO 8601 date string`);
    }
    const parsed = new Date(value.trim());
    if (Number.isNaN(parsed.getTime())) {
        throw new BadRequestError(`${fieldName} must be a valid ISO 8601 date`);
    }
    return parsed;
}

class AuditLogController {
    constructor(service = auditLogService) {
        this.auditLogService = service;
    }

    listAuditLogs = async (req, res, next) => {
        try {
            const { page, limit, skip } = validatePagination(req.query);
            const fromDate = optionalDate(req.query.fromDate, "fromDate");
            const toDate = optionalDate(req.query.toDate, "toDate");

            if (fromDate && toDate && fromDate > toDate) {
                throw new BadRequestError("fromDate must be earlier than or equal to toDate");
            }

            const data = await this.auditLogService.getAuditLogs({
                page,
                limit,
                skip,
                action: optionalString(req.query.action, "action", 100),
                result: optionalString(req.query.result, "result", 50),
                userId: optionalString(req.query.userId, "userId", 36),
                targetType: optionalString(req.query.targetType, "targetType", 50),
                fromDate,
                toDate
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
