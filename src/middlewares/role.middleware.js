const { ForbiddenError, UnauthorizedError } = require("../utils/errors");
const auditLogService = require("../modules/audit-logs/audit-log.service");

/**
 * Middleware factory to authorize access based on user role.
 * @param  {...string} allowedRoles 
 * @returns {import("express").RequestHandler}
 */
function authorizeRoles(...allowedRoles) {
    return async (req, res, next) => {
        try {
            if (!req.user) {
                throw new UnauthorizedError("Authentication required before authorization");
            }

            if (!allowedRoles.includes(req.user.role)) {
                // Audit the forbidden attempt
                await auditLogService.logEvent({
                    userId: req.user.id,
                    action: "FORBIDDEN_ACCESS_ATTEMPT",
                    targetType: "ROUTE",
                    targetId: req.originalUrl,
                    ipAddress: req.ip || req.socket?.remoteAddress,
                    userAgent: req.headers["user-agent"],
                    result: "Failed"
                });

                throw new ForbiddenError(
                    `Access forbidden: required role [${allowedRoles.join(", ")}], your role is [${req.user.role}]`
                );
            }

            next();
        } catch (error) {
            next(error);
        }
    };
}

module.exports = {
    authorizeRoles
};
