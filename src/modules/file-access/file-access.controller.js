const fileAccessService = require("./file-access.service");
const { BadRequestError } = require("../../utils/errors");

class FileAccessController {
    constructor(service = fileAccessService) {
        this.service = service;
    }

    /**
     * Grant access to a VIEWER (ADMIN only).
     * POST /api/v1/files/:id/access
     */
    grantAccess = async (req, res, next) => {
        try {
            const fileId = req.params.id;
            const { userId, expiresInDays } = req.body || {};

            if (!userId || typeof userId !== "string") {
                throw new BadRequestError("userId is required in request body");
            }

            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const grant = await this.service.grantAccess({
                fileId,
                userId,
                expiresInDays: expiresInDays ? Number(expiresInDays) : 30,
                adminUser: req.user,
                ipAddress,
                userAgent
            });

            return res.status(201).json({
                status: "success",
                message: "Access granted successfully",
                data: { grant }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * List access grants for a file (ADMIN only).
     * GET /api/v1/files/:id/access
     */
    getGrants = async (req, res, next) => {
        try {
            const fileId = req.params.id;
            const grants = await this.service.getGrantsByFileId(fileId);

            return res.status(200).json({
                status: "success",
                data: { grants }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Revoke access grant for a user (ADMIN only).
     * DELETE /api/v1/files/:id/access/:userId
     */
    revokeAccess = async (req, res, next) => {
        try {
            const fileId = req.params.id;
            const userId = req.params.userId;

            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const result = await this.service.revokeAccess({
                fileId,
                userId,
                adminUser: req.user,
                ipAddress,
                userAgent
            });

            return res.status(200).json({
                status: "success",
                message: "Access grant revoked successfully",
                data: result
            });
        } catch (error) {
            next(error);
        }
    };
}

module.exports = new FileAccessController();
