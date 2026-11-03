const fileAccessService = require("./file-access.service");
const { BadRequestError } = require("../../utils/errors");
const { validateExpiresInDays, validateGrantStatus } = require("./file-access.validation");

class FileAccessController {
    constructor(service = fileAccessService) {
        this.service = service;
    }

    grantAccess = async (req, res, next) => {
        try {
            const fileId = req.params.id;
            const { userId, expiresInDays } = req.body || {};

            if (!userId || typeof userId !== "string") {
                throw new BadRequestError("userId is required in request body");
            }

            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const { grant, created } = await this.service.grantAccess({
                fileId,
                userId,
                expiresInDays: validateExpiresInDays(expiresInDays),
                adminUser: req.user,
                ipAddress,
                userAgent
            });

            return res.status(created ? 201 : 200).json({
                status: "success",
                message: created ? "Access granted successfully" : "Access grant updated successfully",
                data: { grant, created }
            });
        } catch (error) {
            next(error);
        }
    };

    getGrants = async (req, res, next) => {
        try {
            const fileId = req.params.id;
            const status = validateGrantStatus(req.query.status);
            const grants = await this.service.getGrantsByFileId(fileId, { status });

            return res.status(200).json({
                status: "success",
                data: { grants }
            });
        } catch (error) {
            next(error);
        }
    };

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
