const fileAccessRepository = require("./file-access.repository");
const fileRepository = require("../files/file.repository");
const userRepository = require("../users/user.repository");
const auditLogService = require("../audit-logs/audit-log.service");
const { NotFoundError, BadRequestError } = require("../../utils/errors");

class FileAccessService {
    constructor(
        accessRepo = fileAccessRepository,
        fileRepo = fileRepository,
        userRepo = userRepository,
        auditService = auditLogService
    ) {
        this.accessRepository = accessRepo;
        this.fileRepository = fileRepo;
        this.userRepository = userRepo;
        this.auditLogService = auditService;
    }

    /**
     * Grant a VIEWER access to a specific file (ADMIN only).
     */
    async grantAccess({ fileId, userId, expiresInDays = 30, adminUser, ipAddress, userAgent }) {
        // 1. Verify file exists
        const file = await this.fileRepository.findById(fileId);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        // 2. Verify target user exists
        const targetUser = await this.userRepository.findById(userId);
        if (!targetUser) {
            throw new NotFoundError("Target user not found");
        }

        // 3. Ensure target user is a VIEWER
        if (targetUser.role !== "VIEWER") {
            throw new BadRequestError("Access grants can only be assigned to VIEWER accounts (ADMIN accounts already have full access)");
        }

        if (!targetUser.isActive) {
            throw new BadRequestError("Cannot grant file access to a deactivated user account");
        }

        // 4. Calculate expiration date
        const days = Number(expiresInDays) || 30;
        const expiresAt = new Date(Date.now() + days * 24 * 60 * 60 * 1000);

        // 5. Persist access grant
        const grant = await this.accessRepository.grantAccess({
            fileId,
            userId,
            expiresAt
        });

        // 6. Security audit logging
        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "FILE_ACCESS_GRANTED",
            targetType: "FILE_ACCESS",
            targetId: `${fileId}:${userId}`,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return grant;
    }

    /**
     * Retrieve all active access grants for a file (ADMIN only).
     */
    async getGrantsByFileId(fileId) {
        const file = await this.fileRepository.findById(fileId);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        return await this.accessRepository.findGrantsByFileId(fileId);
    }

    /**
     * Revoke a user's access grant to a file (ADMIN only).
     */
    async revokeAccess({ fileId, userId, adminUser, ipAddress, userAgent }) {
        const file = await this.fileRepository.findById(fileId);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        const deleteResult = await this.accessRepository.revokeAccess(fileId, userId);

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "FILE_ACCESS_REVOKED",
            targetType: "FILE_ACCESS",
            targetId: `${fileId}:${userId}`,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return {
            fileId,
            userId,
            revoked: deleteResult.count > 0
        };
    }
}

module.exports = new FileAccessService();
