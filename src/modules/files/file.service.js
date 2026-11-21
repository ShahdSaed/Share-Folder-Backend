const fileRepository = require("./file.repository");
const auditLogService = require("../audit-logs/audit-log.service");
const { hashPassword, verifyPassword } = require("../../utils/password");
const { signFileUnlockToken, verifyFileUnlockToken, FILE_UNLOCK_EXPIRATION_SECONDS } = require("../../utils/jwt");
const { removeStoredFile } = require("../../utils/file-storage");
const { persistUploadedFile, openFileStream, deleteStoredFile } = require("../../utils/object-storage");
const { NotFoundError, ForbiddenError, UnauthorizedError } = require("../../utils/errors");

class FileService {
    constructor(fileRepo = fileRepository, auditService = auditLogService) {
        this.fileRepository = fileRepo;
        this.auditLogService = auditService;
    }

    /**
     * Upload and encrypt file with password protection (ADMIN only).
     */
    async uploadFile({ file, name, password, adminUser, ipAddress, userAgent }) {
        let passwordHash;
        try {
            passwordHash = await hashPassword(password);
        } catch (err) {
            removeStoredFile(file.filename);
            throw err;
        }

        // Move the validated upload to persistent storage (R2 in production) before recording it
        try {
            await persistUploadedFile({
                storageKey: file.filename,
                mimeType: file.mimetype,
                size: file.size
            });
        } catch (storageError) {
            removeStoredFile(file.filename);
            throw storageError;
        }

        let newFile;
        try {
            newFile = await this.fileRepository.create({
                name: name || file.originalname,
                storageKey: file.filename,
                mimeType: file.mimetype,
                size: file.size,
                passwordHash,
                uploadedBy: adminUser.id
            });
        } catch (dbError) {
            // Clean up the stored file (disk or R2) if database insert fails
            await deleteStoredFile(file.filename);
            throw dbError;
        }

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "FILE_UPLOADED",
            targetType: "FILE",
            targetId: newFile.id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return newFile;
    }

    /**
     * List files based on user role.
     * ADMIN: Sees all files.
     * VIEWER: Sees ONLY files with active access grants assigned to them.
     */
    async getFiles({ user, page = 1, limit = 20, skip = 0, search, mimeType }) {
        let result;

        if (user.role === "ADMIN") {
            result = await this.fileRepository.findPaginated({
                skip,
                limit,
                search,
                mimeType
            });
        } else {
            result = await this.fileRepository.findAssignedToUserPaginated({
                userId: user.id,
                skip,
                limit,
                search,
                mimeType
            });
        }

        const totalPages = Math.ceil(result.total / limit) || 1;

        return {
            files: result.files,
            pagination: {
                page,
                limit,
                total: result.total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        };
    }

    /**
     * Get file metadata with role-based access check.
     */
    async getFileById(id, user) {
        const file = await this.fileRepository.findById(id);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        if (user.role !== "ADMIN") {
            const hasAccess = await this.fileRepository.hasActiveGrant(id, user.id);
            if (!hasAccess) {
                throw new NotFoundError("File not found");
            }
        }

        return file;
    }

    /**
     * Update file metadata (ADMIN only).
     */
    async updateFile(id, updates, adminUser, ipAddress, userAgent) {
        const existing = await this.fileRepository.findById(id);
        if (!existing) {
            throw new NotFoundError("File not found");
        }

        const updated = await this.fileRepository.update(id, updates);

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "FILE_METADATA_UPDATED",
            targetType: "FILE",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return updated;
    }

    /**
     * Delete file from database and storage (ADMIN only).
     */
    async deleteFile(id, adminUser, ipAddress, userAgent) {
        const file = await this.fileRepository.findByIdInternal(id);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        await this.fileRepository.delete(id);
        await deleteStoredFile(file.storageKey);

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "FILE_DELETED",
            targetType: "FILE",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return { id, name: file.name };
    }

    /**
     * Set or change file protection password (ADMIN only).
     */
    async updateFilePassword(id, newPassword, adminUser, ipAddress, userAgent) {
        const file = await this.fileRepository.findById(id);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        const passwordHash = await hashPassword(newPassword);
        await this.fileRepository.updatePassword(id, passwordHash);

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "FILE_PASSWORD_CHANGED",
            targetType: "FILE",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return { id, message: "File password updated successfully" };
    }

    /**
     * Verify a file password and generate a short-lived unlock grant token.
     */
    async verifyFilePassword(id, password, user, ipAddress, userAgent) {
        const file = await this.fileRepository.findByIdInternal(id);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        // VIEWER must have active grant to even attempt password unlock
        if (user.role !== "ADMIN") {
            const hasGrant = await this.fileRepository.hasActiveGrant(id, user.id);
            if (!hasGrant) {
                await this.auditLogService.logEvent({
                    userId: user.id,
                    action: "FILE_PASSWORD_ATTEMPT_DENIED",
                    targetType: "FILE",
                    targetId: id,
                    ipAddress,
                    userAgent,
                    result: "Failed"
                });
                throw new ForbiddenError("You do not have access permission to this file");
            }
        }

        // Verify password with Argon2id
        const isMatch = await verifyPassword(file.passwordHash, password);

        if (!isMatch) {
            await this.auditLogService.logEvent({
                userId: user.id,
                action: "FILE_PASSWORD_FAILED",
                targetType: "FILE",
                targetId: id,
                ipAddress,
                userAgent,
                result: "Failed"
            });
            throw new UnauthorizedError("Incorrect file password");
        }

        // Successful password verification
        await this.auditLogService.logEvent({
            userId: user.id,
            action: "FILE_PASSWORD_VERIFIED",
            targetType: "FILE",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        // Generate short-lived cryptographic unlock grant bound to user and file
        const unlockToken = signFileUnlockToken({
            userId: user.id,
            fileId: file.id
        });

        return {
            unlocked: true,
            unlockToken,
            expiresIn: `${FILE_UNLOCK_EXPIRATION_SECONDS / 60}m`, // kept for backward compatibility
            expiresInSeconds: FILE_UNLOCK_EXPIRATION_SECONDS
        };
    }

    /**
     * Get content file path for streaming with security checks.
     */
    async getFileContent(id, user, unlockToken, ipAddress, userAgent) {
        const file = await this.fileRepository.findByIdInternal(id);
        if (!file) {
            throw new NotFoundError("File not found");
        }

        // VIEWER authorization enforcement
        if (user.role !== "ADMIN") {
            const hasGrant = await this.fileRepository.hasActiveGrant(id, user.id);
            if (!hasGrant) {
                throw new ForbiddenError("Access forbidden: file is not assigned to your account");
            }

            // Enforce valid unlock token
            verifyFileUnlockToken(unlockToken, {
                userId: user.id,
                fileId: id
            });
        }

        // Open the stored object (local disk or R2); throws NotFoundError if missing
        const stream = await openFileStream(file.storageKey);

        await this.auditLogService.logEvent({
            userId: user.id,
            action: "FILE_ACCESSED",
            targetType: "FILE",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return {
            stream,
            name: file.name,
            mimeType: file.mimeType,
            size: file.size
        };
    }
}

module.exports = new FileService();
