const path = require("path");
const fs = require("fs");
const contentDisposition = require("content-disposition");
const fileService = require("./file.service");
const {
    validateUploadInput,
    validateUpdateFileInput,
    validateFilePasswordInput
} = require("./file.validation");
const { validatePagination } = require("../../utils/validator");
const { validateFileContentSignature, removeStoredFile } = require("../../utils/file-storage");
const { BadRequestError } = require("../../utils/errors");

class FileController {
    constructor(service = fileService) {
        this.fileService = service;
    }

    /**
     * Upload a new file (ADMIN only).
     * POST /api/v1/files
     */
    uploadFile = async (req, res, next) => {
        try {
            if (!req.file) {
                throw new BadRequestError("File is required in multipart form data (field name: 'file')");
            }

            // 1. Content signature validation on the stored file
            const ext = path.extname(req.file.originalname || "").toLowerCase();
            const isValidSignature = await validateFileContentSignature(req.file.path, ext);
            if (!isValidSignature) {
                throw new BadRequestError("File content does not match its declared type");
            }

            // 2. Validate display name and protection password
            const { name, password } = validateUploadInput(req.file, req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const file = await this.fileService.uploadFile({
                file: req.file,
                name,
                password,
                adminUser: req.user,
                ipAddress,
                userAgent
            });

            return res.status(201).json({
                status: "success",
                message: "File uploaded and secured successfully",
                data: { file }
            });
        } catch (error) {
            // Clean up stored file if validation, signature check, or service fails
            if (req.file && req.file.filename) {
                removeStoredFile(req.file.filename);
            }
            next(error);
        }
    };

    /**
     * List files.
     * GET /api/v1/files
     */
    getFiles = async (req, res, next) => {
        try {
            const pagination = validatePagination(req.query);
            const { search, mimeType } = req.query;

            const result = await this.fileService.getFiles({
                user: req.user,
                ...pagination,
                search: search ? String(search).trim() : undefined,
                mimeType: mimeType ? String(mimeType).trim() : undefined
            });

            return res.status(200).json({
                status: "success",
                data: result
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Get file metadata.
     * GET /api/v1/files/:id
     */
    getFileById = async (req, res, next) => {
        try {
            const file = await this.fileService.getFileById(req.params.id, req.user);

            return res.status(200).json({
                status: "success",
                data: { file }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Update file metadata (ADMIN only).
     * PATCH /api/v1/files/:id
     */
    updateFile = async (req, res, next) => {
        try {
            const updates = validateUpdateFileInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const file = await this.fileService.updateFile(
                req.params.id,
                updates,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: "File metadata updated successfully",
                data: { file }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Delete a file (ADMIN only).
     * DELETE /api/v1/files/:id
     */
    deleteFile = async (req, res, next) => {
        try {
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const result = await this.fileService.deleteFile(
                req.params.id,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: "File deleted successfully",
                data: result
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Set/Change file protection password (ADMIN only).
     * PUT /api/v1/files/:id/password
     */
    updateFilePassword = async (req, res, next) => {
        try {
            const { password } = validateFilePasswordInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const result = await this.fileService.updateFilePassword(
                req.params.id,
                password,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: "File password changed successfully",
                data: result
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Verify file password to obtain short-lived unlock grant.
     * POST /api/v1/files/:id/verify-password
     */
    verifyFilePassword = async (req, res, next) => {
        try {
            const { password } = validateFilePasswordInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const result = await this.fileService.verifyFilePassword(
                req.params.id,
                password,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: "Password verified. File unlocked for viewing.",
                data: result
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * View / download secure file content.
     * GET /api/v1/files/:id/content
     */
    getFileContent = async (req, res, next) => {
        try {
            // Unlock token can be sent via query param or header
            const unlockToken =
                req.query.token ||
                req.headers["x-file-unlock-token"] ||
                req.headers["x-unlock-token"] ||
                null;

            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const { filePath, name, mimeType, size } = await this.fileService.getFileContent(
                req.params.id,
                req.user,
                unlockToken,
                ipAddress,
                userAgent
            );

            const isInline = req.query.inline === "true" || req.query.disposition === "inline";
            const disposition = isInline ? "inline" : "attachment";

            res.setHeader("Content-Type", mimeType || "application/octet-stream");
            res.setHeader("Content-Length", size);
            const dispositionHeader = typeof contentDisposition.create === "function"
                ? contentDisposition.create(name, { type: disposition })
                : contentDisposition(name, { type: disposition });
            res.setHeader("Content-Disposition", dispositionHeader);

            // Stream private file
            const fileStream = fs.createReadStream(filePath);
            fileStream.on("error", (streamErr) => {
                next(streamErr);
            });
            fileStream.pipe(res);
        } catch (error) {
            next(error);
        }
    };
}

module.exports = new FileController();
