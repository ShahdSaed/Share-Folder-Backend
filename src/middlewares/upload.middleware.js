const { uploadMiddleware, removeStoredFile, MAX_FILE_SIZE_BYTES } = require("../utils/file-storage");
const { BadRequestError } = require("../utils/errors");

/**
 * Middleware factory to safely handle single file uploads with Multer error handling and cleanup.
 * @param {string} fieldName - Form field name (default: "file")
 * @returns {import("express").RequestHandler}
 */
function uploadSingle(fieldName = "file") {
    return (req, res, next) => {
        uploadMiddleware.single(fieldName)(req, res, (err) => {
            if (err) {
                // Ensure partial or orphaned files are cleaned up from storage
                if (req.file && req.file.filename) {
                    removeStoredFile(req.file.filename);
                }

                // Map Multer-specific errors to application BadRequestError
                if (err.name === "MulterError") {
                    if (err.code === "LIMIT_FILE_SIZE") {
                        const sizeMb = Math.round(MAX_FILE_SIZE_BYTES / (1024 * 1024));
                        return next(
                            new BadRequestError(`File size exceeds the allowed limit of ${sizeMb} MB`)
                        );
                    }
                    return next(new BadRequestError(err.message));
                }

                return next(err);
            }
            next();
        });
    };
}

// Default single file upload middleware for the "file" field
const handleFileUpload = uploadSingle("file");

module.exports = {
    handleFileUpload,
    uploadSingle
};
