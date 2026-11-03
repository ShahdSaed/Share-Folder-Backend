const express = require("express");
const fileController = require("./file.controller");
const fileAccessRoutes = require("../file-access/file-access.routes");
const { authenticate } = require("../../middlewares/auth.middleware");
const { authorizeRoles } = require("../../middlewares/role.middleware");
const { handleFileUpload } = require("../../middlewares/upload.middleware");
const { filePasswordRateLimiter } = require("../../middlewares/rate-limit.middleware");

const router = express.Router();

// All file endpoints require user authentication
router.use(authenticate);

// 1. File Listing & Metadata Retrieval (Available to both ADMIN and VIEWER based on grants)
router.get("/", fileController.getFiles);
router.get("/:id", fileController.getFileById);

// 2. File Password Verification & Secure Content Streaming
router.post("/:id/verify-password", filePasswordRateLimiter, fileController.verifyFilePassword);
router.get("/:id/content", fileController.getFileContent);

// 3. File Access Assignment Routes (ADMIN only)
router.use("/:id/access", fileAccessRoutes);

// 4. Administrative Operations (ADMIN only)
router.post(
    "/",
    authorizeRoles("ADMIN"),
    handleFileUpload,
    fileController.uploadFile
);
router.patch("/:id", authorizeRoles("ADMIN"), fileController.updateFile);
router.delete("/:id", authorizeRoles("ADMIN"), fileController.deleteFile);
router.put("/:id/password", authorizeRoles("ADMIN"), fileController.updateFilePassword);

module.exports = router;
