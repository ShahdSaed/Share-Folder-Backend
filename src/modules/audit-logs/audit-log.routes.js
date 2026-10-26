const express = require("express");
const auditLogController = require("./audit-log.controller");
const { authenticate } = require("../../middlewares/auth.middleware");
const { authorizeRoles } = require("../../middlewares/role.middleware");

const router = express.Router();

// Administrator-only audit logs listing
router.get("/", authenticate, authorizeRoles("ADMIN"), auditLogController.listAuditLogs);

module.exports = router;
