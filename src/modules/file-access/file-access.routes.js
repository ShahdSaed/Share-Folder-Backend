const express = require("express");
const fileAccessController = require("./file-access.controller");
const { authenticate } = require("../../middlewares/auth.middleware");
const { authorizeRoles } = require("../../middlewares/role.middleware");

const router = express.Router({ mergeParams: true });

// All file access grant routes require authentication and strictly ADMIN privileges
router.use(authenticate);
router.use(authorizeRoles("ADMIN"));

router.post("/", fileAccessController.grantAccess);
router.get("/", fileAccessController.getGrants);
router.delete("/:userId", fileAccessController.revokeAccess);

module.exports = router;
