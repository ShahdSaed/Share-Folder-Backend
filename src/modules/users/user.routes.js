const express = require("express");
const userController = require("./user.controller");
const { authenticate } = require("../../middlewares/auth.middleware");
const { authorizeRoles } = require("../../middlewares/role.middleware");
const { ForbiddenError } = require("../../utils/errors");

const router = express.Router();

// All user management routes require authentication
router.use(authenticate);

// User retrieval (ADMIN only, or self for /:id)
router.get("/", authorizeRoles("ADMIN"), userController.getUsers);

router.get("/:id", (req, res, next) => {
    // ADMIN can access any user, VIEWER can only access self
    if (req.user.role !== "ADMIN" && req.user.id !== req.params.id) {
        return next(new ForbiddenError("Access forbidden: you may only view your own user profile"));
    }
    return userController.getUserById(req, res, next);
});

// Administrative management endpoints (strictly ADMIN only)
router.post("/", authorizeRoles("ADMIN"), userController.createUser);
router.patch("/:id", authorizeRoles("ADMIN"), userController.updateUser);
router.patch("/:id/status", authorizeRoles("ADMIN"), userController.updateUserStatus);
router.post("/:id/reset-password", authorizeRoles("ADMIN"), userController.resetPassword);

module.exports = router;
