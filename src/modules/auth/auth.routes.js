const express = require("express");
const authController = require("./auth.controller");
const { authenticate } = require("../../middlewares/auth.middleware");
const { requireAllowedOrigin } = require("../../middlewares/csrf-origin.middleware");
const {
    loginRateLimiter,
    refreshRateLimiter
} = require("../../middlewares/rate-limit.middleware");

const router = express.Router();

router.post("/login", loginRateLimiter, authController.login);
router.post("/refresh", refreshRateLimiter, requireAllowedOrigin, authController.refresh);
router.post("/logout", requireAllowedOrigin, authController.logout);
router.post("/logout-all", authenticate, requireAllowedOrigin, authController.logoutAll);
router.patch("/change-password", authenticate, authController.changePassword);
router.get("/me", authenticate, authController.getMe);

module.exports = router;
