const express = require("express");
const authController = require("./auth.controller");
const { authenticate } = require("../../middlewares/auth.middleware");

const router = express.Router();

// Public login endpoint
router.post("/login", authController.login);

// Protected authenticated user profile
router.get("/me", authenticate, authController.getMe);

module.exports = router;
