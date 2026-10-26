const userService = require("./user.service");
const {
    validateCreateUserInput,
    validateUpdateUserInput,
    validateUpdateStatusInput,
    validateResetPasswordInput
} = require("./user.validation");
const { validatePagination } = require("../../utils/validator");

class UserController {
    constructor(service = userService) {
        this.userService = service;
    }

    /**
     * Create user (ADMIN only).
     * POST /api/v1/users
     */
    createUser = async (req, res, next) => {
        try {
            const validatedInput = validateCreateUserInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const user = await this.userService.createUser({
                ...validatedInput,
                adminUser: req.user,
                ipAddress,
                userAgent
            });

            return res.status(201).json({
                status: "success",
                message: "User created successfully",
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * List users (ADMIN only).
     * GET /api/v1/users
     */
    getUsers = async (req, res, next) => {
        try {
            const pagination = validatePagination(req.query);
            const { search, role, status } = req.query;

            const result = await this.userService.getUsers({
                ...pagination,
                search: search ? String(search).trim() : undefined,
                role: role ? String(role).toUpperCase() : undefined,
                status
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
     * Get user by ID.
     * GET /api/v1/users/:id
     */
    getUserById = async (req, res, next) => {
        try {
            const user = await this.userService.getUserById(req.params.id);

            return res.status(200).json({
                status: "success",
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Update user details (ADMIN only).
     * PATCH /api/v1/users/:id
     */
    updateUser = async (req, res, next) => {
        try {
            const updates = validateUpdateUserInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const user = await this.userService.updateUser(
                req.params.id,
                updates,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: "User updated successfully",
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Update user status (ADMIN only).
     * PATCH /api/v1/users/:id/status
     */
    updateUserStatus = async (req, res, next) => {
        try {
            const { isActive } = validateUpdateStatusInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const user = await this.userService.updateUserStatus(
                req.params.id,
                isActive,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: `User account ${isActive ? "activated" : "deactivated"} successfully`,
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Reset user password (ADMIN only).
     * POST /api/v1/users/:id/reset-password
     */
    resetPassword = async (req, res, next) => {
        try {
            const { password } = validateResetPasswordInput(req.body);
            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const user = await this.userService.resetPassword(
                req.params.id,
                password,
                req.user,
                ipAddress,
                userAgent
            );

            return res.status(200).json({
                status: "success",
                message: "User password reset successfully",
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };
}

module.exports = new UserController();
