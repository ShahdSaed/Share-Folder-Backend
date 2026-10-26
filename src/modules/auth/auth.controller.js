const authService = require("./auth.service");
const { validateLoginInput } = require("../../utils/validator");

class AuthController {
    constructor(service = authService) {
        this.authService = service;
    }

    /**
     * Handle user login.
     * POST /api/auth/login
     */
    login = async (req, res, next) => {
        try {
            const { email, password } = validateLoginInput(req.body);

            const ipAddress = req.ip || req.socket?.remoteAddress || null;
            const userAgent = req.headers["user-agent"] || null;

            const result = await this.authService.login({
                email,
                password,
                ipAddress,
                userAgent
            });

            return res.status(200).json({
                status: "success",
                message: "Authentication successful",
                data: result
            });
        } catch (error) {
            next(error);
        }
    };

    /**
     * Get current user profile.
     * GET /api/auth/me
     */
    getMe = async (req, res, next) => {
        try {
            const user = await this.authService.getMe(req.user.id);

            return res.status(200).json({
                status: "success",
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };
}

module.exports = new AuthController();
