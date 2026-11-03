const authService = require("./auth.service");
const { validateLoginInput } = require("../../utils/validator");
const { validateChangePasswordInput } = require("./auth.validation");
const { setRefreshCookie, clearRefreshCookie, readRefreshCookie } = require("../../utils/auth-cookies");

function clientMeta(req) {
    return {
        ipAddress: req.ip || req.socket?.remoteAddress || null,
        userAgent: req.headers["user-agent"] || null
    };
}

function tokenPayload(result) {
    return {
        token: result.accessToken,
        accessToken: result.accessToken,
        expiresIn: result.expiresIn,
        user: result.user
    };
}

class AuthController {
    constructor(service = authService) {
        this.authService = service;
    }

    login = async (req, res, next) => {
        try {
            const { email, password } = validateLoginInput(req.body);
            const result = await this.authService.login({
                email,
                password,
                ...clientMeta(req)
            });

            setRefreshCookie(res, result.refreshToken);

            return res.status(200).json({
                status: "success",
                message: "Authentication successful",
                data: tokenPayload(result)
            });
        } catch (error) {
            next(error);
        }
    };

    refresh = async (req, res, next) => {
        try {
            const result = await this.authService.refresh({
                rawToken: readRefreshCookie(req),
                ...clientMeta(req)
            });

            setRefreshCookie(res, result.refreshToken);

            return res.status(200).json({
                status: "success",
                message: "Session refreshed",
                data: tokenPayload(result)
            });
        } catch (error) {
            clearRefreshCookie(res);
            next(error);
        }
    };

    logout = async (req, res, next) => {
        try {
            await this.authService.logout({
                rawToken: readRefreshCookie(req),
                ...clientMeta(req)
            });
            clearRefreshCookie(res);

            return res.status(200).json({
                status: "success",
                message: "Logged out successfully",
                data: null
            });
        } catch (error) {
            clearRefreshCookie(res);
            next(error);
        }
    };

    logoutAll = async (req, res, next) => {
        try {
            await this.authService.logoutAll({
                userId: req.user.id,
                ...clientMeta(req)
            });
            clearRefreshCookie(res);

            return res.status(200).json({
                status: "success",
                message: "All sessions have been revoked",
                data: null
            });
        } catch (error) {
            next(error);
        }
    };

    changePassword = async (req, res, next) => {
        try {
            const { currentPassword, newPassword } = validateChangePasswordInput(req.body);
            const user = await this.authService.changePassword({
                userId: req.user.id,
                currentPassword,
                newPassword,
                ...clientMeta(req)
            });
            clearRefreshCookie(res);

            return res.status(200).json({
                status: "success",
                message: "Password changed successfully. Please sign in again.",
                data: { user }
            });
        } catch (error) {
            next(error);
        }
    };

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
