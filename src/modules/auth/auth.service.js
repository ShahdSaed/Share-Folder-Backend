const userRepository = require("../users/user.repository");
const auditLogService = require("../audit-logs/audit-log.service");
const refreshSessionRepository = require("./refresh-session.repository");
const env = require("../../config/env");
const { hashPassword, verifyPassword } = require("../../utils/password");
const { signToken } = require("../../utils/jwt");
const { generateRefreshToken } = require("../../utils/refresh-token");
const { UnauthorizedError, NotFoundError, BadRequestError } = require("../../utils/errors");

const GENERIC_AUTH_ERROR = "Invalid email or password";
const GENERIC_REFRESH_ERROR = "Invalid refresh token";

function safeUser(user) {
    return {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role,
        isActive: user.isActive,
        createdAt: user.createdAt
    };
}

function refreshExpiryDate() {
    return new Date(Date.now() + env.refresh.days * 24 * 60 * 60 * 1000);
}

class AuthService {
    constructor(
        userRepo = userRepository,
        auditService = auditLogService,
        sessionRepo = refreshSessionRepository
    ) {
        this.userRepository = userRepo;
        this.auditLogService = auditService;
        this.sessionRepository = sessionRepo;
    }

    async issueSession(user, ipAddress, userAgent) {
        const accessToken = signToken({
            sub: user.id,
            role: user.role
        });
        const refreshToken = generateRefreshToken();
        await this.sessionRepository.createSession({
            userId: user.id,
            rawToken: refreshToken,
            expiresAt: refreshExpiryDate(),
            ipAddress,
            userAgent
        });
        return { accessToken, refreshToken, expiresIn: env.jwt.expiresIn, user: safeUser(user) };
    }

    async login({ email, password, ipAddress, userAgent }) {
        const user = await this.userRepository.findByEmailWithPassword(email);

        if (!user) {
            await this.auditLogService.logEvent({
                userId: null,
                action: "LOGIN_FAILED",
                targetType: "AUTH",
                targetId: null,
                ipAddress,
                userAgent,
                result: "Failed"
            });
            throw new UnauthorizedError(GENERIC_AUTH_ERROR);
        }

        const isPasswordValid = await verifyPassword(user.passwordHash, password);

        if (!isPasswordValid) {
            await this.auditLogService.logEvent({
                userId: user.id,
                action: "LOGIN_FAILED",
                targetType: "AUTH",
                targetId: user.id,
                ipAddress,
                userAgent,
                result: "Failed"
            });
            throw new UnauthorizedError(GENERIC_AUTH_ERROR);
        }

        if (!user.isActive) {
            await this.auditLogService.logEvent({
                userId: user.id,
                action: "LOGIN_REJECTED_INACTIVE",
                targetType: "AUTH",
                targetId: user.id,
                ipAddress,
                userAgent,
                result: "Failed"
            });
            throw new UnauthorizedError("Account has been deactivated. Please contact an administrator.");
        }

        await this.auditLogService.logEvent({
            userId: user.id,
            action: "LOGIN_SUCCESS",
            targetType: "AUTH",
            targetId: user.id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return this.issueSession(user, ipAddress, userAgent);
    }

    async refresh({ rawToken, ipAddress, userAgent }) {
        if (!rawToken) {
            throw new UnauthorizedError(GENERIC_REFRESH_ERROR);
        }

        const newRawToken = generateRefreshToken();
        const result = await this.sessionRepository.rotateSession({
            rawToken,
            newRawToken,
            expiresAt: refreshExpiryDate(),
            ipAddress,
            userAgent
        });

        if (result.reused) {
            await this.auditLogService.logEvent({
                userId: result.userId,
                action: "REFRESH_TOKEN_REUSE",
                targetType: "AUTH",
                targetId: result.userId,
                ipAddress,
                userAgent,
                result: "Failed"
            });
            throw new UnauthorizedError(GENERIC_REFRESH_ERROR);
        }

        if (!result.rotated || !result.user) {
            throw new UnauthorizedError(GENERIC_REFRESH_ERROR);
        }

        if (!result.user.isActive) {
            await this.sessionRepository.revokeAllForUser(result.user.id);
            throw new UnauthorizedError(GENERIC_REFRESH_ERROR);
        }

        const accessToken = signToken({
            sub: result.user.id,
            role: result.user.role
        });

        await this.auditLogService.logEvent({
            userId: result.user.id,
            action: "TOKEN_REFRESHED",
            targetType: "AUTH",
            targetId: result.user.id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return {
            accessToken,
            refreshToken: result.newRawToken,
            expiresIn: env.jwt.expiresIn,
            user: safeUser(result.user)
        };
    }

    async logout({ rawToken, ipAddress, userAgent }) {
        if (rawToken) {
            await this.sessionRepository.revokeByRawToken(rawToken);
        }

        await this.auditLogService.logEvent({
            userId: null,
            action: "LOGOUT",
            targetType: "AUTH",
            targetId: null,
            ipAddress,
            userAgent,
            result: "Success"
        });
    }

    async logoutAll({ userId, ipAddress, userAgent }) {
        await this.sessionRepository.revokeAllForUser(userId);

        await this.auditLogService.logEvent({
            userId,
            action: "LOGOUT_ALL",
            targetType: "AUTH",
            targetId: userId,
            ipAddress,
            userAgent,
            result: "Success"
        });
    }

    async changePassword({ userId, currentPassword, newPassword, ipAddress, userAgent }) {
        const user = await this.userRepository.findByIdWithPassword(userId);
        if (!user) {
            throw new NotFoundError("User not found");
        }

        const matches = await verifyPassword(user.passwordHash, currentPassword);
        if (!matches) {
            await this.auditLogService.logEvent({
                userId,
                action: "PASSWORD_CHANGE_FAILED",
                targetType: "AUTH",
                targetId: userId,
                ipAddress,
                userAgent,
                result: "Failed"
            });
            throw new UnauthorizedError("Current password is incorrect");
        }

        if (currentPassword === newPassword) {
            throw new BadRequestError("New password must be different from the current password");
        }

        const passwordHash = await hashPassword(newPassword);
        const updatedUser = await this.userRepository.updatePassword(userId, passwordHash);
        await this.sessionRepository.revokeAllForUser(userId);

        await this.auditLogService.logEvent({
            userId,
            action: "PASSWORD_CHANGED",
            targetType: "AUTH",
            targetId: userId,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return updatedUser;
    }

    async getMe(userId) {
        const user = await this.userRepository.findById(userId);
        if (!user) {
            throw new NotFoundError("User not found");
        }
        return user;
    }
}

module.exports = new AuthService();
module.exports.GENERIC_AUTH_ERROR = GENERIC_AUTH_ERROR;
module.exports.GENERIC_REFRESH_ERROR = GENERIC_REFRESH_ERROR;
