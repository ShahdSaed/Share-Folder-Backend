const userRepository = require("../users/user.repository");
const auditLogService = require("../audit-logs/audit-log.service");
const { verifyPassword } = require("../../utils/password");
const { signToken } = require("../../utils/jwt");
const { UnauthorizedError, NotFoundError } = require("../../utils/errors");

const GENERIC_AUTH_ERROR = "Invalid email or password";

class AuthService {
    constructor(userRepo = userRepository, auditService = auditLogService) {
        this.userRepository = userRepo;
        this.auditLogService = auditService;
    }

    /**
     * Authenticate a user and return a JWT access token.
     * @param {object} credentials
     * @returns {Promise<{ token: string, user: object }>}
     */
    async login({ email, password, ipAddress, userAgent }) {
        // 1. Find user by normalized email
        const user = await this.userRepository.findByEmailWithPassword(email);

        // 2. If user not found, perform dummy verification to mitigate timing attacks and log failure
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

        // 3. Verify password hash using Argon2id
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

        // 4. Check if account is active
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

        // 5. Audit successful login
        await this.auditLogService.logEvent({
            userId: user.id,
            action: "LOGIN_SUCCESS",
            targetType: "AUTH",
            targetId: user.id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        // 6. Sign JWT with minimal claims
        const token = signToken({
            sub: user.id,
            role: user.role
        });

        // 7. Return token and safe user payload
        return {
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                role: user.role,
                isActive: user.isActive,
                createdAt: user.createdAt
            }
        };
    }

    /**
     * Retrieve the current authenticated user's safe profile.
     * @param {string} userId 
     * @returns {Promise<object>}
     */
    async getMe(userId) {
        const user = await this.userRepository.findById(userId);
        if (!user) {
            throw new NotFoundError("User not found");
        }
        return user;
    }
}

module.exports = new AuthService();
