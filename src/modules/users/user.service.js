const userRepository = require("./user.repository");
const auditLogService = require("../audit-logs/audit-log.service");
const refreshSessionRepository = require("../auth/refresh-session.repository");
const { hashPassword } = require("../../utils/password");
const { ConflictError, NotFoundError, BadRequestError } = require("../../utils/errors");

class UserService {
    constructor(
        userRepo = userRepository,
        auditService = auditLogService,
        sessionRepo = refreshSessionRepository
    ) {
        this.userRepository = userRepo;
        this.auditLogService = auditService;
        this.sessionRepository = sessionRepo;
    }

    /**
     * Create a new user (ADMIN only).
     */
    async createUser({ name, email, password, role, adminUser, ipAddress, userAgent }) {
        // 1. Check duplicate email
        const existing = await this.userRepository.findByEmailWithPassword(email);
        if (existing) {
            throw new ConflictError(`A user with email '${email}' already exists`);
        }

        // 2. Hash password with Argon2id
        const passwordHash = await hashPassword(password);

        // 3. Create user in database
        const newUser = await this.userRepository.create({
            name,
            email,
            passwordHash,
            role,
            isActive: true
        });

        // 4. Audit user creation
        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "USER_CREATED",
            targetType: "USER",
            targetId: newUser.id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return newUser;
    }

    /**
     * List users with pagination and search/filtering (ADMIN only).
     */
    async getUsers({ page = 1, limit = 20, skip = 0, search, role, status }) {
        const { users, total } = await this.userRepository.findPaginated({
            skip,
            limit,
            search,
            role,
            status
        });

        const totalPages = Math.ceil(total / limit) || 1;

        return {
            users,
            pagination: {
                page,
                limit,
                total,
                totalPages,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        };
    }

    /**
     * Retrieve a specific user by id (ADMIN or self).
     */
    async getUserById(id) {
        const user = await this.userRepository.findById(id);
        if (!user) {
            throw new NotFoundError("User not found");
        }
        return user;
    }

    /**
     * Update user details (ADMIN only).
     */
    async updateUser(id, updates, adminUser, ipAddress, userAgent) {
        const targetUser = await this.userRepository.findById(id);
        if (!targetUser) {
            throw new NotFoundError("User not found");
        }

        // Prevent admin from removing their own ADMIN role
        if (targetUser.id === adminUser.id && updates.role && updates.role !== "ADMIN") {
            throw new BadRequestError("Administrators cannot demote their own account role");
        }

        // Prevent admin from deactivating their own account
        if (targetUser.id === adminUser.id && updates.isActive === false) {
            throw new BadRequestError("Administrators cannot deactivate their own account");
        }

        const updatedUser = await this.userRepository.update(id, updates);

        if (updates.isActive === false) {
            await this.sessionRepository.revokeAllForUser(id);
        }

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "USER_UPDATED",
            targetType: "USER",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return updatedUser;
    }

    /**
     * Update user active status (ADMIN only).
     */
    async updateUserStatus(id, isActive, adminUser, ipAddress, userAgent) {
        const targetUser = await this.userRepository.findById(id);
        if (!targetUser) {
            throw new NotFoundError("User not found");
        }

        if (targetUser.id === adminUser.id && !isActive) {
            throw new BadRequestError("Administrators cannot deactivate their own account");
        }

        const updatedUser = await this.userRepository.updateStatus(id, isActive);

        if (!isActive) {
            await this.sessionRepository.revokeAllForUser(id);
        }

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: isActive ? "USER_ACTIVATED" : "USER_DEACTIVATED",
            targetType: "USER",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return updatedUser;
    }

    /**
     * Reset a user's password (ADMIN only).
     */
    async resetPassword(id, newPassword, adminUser, ipAddress, userAgent) {
        const targetUser = await this.userRepository.findById(id);
        if (!targetUser) {
            throw new NotFoundError("User not found");
        }

        const passwordHash = await hashPassword(newPassword);
        const updatedUser = await this.userRepository.updatePassword(id, passwordHash);
        await this.sessionRepository.revokeAllForUser(id);

        await this.auditLogService.logEvent({
            userId: adminUser.id,
            action: "USER_PASSWORD_RESET",
            targetType: "USER",
            targetId: id,
            ipAddress,
            userAgent,
            result: "Success"
        });

        return updatedUser;
    }
}

module.exports = new UserService();
