const prismaPromise = require("../../config/prisma");

class UserRepository {
    async getPrisma() {
        return await prismaPromise;
    }

    /**
     * Find a user by normalized email including their password hash for auth verification.
     * @param {string} email 
     * @returns {Promise<object|null>}
     */
    async findByEmailWithPassword(email) {
        const prisma = await this.getPrisma();
        return await prisma.user.findUnique({
            where: { email }
        });
    }

    /**
     * Find a user by id without exposing the password hash.
     * @param {string} id 
     * @returns {Promise<object|null>}
     */
    async findById(id) {
        const prisma = await this.getPrisma();
        return await prisma.user.findUnique({
            where: { id },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                isActive: true,
                createdAt: true
            }
        });
    }

    async findByIdWithPassword(id) {
        const prisma = await this.getPrisma();
        return await prisma.user.findUnique({
            where: { id }
        });
    }

    /**
     * Retrieve paginated list of users with optional filtering.
     * @param {object} params
     * @returns {Promise<{ users: Array, total: number }>}
     */
    async findPaginated({ skip = 0, limit = 20, search, role, status }) {
        const prisma = await this.getPrisma();
        const where = {};

        if (role) {
            where.role = role;
        }

        if (status !== undefined && status !== null) {
            if (typeof status === "boolean") {
                where.isActive = status;
            } else if (status === "ACTIVE" || status === "active" || status === "true") {
                where.isActive = true;
            } else if (status === "INACTIVE" || status === "inactive" || status === "false") {
                where.isActive = false;
            }
        }

        if (search) {
            where.OR = [
                { name: { contains: search } },
                { email: { contains: search } }
            ];
        }

        const [users, total] = await Promise.all([
            prisma.user.findMany({
                where,
                skip,
                take: limit,
                orderBy: { createdAt: "desc" },
                select: {
                    id: true,
                    name: true,
                    email: true,
                    role: true,
                    isActive: true,
                    createdAt: true
                }
            }),
            prisma.user.count({ where })
        ]);

        return { users, total };
    }

    /**
     * Create a new user with hashed password.
     * @param {object} userData
     * @returns {Promise<object>}
     */
    async create(userData) {
        const prisma = await this.getPrisma();
        return await prisma.user.create({
            data: {
                name: userData.name,
                email: userData.email,
                passwordHash: userData.passwordHash,
                role: userData.role || "VIEWER",
                isActive: userData.isActive !== undefined ? userData.isActive : true
            },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                isActive: true,
                createdAt: true
            }
        });
    }

    /**
     * Update permitted user fields.
     * @param {string} id
     * @param {object} data
     * @returns {Promise<object>}
     */
    async update(id, data) {
        const prisma = await this.getPrisma();
        const updateData = {};

        if (data.name !== undefined) updateData.name = data.name;
        if (data.role !== undefined) updateData.role = data.role;
        if (data.isActive !== undefined) updateData.isActive = data.isActive;

        return await prisma.user.update({
            where: { id },
            data: updateData,
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                isActive: true,
                createdAt: true
            }
        });
    }

    /**
     * Update user account status (active/inactive).
     * @param {string} id
     * @param {boolean} isActive
     * @returns {Promise<object>}
     */
    async updateStatus(id, isActive) {
        const prisma = await this.getPrisma();
        return await prisma.user.update({
            where: { id },
            data: { isActive },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                isActive: true,
                createdAt: true
            }
        });
    }

    /**
     * Update user password hash.
     * @param {string} id
     * @param {string} passwordHash
     * @returns {Promise<object>}
     */
    async updatePassword(id, passwordHash) {
        const prisma = await this.getPrisma();
        return await prisma.user.update({
            where: { id },
            data: { passwordHash },
            select: {
                id: true,
                name: true,
                email: true,
                role: true,
                isActive: true,
                createdAt: true
            }
        });
    }

    /**
     * Count users in the database.
     * @returns {Promise<number>}
     */
    async count() {
        const prisma = await this.getPrisma();
        return await prisma.user.count();
    }
}

module.exports = new UserRepository();
