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
     * Count users in the database.
     * @returns {Promise<number>}
     */
    async count() {
        const prisma = await this.getPrisma();
        return await prisma.user.count();
    }
}

module.exports = new UserRepository();
