const prismaPromise = require("../../config/prisma");

const GRANT_USER_INCLUDE = {
    user: {
        select: {
            id: true,
            name: true,
            username: true,
            role: true
        }
    }
};

function isUniqueConstraintError(error) {
    return Boolean(error && error.code === "P2002");
}

class FileAccessRepository {
    async getPrisma() {
        return await prismaPromise;
    }

    /**
     * Find an existing grant by the unique (userId, fileId) pair.
     */
    async findGrant(fileId, userId) {
        const prisma = await this.getPrisma();
        return await prisma.fileAccessGrant.findUnique({
            where: {
                userId_fileId: { userId, fileId }
            },
            include: GRANT_USER_INCLUDE
        });
    }

    /**
     * List all access grants for a specific file.
     */
    async findGrantsByFileId(fileId, { status = "all" } = {}) {
        const prisma = await this.getPrisma();
        const now = new Date();
        const where = { fileId };

        if (status === "active") {
            where.expiresAt = { gt: now };
        } else if (status === "expired") {
            where.expiresAt = { lte: now };
        }

        return await prisma.fileAccessGrant.findMany({
            where,
            orderBy: { createdAt: "desc" },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        username: true,
                        role: true,
                        isActive: true
                    }
                }
            }
        });
    }

    /**
     * Create or update an access grant using the composite unique key.
     * Concurrent creates that hit the unique constraint retry once as an upsert.
     */
    async grantAccess({ fileId, userId, expiresAt }) {
        const prisma = await this.getPrisma();
        const existing = await prisma.fileAccessGrant.findUnique({
            where: { userId_fileId: { userId, fileId } }
        });

        try {
            const grant = await this.upsertGrant(prisma, { fileId, userId, expiresAt });
            return { grant, created: !existing };
        } catch (error) {
            if (!isUniqueConstraintError(error)) {
                throw error;
            }

            const grant = await this.upsertGrant(prisma, { fileId, userId, expiresAt });
            return { grant, created: false };
        }
    }

    async upsertGrant(prisma, { fileId, userId, expiresAt }) {
        return await prisma.fileAccessGrant.upsert({
            where: {
                userId_fileId: { userId, fileId }
            },
            update: { expiresAt },
            create: {
                fileId,
                userId,
                expiresAt
            },
            include: GRANT_USER_INCLUDE
        });
    }

    /**
     * Revoke access grant for a user and file.
     */
    async revokeAccess(fileId, userId) {
        const prisma = await this.getPrisma();
        return await prisma.fileAccessGrant.deleteMany({
            where: { fileId, userId }
        });
    }
}

module.exports = new FileAccessRepository();
