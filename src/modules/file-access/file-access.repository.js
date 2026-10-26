const prismaPromise = require("../../config/prisma");

class FileAccessRepository {
    async getPrisma() {
        return await prismaPromise;
    }

    /**
     * Find active or existing grant by fileId and userId.
     */
    async findGrant(fileId, userId) {
        const prisma = await this.getPrisma();
        return await prisma.fileAccessGrant.findFirst({
            where: { fileId, userId },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        role: true
                    }
                }
            }
        });
    }

    /**
     * List all access grants for a specific file.
     */
    async findGrantsByFileId(fileId) {
        const prisma = await this.getPrisma();
        return await prisma.fileAccessGrant.findMany({
            where: { fileId },
            orderBy: { createdAt: "desc" },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        role: true,
                        isActive: true
                    }
                }
            }
        });
    }

    /**
     * Create or update (upsert) an access grant.
     */
    async grantAccess({ fileId, userId, expiresAt }) {
        const prisma = await this.getPrisma();

        // Check if an existing grant exists
        const existing = await prisma.fileAccessGrant.findFirst({
            where: { fileId, userId }
        });

        if (existing) {
            return await prisma.fileAccessGrant.update({
                where: { id: existing.id },
                data: { expiresAt },
                include: {
                    user: {
                        select: {
                            id: true,
                            name: true,
                            email: true,
                            role: true
                        }
                    }
                }
            });
        }

        return await prisma.fileAccessGrant.create({
            data: {
                fileId,
                userId,
                expiresAt
            },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        email: true,
                        role: true
                    }
                }
            }
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
