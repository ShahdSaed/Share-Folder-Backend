const prismaPromise = require("../../config/prisma");

class FileRepository {
    async getPrisma() {
        return await prismaPromise;
    }

    /**
     * Helper to safely format file record and cast BigInt size to number.
     */
    formatFile(file) {
        if (!file) return null;
        return {
            ...file,
            size: typeof file.size === "bigint" ? Number(file.size) : file.size
        };
    }

    /**
     * Create a new file record in database.
     */
    async create(data) {
        const prisma = await this.getPrisma();
        const file = await prisma.file.create({
            data: {
                name: data.name,
                description: data.description ?? null,
                storageKey: data.storageKey,
                mimeType: data.mimeType,
                size: BigInt(data.size),
                passwordHash: data.passwordHash,
                uploadedBy: data.uploadedBy
            },
            select: {
                id: true,
                name: true,
                description: true,
                mimeType: true,
                size: true,
                uploadedBy: true,
                createdAt: true,
                updatedAt: true,
                uploader: {
                    select: {
                        id: true,
                        name: true,
                        username: true
                    }
                }
            }
        });
        return this.formatFile(file);
    }

    /**
     * Find file by ID without exposing password hash or internal storage key.
     */
    async findById(id) {
        const prisma = await this.getPrisma();
        const file = await prisma.file.findUnique({
            where: { id },
            select: {
                id: true,
                name: true,
                description: true,
                mimeType: true,
                size: true,
                uploadedBy: true,
                createdAt: true,
                updatedAt: true,
                uploader: {
                    select: {
                        id: true,
                        name: true,
                        username: true
                    }
                }
            }
        });
        return this.formatFile(file);
    }

    /**
     * Find file by ID including password hash and internal storage key for verification / streaming.
     */
    async findByIdInternal(id) {
        const prisma = await this.getPrisma();
        const file = await prisma.file.findUnique({
            where: { id }
        });
        return this.formatFile(file);
    }

    /**
     * Find paginated files (for ADMIN).
     */
    async findPaginated({ skip = 0, limit = 20, search, mimeType }) {
        const prisma = await this.getPrisma();
        const where = {};

        if (search) {
            where.OR = [
                { name: { contains: search } },
                { description: { contains: search } }
            ];
        }
        if (mimeType) {
            where.mimeType = mimeType;
        }

        const [files, total] = await Promise.all([
            prisma.file.findMany({
                where,
                skip,
                take: limit,
                orderBy: { createdAt: "desc" },
                select: {
                    id: true,
                    name: true,
                    description: true,
                    mimeType: true,
                    size: true,
                    uploadedBy: true,
                    createdAt: true,
                    updatedAt: true,
                    uploader: {
                        select: {
                            id: true,
                            name: true,
                            username: true
                        }
                    }
                }
            }),
            prisma.file.count({ where })
        ]);

        return {
            files: files.map((f) => this.formatFile(f)),
            total
        };
    }

    /**
     * Find paginated files explicitly assigned to a VIEWER.
     */
    async findAssignedToUserPaginated({ userId, skip = 0, limit = 20, search, mimeType }) {
        const prisma = await this.getPrisma();
        const now = new Date();

        const where = {
            accessGrants: {
                some: {
                    userId,
                    expiresAt: { gt: now }
                }
            }
        };

        if (search) {
            where.OR = [
                { name: { contains: search } },
                { description: { contains: search } }
            ];
        }
        if (mimeType) {
            where.mimeType = mimeType;
        }

        const [files, total] = await Promise.all([
            prisma.file.findMany({
                where,
                skip,
                take: limit,
                orderBy: { createdAt: "desc" },
                select: {
                    id: true,
                    name: true,
                    description: true,
                    mimeType: true,
                    size: true,
                    uploadedBy: true,
                    createdAt: true,
                    updatedAt: true,
                    uploader: {
                        select: {
                            id: true,
                            name: true,
                            username: true
                        }
                    }
                }
            }),
            prisma.file.count({ where })
        ]);

        return {
            files: files.map((f) => this.formatFile(f)),
            total
        };
    }

    /**
     * Check if a user has an active grant for a file.
     */
    async hasActiveGrant(fileId, userId) {
        const prisma = await this.getPrisma();
        const now = new Date();

        const grant = await prisma.fileAccessGrant.findFirst({
            where: {
                fileId,
                userId,
                expiresAt: { gt: now }
            }
        });

        return Boolean(grant);
    }

    /**
     * Update file metadata.
     */
    async update(id, data) {
        const prisma = await this.getPrisma();
        const file = await prisma.file.update({
            where: { id },
            data: {
                ...(data.name !== undefined && { name: data.name }),
                ...(data.description !== undefined && { description: data.description })
            },
            select: {
                id: true,
                name: true,
                description: true,
                mimeType: true,
                size: true,
                uploadedBy: true,
                createdAt: true,
                updatedAt: true,
                // Include uploader so the UI keeps showing the uploader's name after an edit
                uploader: {
                    select: {
                        id: true,
                        name: true,
                        username: true
                    }
                }
            }
        });
        return this.formatFile(file);
    }

    /**
     * Update file password hash.
     */
    async updatePassword(id, passwordHash) {
        const prisma = await this.getPrisma();
        const file = await prisma.file.update({
            where: { id },
            data: { passwordHash },
            select: {
                id: true,
                name: true,
                updatedAt: true
            }
        });
        return this.formatFile(file);
    }

    /**
     * Delete file from database.
     */
    async delete(id) {
        const prisma = await this.getPrisma();
        return await prisma.file.delete({
            where: { id }
        });
    }
}

module.exports = new FileRepository();
