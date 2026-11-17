const prismaPromise = require("../../config/prisma");
const { hashRefreshToken } = require("../../utils/refresh-token");

class RefreshSessionRepository {
    async getPrisma() {
        return await prismaPromise;
    }

    async createSession({ userId, rawToken, expiresAt, ipAddress, userAgent }) {
        const prisma = await this.getPrisma();
        return await prisma.refreshSession.create({
            data: {
                userId,
                tokenHash: hashRefreshToken(rawToken),
                expiresAt,
                ipAddress: ipAddress || null,
                userAgent: userAgent || null
            }
        });
    }

    async findByRawToken(rawToken) {
        const prisma = await this.getPrisma();
        return await prisma.refreshSession.findUnique({
            where: { tokenHash: hashRefreshToken(rawToken) },
            include: {
                user: {
                    select: {
                        id: true,
                        name: true,
                        username: true,
                        role: true,
                        isActive: true,
                        createdAt: true
                    }
                }
            }
        });
    }

    /**
     * Rotate a refresh token inside a transaction.
     * Reuse of an already-rotated token revokes every active session for that user.
     * @returns {Promise<{ rotated: true, user: object, newRawToken: string, newSession: object } | { reused: true, userId: string } | { invalid: true }>}
     */
    async rotateSession({ rawToken, newRawToken, expiresAt, ipAddress, userAgent }) {
        const prisma = await this.getPrisma();
        const presentedHash = hashRefreshToken(rawToken);
        const newHash = hashRefreshToken(newRawToken);
        const now = new Date();

        return await prisma.$transaction(async (tx) => {
            const existing = await tx.refreshSession.findUnique({
                where: { tokenHash: presentedHash },
                include: {
                    user: {
                        select: {
                            id: true,
                            name: true,
                            username: true,
                            role: true,
                            isActive: true,
                            createdAt: true
                        }
                    }
                }
            });

            if (!existing) {
                return { invalid: true };
            }

            if (existing.revokedAt) {
                if (existing.replacedBy) {
                    await tx.refreshSession.updateMany({
                        where: { userId: existing.userId, revokedAt: null },
                        data: { revokedAt: now }
                    });
                    return { reused: true, userId: existing.userId };
                }
                return { invalid: true };
            }

            if (existing.expiresAt <= now) {
                return { invalid: true };
            }

            const claimed = await tx.refreshSession.updateMany({
                where: {
                    id: existing.id,
                    revokedAt: null
                },
                data: { revokedAt: now, lastUsedAt: now }
            });

            if (claimed.count !== 1) {
                return { invalid: true };
            }

            const newSession = await tx.refreshSession.create({
                data: {
                    userId: existing.userId,
                    tokenHash: newHash,
                    expiresAt,
                    ipAddress: ipAddress || existing.ipAddress,
                    userAgent: userAgent || existing.userAgent
                }
            });

            await tx.refreshSession.update({
                where: { id: existing.id },
                data: { replacedBy: newSession.id }
            });

            return {
                rotated: true,
                user: existing.user,
                newRawToken,
                newSession
            };
        });
    }

    async revokeByRawToken(rawToken) {
        const prisma = await this.getPrisma();
        const now = new Date();
        return await prisma.refreshSession.updateMany({
            where: {
                tokenHash: hashRefreshToken(rawToken),
                revokedAt: null
            },
            data: { revokedAt: now }
        });
    }

    async revokeAllForUser(userId) {
        const prisma = await this.getPrisma();
        const now = new Date();
        return await prisma.refreshSession.updateMany({
            where: { userId, revokedAt: null },
            data: { revokedAt: now }
        });
    }
}

module.exports = new RefreshSessionRepository();
