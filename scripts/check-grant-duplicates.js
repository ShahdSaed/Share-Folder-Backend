const prismaPromise = require("../src/config/prisma");

async function run() {
    const prisma = await prismaPromise;
    try {
        const rows = await prisma.$queryRaw`
            SELECT
                user_id AS userId,
                file_id AS fileId,
                COUNT(*) AS duplicateCount
            FROM file_access_grants
            GROUP BY user_id, file_id
            HAVING COUNT(*) > 1
        `;
        const totalGrants = await prisma.fileAccessGrant.count();

        const duplicates = rows.map((row) => ({
            userId: String(row.userId),
            fileId: String(row.fileId),
            duplicateCount: Number(row.duplicateCount)
        }));

        console.log(JSON.stringify({
            totalGrants,
            duplicateGroups: duplicates.length,
            duplicates
        }, null, 2));
    } finally {
        await prisma.$disconnect();
    }
}

run().catch((error) => {
    console.error("DUPLICATE_CHECK_FAILED:", error.message);
    process.exit(1);
});
