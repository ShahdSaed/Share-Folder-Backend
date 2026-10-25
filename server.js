require("dotenv").config();

const express = require("express");
const prismaPromise = require("./src/config/prisma");

const app = express();
const PORT = Number(process.env.PORT || 3000);

app.use(express.json());

app.get("/api/health", async (req, res) => {
    try {
        const prisma = await prismaPromise;
        await prisma.$queryRaw`SELECT 1`;

        res.status(200).json({
            status: "ok",
            message: "Backend and database are connected"
        });
    } catch (error) {
        console.error("Database health check failed:", error);

        res.status(503).json({
            status: "error",
            message: "Database connection failed"
        });
    }
});

const server = app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

async function shutdown() {
    server.close(async () => {
        try {
            const prisma = await prismaPromise;
            await prisma.$disconnect();
        } catch (error) {
            console.error("Shutdown error:", error.message);
        } finally {
            process.exit(0);
        }
    });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
