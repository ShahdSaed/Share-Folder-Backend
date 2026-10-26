const env = require("./src/config/env");
const express = require("express");
const cors = require("cors");
const prismaPromise = require("./src/config/prisma");

const authRoutes = require("./src/modules/auth/auth.routes");
const auditLogRoutes = require("./src/modules/audit-logs/audit-log.routes");
const { errorHandler, notFoundHandler } = require("./src/middlewares/error.middleware");

const app = express();
const PORT = env.port;

// Global Middleware
app.use(cors());
app.use(express.json());

// Health Check Endpoint
app.get("/api/health", async (req, res) => {
    try {
        const prisma = await prismaPromise;
        await prisma.$queryRaw`SELECT 1`;

        res.status(200).json({
            status: "ok",
            message: "Backend and database are connected"
        });
    } catch (error) {
        console.error("Database health check failed:", error.message);

        res.status(503).json({
            status: "error",
            message: "Database connection failed"
        });
    }
});

// Application Routes
app.use("/api/auth", authRoutes);
app.use("/api/admin/audit-logs", auditLogRoutes);

// 404 & Centralized Error Handlers
app.use(notFoundHandler);
app.use(errorHandler);

let server = null;

// Start server only when executed directly, allowing clean imports in tests
if (require.main === module) {
    server = app.listen(PORT, () => {
        console.log(`Server running at http://localhost:${PORT}`);
    });
}

async function shutdown() {
    if (server) {
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
    } else {
        process.exit(0);
    }
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);

module.exports = { app, server, shutdown };
