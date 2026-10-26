// Ensure BigInt values (e.g. file size in Prisma) serialize safely in JSON responses
BigInt.prototype.toJSON = function () {
    return Number(this);
};

const env = require("./src/config/env");
const express = require("express");
const cors = require("cors");
const prismaPromise = require("./src/config/prisma");

const authRoutes = require("./src/modules/auth/auth.routes");
const userRoutes = require("./src/modules/users/user.routes");
const fileRoutes = require("./src/modules/files/file.routes");
const auditLogRoutes = require("./src/modules/audit-logs/audit-log.routes");
const { errorHandler, notFoundHandler } = require("./src/middlewares/error.middleware");

const app = express();
const PORT = env.port;

// Global Middleware
app.use(cors());
app.use(express.json());

// Health Check Endpoint (supports both /api/health and /api/v1/health)
const healthHandler = async (req, res) => {
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
};

app.get("/api/health", healthHandler);
app.get("/api/v1/health", healthHandler);

// API v1 Routes (Standard API prefix)
app.use("/api/v1/auth", authRoutes);
app.use("/api/v1/users", userRoutes);
app.use("/api/v1/files", fileRoutes);
app.use("/api/v1/admin/audit-logs", auditLogRoutes);

// Compatibility aliases for /api/* without versioning
app.use("/api/auth", authRoutes);
app.use("/api/users", userRoutes);
app.use("/api/files", fileRoutes);
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
