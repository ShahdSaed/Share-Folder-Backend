require("dotenv").config();
const { parseCorsOrigins } = require("./cors-origins");

function parseSameSite(raw, isProduction) {
    const value = String(raw || (isProduction ? "none" : "lax")).toLowerCase();
    if (value !== "lax" && value !== "strict" && value !== "none") {
        throw new Error("[FATAL] COOKIE_SAMESITE must be one of: lax, strict, none.");
    }
    return value;
}

function validateEnv() {
    const missingVars = [];

    if (!process.env.JWT_SECRET) {
        missingVars.push("JWT_SECRET");
    }

    if (missingVars.length > 0) {
        throw new Error(
            `[FATAL] Missing required environment variable(s): ${missingVars.join(", ")}. ` +
            `Please ensure they are defined in your .env file or deployment environment.`
        );
    }

    const nodeEnv = process.env.NODE_ENV || "development";
    const isProduction = nodeEnv === "production";

    if (process.env.JWT_SECRET.length < 32 && isProduction) {
        throw new Error(
            `[FATAL] JWT_SECRET must be at least 32 characters long in production for security.`
        );
    }

    const corsOrigins = parseCorsOrigins(process.env.CORS_ORIGINS);
    const cookieSecure = process.env.COOKIE_SECURE
        ? process.env.COOKIE_SECURE === "true"
        : isProduction;
    const cookieSameSite = parseSameSite(process.env.COOKIE_SAMESITE || "lax", isProduction);

    if (cookieSameSite === "none" && !cookieSecure) {
        throw new Error("[FATAL] COOKIE_SAMESITE=none requires COOKIE_SECURE=true (HTTPS).");
    }

    const refreshDays = Number(process.env.REFRESH_TOKEN_DAYS || 7);
    if (!Number.isFinite(refreshDays) || refreshDays < 1 || refreshDays > 30) {
        throw new Error("[FATAL] REFRESH_TOKEN_DAYS must be a number between 1 and 30.");
    }

    return {
        port: Number(process.env.PORT || 3000),
        nodeEnv,
        jwt: {
            secret: process.env.JWT_SECRET,
            expiresIn: process.env.JWT_ACCESS_EXPIRES_IN || process.env.JWT_EXPIRES_IN || "15m",
            algorithm: "HS256"
        },
        refresh: {
            days: refreshDays
        },
        cookie: {
            name: process.env.REFRESH_COOKIE_NAME || "refresh_token",
            secure: cookieSecure,
            sameSite: cookieSameSite,
            path: "/api",
            maxAgeMs: refreshDays * 24 * 60 * 60 * 1000
        },
        db: {
            host: process.env.DB_HOST || "localhost",
            port: Number(process.env.DB_PORT || 3306),
            user: process.env.DB_USER || "root",
            password: process.env.DB_PASSWORD || "",
            database: process.env.DB_NAME || "company_file_hub"
        },
        cors: {
            origins: corsOrigins
        }
    };
}

const env = validateEnv();

module.exports = env;
