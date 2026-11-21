require("dotenv").config();
const { parseCorsOrigins } = require("./cors-origins");

// Default "lax": the frontend reaches the API same-origin (Vercel /api rewrite), so the
// refresh cookie is first-party. Use "none" only for a true cross-site setup (blocked by iOS Safari).
function parseSameSite(raw) {
    const value = String(raw || "lax").toLowerCase();
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
    const cookieSameSite = parseSameSite(process.env.COOKIE_SAMESITE);

    if (cookieSameSite === "none" && !cookieSecure) {
        throw new Error("[FATAL] COOKIE_SAMESITE=none requires COOKIE_SECURE=true (HTTPS).");
    }

    const refreshDays = Number(process.env.REFRESH_TOKEN_DAYS || 7);
    if (!Number.isFinite(refreshDays) || refreshDays < 1 || refreshDays > 30) {
        throw new Error("[FATAL] REFRESH_TOKEN_DAYS must be a number between 1 and 30.");
    }

    const storageDriver = String(process.env.STORAGE_DRIVER || "local").toLowerCase();
    if (storageDriver !== "local" && storageDriver !== "r2") {
        throw new Error("[FATAL] STORAGE_DRIVER must be one of: local, r2.");
    }
    if (storageDriver === "r2") {
        const missingR2 = ["R2_ACCOUNT_ID", "R2_ACCESS_KEY_ID", "R2_SECRET_ACCESS_KEY", "R2_BUCKET"]
            .filter((key) => !process.env[key]);
        if (missingR2.length > 0) {
            throw new Error(`[FATAL] STORAGE_DRIVER=r2 requires: ${missingR2.join(", ")}.`);
        }
    } else if (isProduction && !process.env.STORAGE_DIR) {
        console.warn(
            "[WARN] Files are stored inside the app folder in production: they will be LOST on restart/redeploy " +
            "on hosts with ephemeral disks (e.g. Render). Mount a persistent disk and set STORAGE_DIR " +
            "(e.g. /var/data/private), or set STORAGE_DRIVER=r2."
        );
    }

    // Number of reverse proxies in front of the app (Express "trust proxy").
    // Render alone = 1. Vercel rewrite → Render = 2. Wrong values make every user share one IP
    // (login rate limit locks everyone out) or let clients spoof X-Forwarded-For.
    const rawTrustProxy = String(process.env.TRUST_PROXY ?? "1").trim();
    const trustProxy = /^\d+$/.test(rawTrustProxy) ? Number(rawTrustProxy) : rawTrustProxy;

    return {
        port: Number(process.env.PORT || 3000),
        trustProxy,
        storage: {
            driver: storageDriver,
            r2: {
                accountId: process.env.R2_ACCOUNT_ID,
                accessKeyId: process.env.R2_ACCESS_KEY_ID,
                secretAccessKey: process.env.R2_SECRET_ACCESS_KEY,
                bucket: process.env.R2_BUCKET
            }
        },
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
