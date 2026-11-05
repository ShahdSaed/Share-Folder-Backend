const helmet = require("helmet");
const cors = require("cors");
const env = require("../config/env");
const { ForbiddenError } = require("../utils/errors");

const CORS_ALLOWED_METHODS = ["GET", "HEAD", "PUT", "PATCH", "POST", "DELETE", "OPTIONS"];
const CORS_ALLOWED_HEADERS = [
    "Content-Type",
    "Authorization",
    "X-File-Unlock-Token",
    "X-Unlock-Token",
    "ngrok-skip-browser-warning",
    "Accept",
    "X-Requested-With"
];

const HSTS_MAX_AGE_SECONDS = 15552000; // 180 days

/**
 * Helmet for a JSON API: keep recommended headers, use an API-oriented CSP,
 * and enable HSTS only in production (HTTPS deployments).
 * CORP is cross-origin so a separately hosted frontend can read API responses.
 * @param {{ isProduction?: boolean }} [options]
 */
function createHelmetMiddleware({ isProduction = false } = {}) {
    return helmet({
        frameguard: { action: "deny" },
        noSniff: true,
        contentSecurityPolicy: {
            useDefaults: false,
            directives: {
                defaultSrc: ["'none'"],
                frameAncestors: ["'none'"],
                baseUri: ["'none'"],
                formAction: ["'none'"]
            }
        },
        hsts: isProduction
            ? {
                maxAge: HSTS_MAX_AGE_SECONDS,
                includeSubDomains: true,
                preload: false
            }
            : false,
        crossOriginResourcePolicy: { policy: "cross-origin" }
    });
}

/**
 * CORS allowlist middleware. Requests without Origin are allowed (Postman, curl, server-to-server).
 * Credentials are enabled so the HttpOnly refresh cookie can be sent from the Angular origin.
 * Origins are never wildcards.
 * @param {{ origins?: string[] }} [options]
 */
function createCorsMiddleware({ origins = [] } = {}) {
    const allowedOrigins = new Set(origins);

    return cors({
        origin(origin, callback) {
            if (!origin) {
                return callback(null, true);
            }

            if (allowedOrigins.has(origin)) {
                return callback(null, true);
            }

            return callback(new ForbiddenError("Cross-origin request was rejected"));
        },
        credentials: true,
        methods: CORS_ALLOWED_METHODS,
        allowedHeaders: CORS_ALLOWED_HEADERS,
        optionsSuccessStatus: 204,
        maxAge: 600
    });
}

const helmetMiddleware = createHelmetMiddleware({
    isProduction: env.nodeEnv === "production"
});

const corsMiddleware = createCorsMiddleware({
    origins: env.cors.origins
});

module.exports = {
    CORS_ALLOWED_METHODS,
    CORS_ALLOWED_HEADERS,
    HSTS_MAX_AGE_SECONDS,
    createHelmetMiddleware,
    createCorsMiddleware,
    helmetMiddleware,
    corsMiddleware
};
