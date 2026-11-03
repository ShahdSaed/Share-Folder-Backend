const { rateLimit } = require("express-rate-limit");
const { TooManyRequestsError } = require("../utils/errors");

const LOGIN_RATE_LIMIT_MAX = 5;
const LOGIN_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;

const FILE_PASSWORD_RATE_LIMIT_MAX = 5;
const FILE_PASSWORD_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;

const LOGIN_RATE_LIMIT_MESSAGE =
    "Too many login attempts. Please try again later.";
const FILE_PASSWORD_RATE_LIMIT_MESSAGE =
    "Too many file password attempts. Please try again later.";

/**
 * Count only failed authentication responses (HTTP 401).
 * Successful logins and validation errors do not consume the brute-force budget.
 */
function isLoginAttemptSuccessful(_req, res) {
    return res.statusCode !== 401;
}

function sendRateLimitError(message) {
    return (req, res, next) => {
        next(new TooManyRequestsError(message));
    };
}

/**
 * Factory for the login brute-force limiter.
 * Isolated stores/windows can be injected from tests.
 * @param {object} [overrides]
 */
function createLoginRateLimiter(overrides = {}) {
    return rateLimit({
        windowMs: LOGIN_RATE_LIMIT_WINDOW_MS,
        limit: LOGIN_RATE_LIMIT_MAX,
        skipSuccessfulRequests: true,
        requestWasSuccessful: isLoginAttemptSuccessful,
        standardHeaders: "draft-6",
        legacyHeaders: false,
        handler: sendRateLimitError(LOGIN_RATE_LIMIT_MESSAGE),
        ...overrides
    });
}

/**
 * Build a per-authenticated-user, per-file rate-limit key.
 * Authentication must run before this limiter so `req.user` is present.
 * @param {import("express").Request} req
 * @returns {string}
 */
function filePasswordKeyGenerator(req) {
    const userId = req.user && req.user.id ? String(req.user.id) : "anonymous";
    const fileId = req.params && req.params.id ? String(req.params.id) : "unknown";
    return `file-password:${userId}:${fileId}`;
}

/**
 * Factory for the file password verification limiter.
 * @param {object} [overrides]
 */
function createFilePasswordRateLimiter(overrides = {}) {
    return rateLimit({
        windowMs: FILE_PASSWORD_RATE_LIMIT_WINDOW_MS,
        limit: FILE_PASSWORD_RATE_LIMIT_MAX,
        standardHeaders: "draft-6",
        legacyHeaders: false,
        keyGenerator: filePasswordKeyGenerator,
        // Custom key is user+file, not IP. Do not set ipv6Subnet with a custom keyGenerator.
        validate: {
            keyGeneratorIpFallback: false,
            xForwardedForHeader: false
        },
        handler: sendRateLimitError(FILE_PASSWORD_RATE_LIMIT_MESSAGE),
        ...overrides
    });
}

const REFRESH_RATE_LIMIT_MAX = 30;
const REFRESH_RATE_LIMIT_WINDOW_MS = 15 * 60 * 1000;
const REFRESH_RATE_LIMIT_MESSAGE =
    "Too many token refresh attempts. Please try again later.";

function createRefreshRateLimiter(overrides = {}) {
    return rateLimit({
        windowMs: REFRESH_RATE_LIMIT_WINDOW_MS,
        limit: REFRESH_RATE_LIMIT_MAX,
        standardHeaders: "draft-6",
        legacyHeaders: false,
        handler: sendRateLimitError(REFRESH_RATE_LIMIT_MESSAGE),
        ...overrides
    });
}

const loginRateLimiter = createLoginRateLimiter();
const filePasswordRateLimiter = createFilePasswordRateLimiter();
const refreshRateLimiter = createRefreshRateLimiter();

module.exports = {
    LOGIN_RATE_LIMIT_MAX,
    LOGIN_RATE_LIMIT_WINDOW_MS,
    FILE_PASSWORD_RATE_LIMIT_MAX,
    FILE_PASSWORD_RATE_LIMIT_WINDOW_MS,
    LOGIN_RATE_LIMIT_MESSAGE,
    FILE_PASSWORD_RATE_LIMIT_MESSAGE,
    REFRESH_RATE_LIMIT_MAX,
    REFRESH_RATE_LIMIT_WINDOW_MS,
    REFRESH_RATE_LIMIT_MESSAGE,
    createLoginRateLimiter,
    createFilePasswordRateLimiter,
    createRefreshRateLimiter,
    loginRateLimiter,
    filePasswordRateLimiter,
    refreshRateLimiter
};
