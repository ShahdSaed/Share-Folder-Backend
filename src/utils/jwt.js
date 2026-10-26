const jwt = require("jsonwebtoken");
const env = require("../config/env");
const { UnauthorizedError, ForbiddenError } = require("./errors");

const ALLOWED_ALGORITHM = "HS256";
const FILE_UNLOCK_EXPIRATION = "15m";

/**
 * Generate a signed JWT access token.
 * @param {object} payload - claims to sign (must include sub)
 * @param {object} options - override options like expiresIn
 * @returns {string} signed JWT
 */
function signToken(payload, options = {}) {
    if (!payload || !payload.sub) {
        throw new Error("Token payload must include a 'sub' claim");
    }

    return jwt.sign(
        {
            ...payload,
            sub: payload.sub,
            role: payload.role
        },
        env.jwt.secret,
        {
            algorithm: ALLOWED_ALGORITHM,
            expiresIn: options.expiresIn || env.jwt.expiresIn
        }
    );
}

/**
 * Generate a short-lived, file-specific unlock token.
 * Bound to specific user and file, expires in 15 minutes.
 * @param {object} params
 * @param {string} params.userId
 * @param {string} params.fileId
 * @returns {string}
 */
function signFileUnlockToken({ userId, fileId }) {
    if (!userId || !fileId) {
        throw new Error("Both userId and fileId are required for unlock grant");
    }

    return jwt.sign(
        {
            sub: userId,
            fileId,
            type: "FILE_UNLOCK"
        },
        env.jwt.secret,
        {
            algorithm: ALLOWED_ALGORITHM,
            expiresIn: FILE_UNLOCK_EXPIRATION
        }
    );
}

/**
 * Verify and decode a JWT token using HS256.
 * @param {string} token - raw JWT string
 * @returns {object} decoded payload
 */
function verifyToken(token) {
    if (!token || typeof token !== "string") {
        throw new UnauthorizedError("Authentication token is missing or malformed");
    }

    try {
        return jwt.verify(token, env.jwt.secret, {
            algorithms: [ALLOWED_ALGORITHM]
        });
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            throw new UnauthorizedError("Authentication token has expired");
        }
        if (error instanceof jwt.JsonWebTokenError) {
            throw new UnauthorizedError("Authentication token is invalid");
        }
        throw new UnauthorizedError("Authentication token verification failed");
    }
}

/**
 * Verify a file unlock token for a specific user and file.
 * @param {string} token
 * @param {object} context
 * @param {string} context.userId
 * @param {string} context.fileId
 * @returns {boolean}
 */
function verifyFileUnlockToken(token, { userId, fileId }) {
    if (!token) {
        throw new ForbiddenError("File unlock verification required to view or download file content");
    }

    const decoded = verifyToken(token);

    if (decoded.type !== "FILE_UNLOCK") {
        throw new ForbiddenError("Invalid grant token type");
    }

    if (decoded.sub !== userId) {
        throw new ForbiddenError("Unlock token was issued to a different user");
    }

    if (decoded.fileId !== fileId) {
        throw new ForbiddenError("Unlock token was issued for a different file");
    }

    return true;
}

module.exports = {
    signToken,
    signFileUnlockToken,
    verifyToken,
    verifyFileUnlockToken,
    ALLOWED_ALGORITHM,
    FILE_UNLOCK_EXPIRATION
};
