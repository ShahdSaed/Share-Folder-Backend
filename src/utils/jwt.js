const jwt = require("jsonwebtoken");
const env = require("../config/env");
const { UnauthorizedError } = require("./errors");

const ALLOWED_ALGORITHM = "HS256";

/**
 * Generate a signed JWT access token.
 * @param {object} payload - claims to sign (must include sub and role)
 * @param {object} options - override options like expiresIn
 * @returns {string} signed JWT
 */
function signToken(payload, options = {}) {
    if (!payload || !payload.sub) {
        throw new Error("Token payload must include a 'sub' claim");
    }

    return jwt.sign(
        {
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

module.exports = {
    signToken,
    verifyToken,
    ALLOWED_ALGORITHM
};
