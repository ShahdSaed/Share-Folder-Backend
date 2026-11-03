const jwt = require("jsonwebtoken");
const env = require("../config/env");
const { UnauthorizedError, ForbiddenError } = require("./errors");

const ALLOWED_ALGORITHM = "HS256";
const FILE_UNLOCK_EXPIRATION = "15m";
const TOKEN_TYPE_ACCESS = "ACCESS";
const TOKEN_TYPE_FILE_UNLOCK = "FILE_UNLOCK";

function signToken(payload, options = {}) {
    if (!payload || !payload.sub) {
        throw new Error("Token payload must include a 'sub' claim");
    }

    return jwt.sign(
        {
            sub: payload.sub,
            role: payload.role,
            type: TOKEN_TYPE_ACCESS
        },
        env.jwt.secret,
        {
            algorithm: ALLOWED_ALGORITHM,
            expiresIn: options.expiresIn || env.jwt.expiresIn
        }
    );
}

function signFileUnlockToken({ userId, fileId }) {
    if (!userId || !fileId) {
        throw new Error("Both userId and fileId are required for unlock grant");
    }

    return jwt.sign(
        {
            sub: userId,
            fileId,
            type: TOKEN_TYPE_FILE_UNLOCK
        },
        env.jwt.secret,
        {
            algorithm: ALLOWED_ALGORITHM,
            expiresIn: FILE_UNLOCK_EXPIRATION
        }
    );
}

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

function verifyAccessToken(token) {
    const decoded = verifyToken(token);
    if (decoded.type !== TOKEN_TYPE_ACCESS) {
        throw new UnauthorizedError("Authentication token is invalid");
    }
    return decoded;
}

function verifyFileUnlockToken(token, { userId, fileId }) {
    if (!token) {
        throw new ForbiddenError("File unlock verification required to view or download file content");
    }

    const decoded = verifyToken(token);

    if (decoded.type !== TOKEN_TYPE_FILE_UNLOCK) {
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
    verifyAccessToken,
    verifyFileUnlockToken,
    ALLOWED_ALGORITHM,
    FILE_UNLOCK_EXPIRATION,
    TOKEN_TYPE_ACCESS,
    TOKEN_TYPE_FILE_UNLOCK
};
