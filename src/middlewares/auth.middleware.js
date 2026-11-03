const { verifyAccessToken } = require("../utils/jwt");
const userRepository = require("../modules/users/user.repository");
const { UnauthorizedError } = require("../utils/errors");

/**
 * Middleware to authenticate requests using JWT Bearer token.
 * Validates token and checks current user status in the database.
 */
async function authenticate(req, res, next) {
    try {
        const authHeader = req.headers.authorization;

        if (!authHeader) {
            throw new UnauthorizedError("Authorization header is missing");
        }

        const [scheme, token] = authHeader.split(" ");

        if (scheme !== "Bearer" || !token) {
            throw new UnauthorizedError("Authorization format must be: Bearer <token>");
        }

        // 1. Verify token signature and expiration
        const decoded = verifyAccessToken(token);

        // 2. Load current user from database as source of truth
        const user = await userRepository.findById(decoded.sub);

        if (!user) {
            throw new UnauthorizedError("User associated with this token no longer exists");
        }

        if (!user.isActive) {
            throw new UnauthorizedError("User account has been deactivated");
        }

        // 3. Attach trusted user object to request
        req.user = user;

        next();
    } catch (error) {
        next(error);
    }
}

module.exports = {
    authenticate
};
