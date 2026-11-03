const env = require("../config/env");
const { ForbiddenError } = require("../utils/errors");

/**
 * Cookie-authenticated POSTs must come from an allowlisted Origin when a browser
 * sends the Origin header. Requests without Origin (Postman, server-to-server) are allowed.
 */
function requireAllowedOrigin(req, res, next) {
    try {
        const origin = req.headers.origin;
        if (!origin) {
            return next();
        }

        if (!env.cors.origins.includes(origin)) {
            throw new ForbiddenError("Cross-origin request was rejected");
        }

        next();
    } catch (error) {
        next(error);
    }
}

module.exports = {
    requireAllowedOrigin
};
