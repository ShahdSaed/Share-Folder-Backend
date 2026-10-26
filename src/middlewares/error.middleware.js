const { AppError } = require("../utils/errors");
const env = require("../config/env");

/**
 * Centralized error handling middleware.
 */
function errorHandler(err, req, res, next) {
    // 1. Handle JSON parse errors from body-parser
    if (err instanceof SyntaxError && err.status === 400 && "body" in err) {
        return res.status(400).json({
            status: "error",
            code: "INVALID_JSON",
            message: "Malformed JSON in request body"
        });
    }

    // 2. Handle known operational AppError
    if (err instanceof AppError) {
        const response = {
            status: "error",
            code: err.code,
            message: err.message
        };

        if (err.details) {
            response.details = err.details;
        }

        return res.status(err.statusCode).json(response);
    }

    // 3. Handle unexpected / internal errors
    console.error("[ServerError] Unexpected error caught in error middleware:", {
        message: err.message,
        stack: env.nodeEnv === "development" ? err.stack : undefined
    });

    const isProduction = env.nodeEnv === "production";

    return res.status(500).json({
        status: "error",
        code: "INTERNAL_SERVER_ERROR",
        message: isProduction
            ? "An unexpected internal server error occurred"
            : err.message || "An unexpected internal server error occurred"
    });
}

/**
 * 404 Not Found handler for undefined routes.
 */
function notFoundHandler(req, res, next) {
    res.status(404).json({
        status: "error",
        code: "ROUTE_NOT_FOUND",
        message: `Endpoint ${req.method} ${req.originalUrl} not found`
    });
}

module.exports = {
    errorHandler,
    notFoundHandler
};
