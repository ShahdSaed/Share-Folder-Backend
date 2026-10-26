const validator = require("validator");
const { BadRequestError } = require("./errors");

/**
 * Normalize and validate an email address.
 * @param {string} email 
 * @returns {string} normalized email
 */
function normalizeAndValidateEmail(email) {
    if (!email || typeof email !== "string") {
        throw new BadRequestError("Email is required and must be a string");
    }

    const trimmed = email.trim();
    if (!validator.isEmail(trimmed)) {
        throw new BadRequestError("Invalid email format");
    }

    // Normalize email: lowercase, trim whitespace
    const normalized = validator.normalizeEmail(trimmed, {
        all_lowercase: true,
        gmail_remove_dots: false
    });

    return normalized || trimmed.toLowerCase();
}

/**
 * Validate login input payload.
 * @param {object} body 
 * @returns {{ email: string, password: string }}
 */
function validateLoginInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body is missing or malformed");
    }

    const { email, password } = body;

    if (!email || typeof email !== "string" || email.trim().length === 0) {
        throw new BadRequestError("Email is required");
    }

    if (!password || typeof password !== "string" || password.length === 0) {
        throw new BadRequestError("Password is required");
    }

    if (email.length > 255) {
        throw new BadRequestError("Email exceeds maximum allowable length");
    }

    if (password.length > 1024) {
        throw new BadRequestError("Password exceeds maximum allowable length");
    }

    const normalizedEmail = normalizeAndValidateEmail(email);

    return {
        email: normalizedEmail,
        password
    };
}

/**
 * Sanitize and validate pagination parameters.
 * @param {object} query 
 * @returns {{ page: number, limit: number, skip: number }}
 */
function validatePagination(query) {
    let page = parseInt(query.page, 10);
    let limit = parseInt(query.limit, 10);

    if (isNaN(page) || page < 1) {
        page = 1;
    }

    if (isNaN(limit) || limit < 1) {
        limit = 20;
    } else if (limit > 100) {
        limit = 100;
    }

    const skip = (page - 1) * limit;

    return { page, limit, skip };
}

module.exports = {
    normalizeAndValidateEmail,
    validateLoginInput,
    validatePagination
};
