const validator = require("validator");
const { BadRequestError } = require("./errors");

const USERNAME_REGEX = /^(?=.{3,20}$)[a-zA-Z][a-zA-Z0-9]*(?:[._][a-zA-Z0-9]+)*$/;

/**
 * Normalize and validate a username.
 * Rules:
 * - 3 to 20 characters
 * - Starts with an English letter
 * - Contains only letters, numbers, underscore _, and dot .
 * - No spaces
 * - Does not end with . or _
 * - No consecutive symbols (no .. or __ or ._ or _.)
 * - Case-insensitive (normalized to lowercase)
 * @param {string} username 
 * @returns {string} normalized lowercase username
 */
function normalizeAndValidateUsername(username) {
    if (!username || typeof username !== "string" || username.trim().length === 0) {
        throw new BadRequestError("Username is required");
    }

    const trimmed = username.trim();
    if (!USERNAME_REGEX.test(trimmed)) {
        throw new BadRequestError(
            "Username must be 3-20 characters, start with an English letter, contain only letters, numbers, dots, or underscores, and cannot end with or contain consecutive symbols"
        );
    }

    return trimmed.toLowerCase();
}

/**
 * Normalize and validate an email address (kept for legacy/optional support).
 * @param {string} email 
 * @returns {string} normalized email
 */
function normalizeAndValidateEmail(email) {
    if (!email || typeof email !== "string" || email.trim().length === 0) {
        throw new BadRequestError("Email is required");
    }

    const trimmed = email.trim();
    if (!validator.isEmail(trimmed)) {
        throw new BadRequestError("Invalid email format");
    }

    const normalized = validator.normalizeEmail(trimmed, {
        all_lowercase: true,
        gmail_remove_dots: false
    });

    return normalized || trimmed.toLowerCase();
}

/**
 * Validate login input payload.
 * Accepts username or email and returns normalized identifier.
 * @param {object} body 
 * @returns {{ username: string, email: string, password: string }}
 */
function validateLoginInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body is missing or malformed");
    }

    const { username, email, password } = body;
    const identifier = username || email;

    if (!identifier || typeof identifier !== "string" || identifier.trim().length === 0) {
        throw new BadRequestError("Username is required");
    }

    if (!password || typeof password !== "string" || password.length === 0) {
        throw new BadRequestError("Password is required");
    }

    if (identifier.length > 255) {
        throw new BadRequestError("Username exceeds maximum allowable length");
    }

    if (password.length > 1024) {
        throw new BadRequestError("Password exceeds maximum allowable length");
    }

    const normalizedUsername = normalizeAndValidateUsername(identifier);

    return {
        username: normalizedUsername,
        email: normalizedUsername,
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
    USERNAME_REGEX,
    normalizeAndValidateUsername,
    normalizeAndValidateEmail,
    validateLoginInput,
    validatePagination
};
