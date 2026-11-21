const { BadRequestError } = require("../../utils/errors");

const MIN_FILE_PASSWORD_LENGTH = 8;
const MAX_FILE_PASSWORD_LENGTH = 128;
const MAX_FILE_NAME_LENGTH = 255;
const MAX_FILE_DESCRIPTION_LENGTH = 1000;

/**
 * Validate a file protection password string.
 * Enforces 8 to 128 characters, string type, and rejection of empty/whitespace passwords.
 * @param {any} password 
 * @param {string} fieldName 
 * @returns {string}
 */
function validateFilePassword(password, fieldName = "File password") {
    if (password === undefined || password === null) {
        throw new BadRequestError(`${fieldName} is required`);
    }

    if (typeof password !== "string") {
        throw new BadRequestError(`${fieldName} must be a string`);
    }

    if (password.length === 0) {
        throw new BadRequestError(`${fieldName} cannot be empty`);
    }

    if (password.length < MIN_FILE_PASSWORD_LENGTH || password.length > MAX_FILE_PASSWORD_LENGTH) {
        throw new BadRequestError(
            `${fieldName} must be between ${MIN_FILE_PASSWORD_LENGTH} and ${MAX_FILE_PASSWORD_LENGTH} characters long`
        );
    }

    return password;
}

/**
 * Validate and trim a user-provided file display name.
 * @param {any} name 
 * @returns {string}
 */
function validateDisplayName(name) {
    if (typeof name !== "string") {
        throw new BadRequestError("File name must be a string");
    }

    const trimmed = name.trim();
    if (trimmed.length === 0) {
        throw new BadRequestError("File name cannot be empty");
    }

    if (trimmed.length > MAX_FILE_NAME_LENGTH) {
        throw new BadRequestError(`File name must not exceed ${MAX_FILE_NAME_LENGTH} characters`);
    }

    return trimmed;
}

/**
 * Validate an optional file description.
 * Returns undefined when not provided, null when cleared (empty), or the trimmed string.
 * @param {any} description
 * @returns {string|null|undefined}
 */
function validateDescription(description) {
    if (description === undefined) {
        return undefined;
    }
    if (description === null) {
        return null;
    }
    if (typeof description !== "string") {
        throw new BadRequestError("File description must be a string");
    }

    const trimmed = description.trim();
    if (trimmed.length === 0) {
        return null;
    }
    if (trimmed.length > MAX_FILE_DESCRIPTION_LENGTH) {
        throw new BadRequestError(`File description must not exceed ${MAX_FILE_DESCRIPTION_LENGTH} characters`);
    }
    return trimmed;
}

function validateUploadInput(file, body) {
    if (!file) {
        throw new BadRequestError("File is required in multipart form data (field name: 'file')");
    }

    if (!body || typeof body !== "object") {
        throw new BadRequestError("File protection password is required (field name: 'password')");
    }

    if (!body.password) {
        throw new BadRequestError("File protection password is required (field name: 'password')");
    }

    const password = validateFilePassword(body.password, "File password");

    let displayName;
    if (body.name !== undefined && body.name !== null) {
        displayName = validateDisplayName(body.name);
    } else {
        const original = typeof file.originalname === "string" ? file.originalname.trim() : "";
        if (!original) {
            throw new BadRequestError("Valid original filename is required");
        }
        displayName = original.length > MAX_FILE_NAME_LENGTH
            ? original.slice(0, MAX_FILE_NAME_LENGTH)
            : original;
    }

    return {
        name: displayName,
        description: validateDescription(body.description) ?? null,
        password
    };
}

function validateUpdateFileInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body must be a JSON object");
    }

    const updates = {};

    if (body.name !== undefined && body.name !== null) {
        updates.name = validateDisplayName(body.name);
    }

    const description = validateDescription(body.description);
    if (description !== undefined) {
        updates.description = description;
    }

    if (Object.keys(updates).length === 0) {
        throw new BadRequestError("Valid file name or description is required");
    }

    return updates;
}

function validateFilePasswordInput(body) {
    if (!body || typeof body !== "object" || !body.password) {
        throw new BadRequestError("Password is required in request body");
    }

    const password = validateFilePassword(body.password, "Password");

    return {
        password
    };
}

module.exports = {
    validateUploadInput,
    validateUpdateFileInput,
    validateFilePasswordInput,
    validateFilePassword,
    validateDisplayName,
    validateDescription,
    MIN_FILE_PASSWORD_LENGTH,
    MAX_FILE_PASSWORD_LENGTH,
    MAX_FILE_NAME_LENGTH,
    MAX_FILE_DESCRIPTION_LENGTH
};
