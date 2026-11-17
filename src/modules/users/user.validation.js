const { BadRequestError } = require("../../utils/errors");
const { normalizeAndValidateUsername } = require("../../utils/validator");

const VALID_ROLES = ["ADMIN", "VIEWER"];

function validateCreateUserInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body must be a JSON object");
    }

    const { name, username, email, password, role } = body;

    if (!name || typeof name !== "string" || name.trim().length === 0) {
        throw new BadRequestError("Full name is required");
    }

    const identifier = username || email;
    if (!identifier) {
        throw new BadRequestError("Username is required");
    }

    const normalizedUsername = normalizeAndValidateUsername(identifier);

    if (!password || typeof password !== "string" || password.length < 8) {
        throw new BadRequestError("Password must be at least 8 characters long");
    }

    const userRole = role ? role.toUpperCase() : "VIEWER";
    if (!VALID_ROLES.includes(userRole)) {
        throw new BadRequestError(`Invalid role. Allowed roles: ${VALID_ROLES.join(", ")}`);
    }

    return {
        name: name.trim(),
        username: normalizedUsername,
        password,
        role: userRole
    };
}

function validateUpdateUserInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body must be a JSON object");
    }

    const updates = {};

    if (body.name !== undefined) {
        if (typeof body.name !== "string" || body.name.trim().length === 0) {
            throw new BadRequestError("Name cannot be empty");
        }
        updates.name = body.name.trim();
    }

    if (body.username !== undefined || body.email !== undefined) {
        const identifier = body.username || body.email;
        updates.username = normalizeAndValidateUsername(identifier);
    }

    if (body.role !== undefined) {
        const role = body.role.toUpperCase();
        if (!VALID_ROLES.includes(role)) {
            throw new BadRequestError(`Invalid role. Allowed roles: ${VALID_ROLES.join(", ")}`);
        }
        updates.role = role;
    }

    if (body.isActive !== undefined) {
        if (typeof body.isActive !== "boolean") {
            throw new BadRequestError("isActive must be a boolean");
        }
        updates.isActive = body.isActive;
    }

    if (Object.keys(updates).length === 0) {
        throw new BadRequestError("At least one valid field (name, username, role, isActive) must be provided to update");
    }

    return updates;
}

function validateUpdateStatusInput(body) {
    if (!body || typeof body !== "object" || body.isActive === undefined) {
        throw new BadRequestError("isActive (boolean) is required in request body");
    }

    if (typeof body.isActive !== "boolean") {
        throw new BadRequestError("isActive must be a boolean value");
    }

    return { isActive: body.isActive };
}

function validateResetPasswordInput(body) {
    if (!body || typeof body !== "object" || !body.password) {
        throw new BadRequestError("New password is required");
    }

    if (typeof body.password !== "string" || body.password.length < 8) {
        throw new BadRequestError("New password must be at least 8 characters long");
    }

    return { password: body.password };
}

module.exports = {
    validateCreateUserInput,
    validateUpdateUserInput,
    validateUpdateStatusInput,
    validateResetPasswordInput
};
