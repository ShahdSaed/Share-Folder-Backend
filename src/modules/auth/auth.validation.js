const { BadRequestError } = require("../../utils/errors");

function validateChangePasswordInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body must be a JSON object");
    }

    const { currentPassword, newPassword } = body;

    if (!currentPassword || typeof currentPassword !== "string") {
        throw new BadRequestError("currentPassword is required");
    }

    if (!newPassword || typeof newPassword !== "string") {
        throw new BadRequestError("newPassword is required");
    }

    if (newPassword.length < 8) {
        throw new BadRequestError("New password must be at least 8 characters long");
    }

    if (newPassword.length > 1024) {
        throw new BadRequestError("New password exceeds maximum allowable length");
    }

    return { currentPassword, newPassword };
}

module.exports = {
    validateChangePasswordInput
};
