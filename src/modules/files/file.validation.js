const { BadRequestError } = require("../../utils/errors");

function validateUploadInput(file, body) {
    if (!file) {
        throw new BadRequestError("File is required in multipart form data (field name: 'file')");
    }

    if (!body || !body.password) {
        throw new BadRequestError("File protection password is required (field name: 'password')");
    }

    if (typeof body.password !== "string" || body.password.length < 4) {
        throw new BadRequestError("File password must be at least 4 characters long");
    }

    const displayName = body.name && typeof body.name === "string" && body.name.trim().length > 0
        ? body.name.trim()
        : file.originalname;

    return {
        name: displayName,
        password: body.password
    };
}

function validateUpdateFileInput(body) {
    if (!body || typeof body !== "object") {
        throw new BadRequestError("Request body must be a JSON object");
    }

    if (!body.name || typeof body.name !== "string" || body.name.trim().length === 0) {
        throw new BadRequestError("Valid file name is required");
    }

    return {
        name: body.name.trim()
    };
}

function validateFilePasswordInput(body) {
    if (!body || typeof body !== "object" || !body.password) {
        throw new BadRequestError("Password is required in request body");
    }

    if (typeof body.password !== "string" || body.password.length < 4) {
        throw new BadRequestError("Password must be at least 4 characters long");
    }

    return {
        password: body.password
    };
}

module.exports = {
    validateUploadInput,
    validateUpdateFileInput,
    validateFilePasswordInput
};
