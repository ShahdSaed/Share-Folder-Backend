const crypto = require("crypto");

function generateRefreshToken() {
    return crypto.randomBytes(32).toString("base64url");
}

function hashRefreshToken(rawToken) {
    if (!rawToken || typeof rawToken !== "string") {
        throw new Error("Refresh token must be a non-empty string");
    }
    return crypto.createHash("sha256").update(rawToken, "utf8").digest("hex");
}

module.exports = {
    generateRefreshToken,
    hashRefreshToken
};
