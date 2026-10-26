const argon2 = require("argon2");

/**
 * Hash a plain text password using Argon2id with secure parameters.
 * @param {string} plainPassword 
 * @returns {Promise<string>}
 */
async function hashPassword(plainPassword) {
    if (!plainPassword || typeof plainPassword !== "string") {
        throw new Error("Password must be a non-empty string");
    }

    return await argon2.hash(plainPassword, {
        type: argon2.argon2id,
        memoryCost: 65536, // 64 MB
        timeCost: 3,
        parallelism: 4
    });
}

/**
 * Verify a plain text password against an Argon2id hash.
 * @param {string} hash 
 * @param {string} plainPassword 
 * @returns {Promise<boolean>}
 */
async function verifyPassword(hash, plainPassword) {
    if (!hash || !plainPassword || typeof hash !== "string" || typeof plainPassword !== "string") {
        return false;
    }

    try {
        return await argon2.verify(hash, plainPassword);
    } catch {
        return false;
    }
}

module.exports = {
    hashPassword,
    verifyPassword
};
