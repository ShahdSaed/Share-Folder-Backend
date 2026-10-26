const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const { hashPassword, verifyPassword } = require("../../src/utils/password");

describe("Password Utility (Argon2id)", () => {
    it("should generate a valid Argon2id hash", async () => {
        const password = "SuperSecretPassword123!";
        const hash = await hashPassword(password);

        assert.ok(hash.startsWith("$argon2id$"), "Hash must be in argon2id format");
        assert.notStrictEqual(hash, password, "Hash must never match plain password");
    });

    it("should verify correct password successfully", async () => {
        const password = "TestPassword456$";
        const hash = await hashPassword(password);

        const isValid = await verifyPassword(hash, password);
        assert.strictEqual(isValid, true, "Valid password should verify as true");
    });

    it("should reject incorrect password", async () => {
        const password = "CorrectPassword1!";
        const hash = await hashPassword(password);

        const isValid = await verifyPassword(hash, "WrongPassword1!");
        assert.strictEqual(isValid, false, "Incorrect password should verify as false");
    });

    it("should return false safely when given empty or null inputs", async () => {
        assert.strictEqual(await verifyPassword(null, "password"), false);
        assert.strictEqual(await verifyPassword("somehash", null), false);
        assert.strictEqual(await verifyPassword("", ""), false);
    });
});
