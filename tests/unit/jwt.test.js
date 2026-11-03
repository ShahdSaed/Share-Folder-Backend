const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const jwt = require("jsonwebtoken");
const { signToken, verifyToken, ALLOWED_ALGORITHM, TOKEN_TYPE_ACCESS } = require("../../src/utils/jwt");
const env = require("../../src/config/env");

describe("JWT Utility (HS256)", () => {
    it("should sign a token with HS256 algorithm and required claims", () => {
        const payload = { sub: "user-123", role: "ADMIN" };
        const token = signToken(payload);

        assert.ok(typeof token === "string", "Token must be a string");

        const decodedHeader = jwt.decode(token, { complete: true });
        assert.strictEqual(decodedHeader.header.alg, ALLOWED_ALGORITHM, "Algorithm must be HS256");

        const decoded = verifyToken(token);
        assert.strictEqual(decoded.sub, "user-123");
        assert.strictEqual(decoded.role, "ADMIN");
        assert.strictEqual(decoded.type, TOKEN_TYPE_ACCESS);
        assert.ok(decoded.iat, "iat claim must be present");
        assert.ok(decoded.exp, "exp claim must be present");
    });

    it("should throw UnauthorizedError on expired token", () => {
        const token = signToken({ sub: "user-exp", role: "VIEWER" }, { expiresIn: "0s" });

        assert.throws(
            () => verifyToken(token),
            (err) => err.statusCode === 401 && err.message.includes("expired")
        );
    });

    it("should throw UnauthorizedError on tampered token", () => {
        const token = signToken({ sub: "user-tamper", role: "VIEWER" });
        const tamperedToken = token.slice(0, -5) + "abcde";

        assert.throws(
            () => verifyToken(tamperedToken),
            (err) => err.statusCode === 401
        );
    });

    it("should reject token signed with unauthorized algorithm (e.g. none)", () => {
        // Construct an unsigned token with alg "none"
        const header = Buffer.from(JSON.stringify({ alg: "none", typ: "JWT" })).toString("base64url");
        const body = Buffer.from(JSON.stringify({ sub: "fake-admin", role: "ADMIN" })).toString("base64url");
        const fakeToken = `${header}.${body}.`;

        assert.throws(
            () => verifyToken(fakeToken),
            (err) => err.statusCode === 401
        );
    });
});
