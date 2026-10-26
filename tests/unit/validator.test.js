const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
    normalizeAndValidateEmail,
    validateLoginInput,
    validatePagination
} = require("../../src/utils/validator");

describe("Validator Utilities", () => {
    describe("Email Normalization and Validation", () => {
        it("should normalize email by trimming and converting to lowercase", () => {
            const input = "  Admin.User@Company.COM  ";
            const result = normalizeAndValidateEmail(input);
            assert.strictEqual(result, "admin.user@company.com");
        });

        it("should throw BadRequestError on invalid email format", () => {
            assert.throws(
                () => normalizeAndValidateEmail("not-an-email"),
                (err) => err.statusCode === 400 && err.message.includes("format")
            );
        });

        it("should throw BadRequestError on empty email", () => {
            assert.throws(
                () => normalizeAndValidateEmail(""),
                (err) => err.statusCode === 400
            );
        });
    });

    describe("Login Input Validation", () => {
        it("should accept valid credentials and return normalized email", () => {
            const input = {
                email: " User@Domain.com ",
                password: "MySecurePassword123"
            };
            const result = validateLoginInput(input);
            assert.strictEqual(result.email, "user@domain.com");
            assert.strictEqual(result.password, "MySecurePassword123");
        });

        it("should throw BadRequestError when email is missing", () => {
            assert.throws(
                () => validateLoginInput({ password: "some-password" }),
                (err) => err.statusCode === 400 && err.message.includes("Email is required")
            );
        });

        it("should throw BadRequestError when password is missing", () => {
            assert.throws(
                () => validateLoginInput({ email: "user@domain.com" }),
                (err) => err.statusCode === 400 && err.message.includes("Password is required")
            );
        });

        it("should throw BadRequestError on non-object payload", () => {
            assert.throws(
                () => validateLoginInput(null),
                (err) => err.statusCode === 400
            );
        });
    });

    describe("Pagination Validation", () => {
        it("should provide safe defaults when query is empty", () => {
            const result = validatePagination({});
            assert.strictEqual(result.page, 1);
            assert.strictEqual(result.limit, 20);
            assert.strictEqual(result.skip, 0);
        });

        it("should clamp limit to maximum 100", () => {
            const result = validatePagination({ page: "2", limit: "500" });
            assert.strictEqual(result.page, 2);
            assert.strictEqual(result.limit, 100);
            assert.strictEqual(result.skip, 100);
        });
    });
});
