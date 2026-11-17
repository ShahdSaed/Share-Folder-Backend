const { describe, it } = require("node:test");
const assert = require("node:assert/strict");
const {
    normalizeAndValidateUsername,
    normalizeAndValidateEmail,
    validateLoginInput,
    validatePagination
} = require("../../src/utils/validator");

describe("Validator Utilities", () => {
    describe("Username Normalization and Validation", () => {
        it("should accept valid usernames and normalize to lowercase", () => {
            assert.strictEqual(normalizeAndValidateUsername("John.Doe"), "john.doe");
            assert.strictEqual(normalizeAndValidateUsername("  admin_99  "), "admin_99");
            assert.strictEqual(normalizeAndValidateUsername("usr"), "usr");
            assert.strictEqual(normalizeAndValidateUsername("a_b_c_d_e_1_2_3_4_5"), "a_b_c_d_e_1_2_3_4_5");
        });

        it("should reject usernames shorter than 3 characters", () => {
            assert.throws(() => normalizeAndValidateUsername("ab"), (err) => err.statusCode === 400);
        });

        it("should reject usernames longer than 20 characters", () => {
            assert.throws(() => normalizeAndValidateUsername("a12345678901234567890"), (err) => err.statusCode === 400);
        });

        it("should reject usernames that do not start with an English letter", () => {
            assert.throws(() => normalizeAndValidateUsername("1user"), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername("_user"), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername(".user"), (err) => err.statusCode === 400);
        });

        it("should reject usernames with spaces", () => {
            assert.throws(() => normalizeAndValidateUsername("john doe"), (err) => err.statusCode === 400);
        });

        it("should reject usernames that end with dot or underscore", () => {
            assert.throws(() => normalizeAndValidateUsername("user_"), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername("user."), (err) => err.statusCode === 400);
        });

        it("should reject usernames with consecutive symbols", () => {
            assert.throws(() => normalizeAndValidateUsername("user..name"), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername("user__name"), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername("user._name"), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername("user_.name"), (err) => err.statusCode === 400);
        });

        it("should reject empty or missing username", () => {
            assert.throws(() => normalizeAndValidateUsername(""), (err) => err.statusCode === 400);
            assert.throws(() => normalizeAndValidateUsername(null), (err) => err.statusCode === 400);
        });
    });

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
        it("should accept valid credentials and return normalized username", () => {
            const input = {
                username: " John.Doe ",
                password: "MySecurePassword123"
            };
            const result = validateLoginInput(input);
            assert.strictEqual(result.username, "john.doe");
            assert.strictEqual(result.password, "MySecurePassword123");
        });

        it("should throw BadRequestError when identifier is missing", () => {
            assert.throws(
                () => validateLoginInput({ password: "some-password" }),
                (err) => err.statusCode === 400 && err.message.includes("required")
            );
        });

        it("should throw BadRequestError when password is missing", () => {
            assert.throws(
                () => validateLoginInput({ username: "john.doe" }),
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
            const result = validatePagination({ limit: "500" });
            assert.strictEqual(result.limit, 100);
        });
    });
});
