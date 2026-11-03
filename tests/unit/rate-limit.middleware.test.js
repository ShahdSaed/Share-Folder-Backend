const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");
const {
    createLoginRateLimiter,
    createFilePasswordRateLimiter,
    loginRateLimiter,
    filePasswordRateLimiter,
    LOGIN_RATE_LIMIT_MAX,
    FILE_PASSWORD_RATE_LIMIT_MAX,
    LOGIN_RATE_LIMIT_MESSAGE,
    FILE_PASSWORD_RATE_LIMIT_MESSAGE
} = require("../../src/middlewares/rate-limit.middleware");
const { authenticate } = require("../../src/middlewares/auth.middleware");
const { errorHandler } = require("../../src/middlewares/error.middleware");
const { UnauthorizedError } = require("../../src/utils/errors");

async function listen(app) {
    const server = http.createServer(app);
    await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
    const { port } = server.address();
    return {
        server,
        baseUrl: `http://127.0.0.1:${port}`,
        close: () => new Promise((resolve) => server.close(resolve))
    };
}

async function postJson(baseUrl, path, body, headers = {}) {
    const res = await fetch(`${baseUrl}${path}`, {
        method: "POST",
        headers: { "Content-Type": "application/json", ...headers },
        body: JSON.stringify(body)
    });
    const data = await res.json();
    return { status: res.status, data };
}

function stubAuthenticate(req, res, next) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith("Bearer ")) {
        return next(new UnauthorizedError("Authorization header is missing"));
    }
    req.user = {
        id: header.slice("Bearer ".length),
        role: "VIEWER",
        isActive: true
    };
    next();
}

describe("Rate limit middleware exports", () => {
    it("should export reusable limiter middleware and factories", () => {
        assert.strictEqual(typeof loginRateLimiter, "function");
        assert.strictEqual(typeof filePasswordRateLimiter, "function");
        assert.strictEqual(typeof createLoginRateLimiter, "function");
        assert.strictEqual(typeof createFilePasswordRateLimiter, "function");
        assert.strictEqual(LOGIN_RATE_LIMIT_MAX, 5);
        assert.strictEqual(FILE_PASSWORD_RATE_LIMIT_MAX, 5);
    });
});

describe("Login rate limiter", () => {
    let harness;

    function buildLoginApp(overrides = {}) {
        const app = express();
        app.use(express.json());
        app.post(
            "/login",
            createLoginRateLimiter({
                windowMs: 60_000,
                limit: LOGIN_RATE_LIMIT_MAX,
                ...overrides
            }),
            (req, res, next) => {
                if (req.body && req.body.invalid) {
                    return res.status(400).json({
                        status: "error",
                        code: "BAD_REQUEST",
                        message: "Invalid input"
                    });
                }
                if (req.body && req.body.fail) {
                    return next(new UnauthorizedError("Invalid email or password"));
                }
                return res.status(200).json({
                    status: "success",
                    message: "Authentication successful"
                });
            }
        );
        app.use(errorHandler);
        return app;
    }

    afterEach(async () => {
        if (harness) {
            await harness.close();
            harness = null;
        }
    });

    it("should allow requests below the failed-attempt limit", async () => {
        harness = await listen(buildLoginApp());

        for (let i = 0; i < LOGIN_RATE_LIMIT_MAX; i++) {
            const res = await postJson(harness.baseUrl, "/login", { fail: true });
            assert.strictEqual(res.status, 401);
            assert.strictEqual(res.data.code, "UNAUTHORIZED");
        }
    });

    it("should count failed login attempts thrown by the controller", async () => {
        harness = await listen(buildLoginApp());

        for (let i = 0; i < LOGIN_RATE_LIMIT_MAX; i++) {
            const res = await postJson(harness.baseUrl, "/login", { fail: true });
            assert.strictEqual(res.status, 401);
        }

        const blocked = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(blocked.status, 429);
        assert.strictEqual(blocked.data.status, "error");
        assert.strictEqual(blocked.data.code, "TOO_MANY_REQUESTS");
        assert.strictEqual(blocked.data.message, LOGIN_RATE_LIMIT_MESSAGE);
        assert.strictEqual(blocked.data.message.includes("password"), false);
        assert.strictEqual(blocked.data.message.includes("token"), false);
    });

    it("should not count successful login attempts toward the limit", async () => {
        harness = await listen(buildLoginApp());

        for (let i = 0; i < LOGIN_RATE_LIMIT_MAX; i++) {
            const success = await postJson(harness.baseUrl, "/login", { fail: false });
            assert.strictEqual(success.status, 200);
        }

        const stillAllowed = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(stillAllowed.status, 401);

        for (let i = 1; i < LOGIN_RATE_LIMIT_MAX; i++) {
            const failed = await postJson(harness.baseUrl, "/login", { fail: true });
            assert.strictEqual(failed.status, 401);
        }

        const blocked = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(blocked.status, 429);
        assert.strictEqual(blocked.data.code, "TOO_MANY_REQUESTS");
    });

    it("should not count non-authentication validation errors toward the limit", async () => {
        harness = await listen(buildLoginApp());

        for (let i = 0; i < LOGIN_RATE_LIMIT_MAX + 2; i++) {
            const res = await postJson(harness.baseUrl, "/login", { invalid: true });
            assert.strictEqual(res.status, 400);
        }

        const authFailure = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(authFailure.status, 401);
    });

    it("should return 429 on the failed attempt after the configured limit", async () => {
        harness = await listen(buildLoginApp());

        for (let i = 0; i < LOGIN_RATE_LIMIT_MAX; i++) {
            const res = await postJson(harness.baseUrl, "/login", { fail: true });
            assert.strictEqual(res.status, 401);
        }

        const blocked = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(blocked.status, 429);
    });

    it("should reset after the configured window without waiting 15 minutes", async () => {
        harness = await listen(buildLoginApp({ windowMs: 80 }));

        for (let i = 0; i < LOGIN_RATE_LIMIT_MAX; i++) {
            const res = await postJson(harness.baseUrl, "/login", { fail: true });
            assert.strictEqual(res.status, 401);
        }

        const blocked = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(blocked.status, 429);

        await new Promise((resolve) => setTimeout(resolve, 120));

        const afterReset = await postJson(harness.baseUrl, "/login", { fail: true });
        assert.strictEqual(afterReset.status, 401);
    });
});

describe("File password verification rate limiter", () => {
    let harness;

    function buildFilePasswordApp({ useRealAuth = false, limiterOverrides = {} } = {}) {
        const app = express();
        app.use(express.json());
        app.post(
            "/files/:id/verify-password",
            useRealAuth ? authenticate : stubAuthenticate,
            createFilePasswordRateLimiter({
                windowMs: 60_000,
                limit: FILE_PASSWORD_RATE_LIMIT_MAX,
                ...limiterOverrides
            }),
            (req, res) => {
                res.status(200).json({
                    status: "success",
                    message: "Password verified. File unlocked for viewing."
                });
            }
        );
        app.use(errorHandler);
        return app;
    }

    afterEach(async () => {
        if (harness) {
            await harness.close();
            harness = null;
        }
    });

    it("should allow authenticated users within the configured limit", async () => {
        harness = await listen(buildFilePasswordApp());

        for (let i = 0; i < FILE_PASSWORD_RATE_LIMIT_MAX; i++) {
            const res = await postJson(
                harness.baseUrl,
                "/files/file-1/verify-password",
                { password: "x" },
                { Authorization: "Bearer user-1" }
            );
            assert.strictEqual(res.status, 200);
        }
    });

    it("should return 429 after excessive attempts for the same user and file", async () => {
        harness = await listen(buildFilePasswordApp());

        for (let i = 0; i < FILE_PASSWORD_RATE_LIMIT_MAX; i++) {
            const res = await postJson(
                harness.baseUrl,
                "/files/file-1/verify-password",
                { password: "x" },
                { Authorization: "Bearer user-1" }
            );
            assert.strictEqual(res.status, 200);
        }

        const blocked = await postJson(
            harness.baseUrl,
            "/files/file-1/verify-password",
            { password: "x" },
            { Authorization: "Bearer user-1" }
        );
        assert.strictEqual(blocked.status, 429);
        assert.strictEqual(blocked.data.status, "error");
        assert.strictEqual(blocked.data.code, "TOO_MANY_REQUESTS");
        assert.strictEqual(blocked.data.message, FILE_PASSWORD_RATE_LIMIT_MESSAGE);
    });

    it("should keep independent limits for different users", async () => {
        harness = await listen(buildFilePasswordApp());

        for (let i = 0; i < FILE_PASSWORD_RATE_LIMIT_MAX; i++) {
            const res = await postJson(
                harness.baseUrl,
                "/files/file-1/verify-password",
                { password: "x" },
                { Authorization: "Bearer user-a" }
            );
            assert.strictEqual(res.status, 200);
        }

        const blockedA = await postJson(
            harness.baseUrl,
            "/files/file-1/verify-password",
            { password: "x" },
            { Authorization: "Bearer user-a" }
        );
        assert.strictEqual(blockedA.status, 429);

        const userB = await postJson(
            harness.baseUrl,
            "/files/file-1/verify-password",
            { password: "x" },
            { Authorization: "Bearer user-b" }
        );
        assert.strictEqual(userB.status, 200);
    });

    it("should keep independent limits for different files of the same user", async () => {
        harness = await listen(buildFilePasswordApp());

        for (let i = 0; i < FILE_PASSWORD_RATE_LIMIT_MAX; i++) {
            const res = await postJson(
                harness.baseUrl,
                "/files/file-1/verify-password",
                { password: "x" },
                { Authorization: "Bearer user-1" }
            );
            assert.strictEqual(res.status, 200);
        }

        const blockedFile1 = await postJson(
            harness.baseUrl,
            "/files/file-1/verify-password",
            { password: "x" },
            { Authorization: "Bearer user-1" }
        );
        assert.strictEqual(blockedFile1.status, 429);

        const file2 = await postJson(
            harness.baseUrl,
            "/files/file-2/verify-password",
            { password: "x" },
            { Authorization: "Bearer user-1" }
        );
        assert.strictEqual(file2.status, 200);
    });

    it("should reject unauthenticated requests before the limiter", async () => {
        harness = await listen(buildFilePasswordApp({ useRealAuth: true }));

        for (let i = 0; i < FILE_PASSWORD_RATE_LIMIT_MAX + 3; i++) {
            const res = await postJson(
                harness.baseUrl,
                "/files/file-1/verify-password",
                { password: "x" }
            );
            assert.strictEqual(res.status, 401);
            assert.strictEqual(res.data.code, "UNAUTHORIZED");
        }
    });
});
