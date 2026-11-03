const { describe, it, afterEach } = require("node:test");
const assert = require("node:assert/strict");
const http = require("node:http");
const express = require("express");
const { parseCorsOrigins } = require("../../src/config/cors-origins");
const { errorHandler } = require("../../src/middlewares/error.middleware");
const {
    createHelmetMiddleware,
    createCorsMiddleware,
    CORS_ALLOWED_HEADERS,
    CORS_ALLOWED_METHODS,
    HSTS_MAX_AGE_SECONDS
} = require("../../src/middlewares/http-security.middleware");

const ALLOWED_A = "http://localhost:4200";
const ALLOWED_B = "http://localhost:5173";
const REJECTED_ORIGIN = "http://unapproved.example";

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

function buildApp({ isProduction = false, origins = [ALLOWED_A, ALLOWED_B] } = {}) {
    const app = express();
    app.use(createHelmetMiddleware({ isProduction }));
    app.use(createCorsMiddleware({ origins }));
    app.use(express.json());
    app.get("/api/health", (req, res) => {
        res.status(200).json({ status: "ok" });
    });
    app.post("/api/auth/login", (req, res) => {
        res.status(200).json({ status: "success" });
    });
    app.use(errorHandler);
    return app;
}

describe("CORS origin parsing", () => {
    it("should return an empty list when CORS_ORIGINS is unset or blank", () => {
        assert.deepStrictEqual(parseCorsOrigins(undefined), []);
        assert.deepStrictEqual(parseCorsOrigins(""), []);
        assert.deepStrictEqual(parseCorsOrigins("  ,  "), []);
    });

    it("should parse, trim, and de-duplicate multiple origins", () => {
        const parsed = parseCorsOrigins(` ${ALLOWED_A}, ${ALLOWED_B}, ${ALLOWED_A} `);
        assert.deepStrictEqual(parsed, [ALLOWED_A, ALLOWED_B]);
    });

    it("should normalize origins via URL.origin", () => {
        const parsed = parseCorsOrigins("http://localhost:4200/");
        assert.deepStrictEqual(parsed, [ALLOWED_A]);
    });

    it("should reject wildcard origins", () => {
        assert.throws(() => parseCorsOrigins("*"), /wildcard/);
        assert.throws(() => parseCorsOrigins(`${ALLOWED_A},*`), /wildcard/);
    });

    it("should reject invalid or non-http origins", () => {
        assert.throws(() => parseCorsOrigins("not-a-url"), /Invalid CORS origin/);
        assert.throws(() => parseCorsOrigins("ftp://localhost:21"), /http or https/);
        assert.throws(() => parseCorsOrigins("http://localhost:4200/app"), /origins only/);
    });
});

describe("Helmet security headers", () => {
    let harness;

    afterEach(async () => {
        if (harness) {
            await harness.close();
            harness = null;
        }
    });

    it("should send recommended security headers without disabling core protections", async () => {
        harness = await listen(buildApp({ isProduction: false }));
        const res = await fetch(`${harness.baseUrl}/api/health`);
        assert.strictEqual(res.status, 200);

        assert.strictEqual(res.headers.get("x-content-type-options"), "nosniff");
        assert.strictEqual(res.headers.get("x-frame-options"), "DENY");
        assert.ok(res.headers.get("content-security-policy"));
        assert.ok(res.headers.get("content-security-policy").includes("default-src 'none'"));
        assert.ok(res.headers.get("content-security-policy").includes("frame-ancestors 'none'"));
        assert.strictEqual(res.headers.get("cross-origin-resource-policy"), "cross-origin");
        assert.ok(res.headers.get("x-dns-prefetch-control"));
        assert.ok(res.headers.get("referrer-policy"));
        assert.equal(res.headers.get("strict-transport-security"), null);
    });

    it("should enable HSTS only when configured for production", async () => {
        harness = await listen(buildApp({ isProduction: true }));
        const res = await fetch(`${harness.baseUrl}/api/health`);
        assert.strictEqual(res.status, 200);

        const hsts = res.headers.get("strict-transport-security");
        assert.ok(hsts);
        assert.ok(hsts.includes(`max-age=${HSTS_MAX_AGE_SECONDS}`));
        assert.ok(hsts.toLowerCase().includes("includesubdomains"));
    });
});

describe("Secure CORS configuration", () => {
    let harness;

    afterEach(async () => {
        if (harness) {
            await harness.close();
            harness = null;
        }
    });

    it("should allow an approved origin and echo it in CORS headers", async () => {
        harness = await listen(buildApp());
        const res = await fetch(`${harness.baseUrl}/api/health`, {
            headers: { Origin: ALLOWED_A }
        });

        assert.strictEqual(res.status, 200);
        assert.strictEqual(res.headers.get("access-control-allow-origin"), ALLOWED_A);
        assert.notEqual(res.headers.get("access-control-allow-origin"), "*");
        assert.strictEqual(res.headers.get("access-control-allow-credentials"), "true");
    });

    it("should reject an unapproved origin", async () => {
        harness = await listen(buildApp());
        const res = await fetch(`${harness.baseUrl}/api/health`, {
            headers: { Origin: REJECTED_ORIGIN }
        });

        assert.strictEqual(res.status, 403);
        const body = await res.json();
        assert.strictEqual(body.status, "error");
        assert.strictEqual(body.code, "FORBIDDEN");
        assert.equal(res.headers.get("access-control-allow-origin"), null);
    });

    it("should allow requests that have no Origin header", async () => {
        harness = await listen(buildApp());
        const res = await fetch(`${harness.baseUrl}/api/health`);

        assert.strictEqual(res.status, 200);
        assert.notEqual(res.headers.get("access-control-allow-origin"), "*");
    });

    it("should allow each origin from a multi-origin allowlist", async () => {
        harness = await listen(buildApp({ origins: [ALLOWED_A, ALLOWED_B] }));

        const first = await fetch(`${harness.baseUrl}/api/health`, {
            headers: { Origin: ALLOWED_A }
        });
        const second = await fetch(`${harness.baseUrl}/api/health`, {
            headers: { Origin: ALLOWED_B }
        });

        assert.strictEqual(first.status, 200);
        assert.strictEqual(first.headers.get("access-control-allow-origin"), ALLOWED_A);
        assert.strictEqual(second.status, 200);
        assert.strictEqual(second.headers.get("access-control-allow-origin"), ALLOWED_B);
    });

    it("should handle CORS preflight and allow Authorization and Content-Type", async () => {
        harness = await listen(buildApp());
        const res = await fetch(`${harness.baseUrl}/api/auth/login`, {
            method: "OPTIONS",
            headers: {
                Origin: ALLOWED_A,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type, Authorization"
            }
        });

        assert.strictEqual(res.status, 204);
        assert.strictEqual(res.headers.get("access-control-allow-origin"), ALLOWED_A);
        assert.strictEqual(res.headers.get("access-control-allow-credentials"), "true");

        const allowHeaders = (res.headers.get("access-control-allow-headers") || "").toLowerCase();
        assert.ok(allowHeaders.includes("content-type"));
        assert.ok(allowHeaders.includes("authorization"));
        for (const header of CORS_ALLOWED_HEADERS) {
            assert.ok(allowHeaders.includes(header.toLowerCase()));
        }

        const allowMethods = (res.headers.get("access-control-allow-methods") || "").toUpperCase();
        for (const method of CORS_ALLOWED_METHODS) {
            assert.ok(allowMethods.includes(method));
        }
    });

    it("should reject preflight from an unapproved origin", async () => {
        harness = await listen(buildApp());
        const res = await fetch(`${harness.baseUrl}/api/auth/login`, {
            method: "OPTIONS",
            headers: {
                Origin: REJECTED_ORIGIN,
                "Access-Control-Request-Method": "POST"
            }
        });

        assert.strictEqual(res.status, 403);
        const body = await res.json();
        assert.strictEqual(body.code, "FORBIDDEN");
    });
});
