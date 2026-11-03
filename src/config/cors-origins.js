/**
 * Parse and validate CORS_ORIGINS (comma-separated origin list).
 * Wildcards and non-http(s) values are rejected.
 * @param {string | undefined | null} raw
 * @returns {string[]}
 */
function parseCorsOrigins(raw) {
    if (raw == null || String(raw).trim() === "") {
        return [];
    }

    const origins = [];

    for (const part of String(raw).split(",")) {
        const trimmed = part.trim();
        if (!trimmed) {
            continue;
        }

        if (trimmed === "*") {
            throw new Error(
                "[FATAL] CORS_ORIGINS must not include a wildcard (*). List explicit frontend origins instead."
            );
        }

        let parsed;
        try {
            parsed = new URL(trimmed);
        } catch {
            throw new Error(
                "[FATAL] Invalid CORS origin in CORS_ORIGINS. Each entry must be a full origin (scheme + host, optional port)."
            );
        }

        if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
            throw new Error("[FATAL] CORS origins must use the http or https scheme.");
        }

        if (parsed.username || parsed.password) {
            throw new Error("[FATAL] CORS origins must not include credentials.");
        }

        if ((parsed.pathname && parsed.pathname !== "/") || parsed.search || parsed.hash) {
            throw new Error("[FATAL] CORS_ORIGINS entries must be origins only (no path, query, or fragment).");
        }

        origins.push(parsed.origin);
    }

    return [...new Set(origins)];
}

module.exports = {
    parseCorsOrigins
};
