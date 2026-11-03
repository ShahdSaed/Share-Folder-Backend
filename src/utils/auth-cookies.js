const env = require("../config/env");

function refreshCookieOptions() {
    return {
        httpOnly: true,
        secure: env.cookie.secure,
        sameSite: env.cookie.sameSite,
        path: env.cookie.path,
        maxAge: env.cookie.maxAgeMs
    };
}

function setRefreshCookie(res, rawToken) {
    res.cookie(env.cookie.name, rawToken, refreshCookieOptions());
}

function clearRefreshCookie(res) {
    res.clearCookie(env.cookie.name, {
        httpOnly: true,
        secure: env.cookie.secure,
        sameSite: env.cookie.sameSite,
        path: env.cookie.path
    });
}

function readRefreshCookie(req) {
    const value = req.cookies && req.cookies[env.cookie.name];
    return typeof value === "string" && value.length > 0 ? value : null;
}

module.exports = {
    refreshCookieOptions,
    setRefreshCookie,
    clearRefreshCookie,
    readRefreshCookie
};
