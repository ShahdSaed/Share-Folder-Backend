const { BadRequestError } = require("../../utils/errors");

const DEFAULT_GRANT_DAYS = 30;
const MIN_GRANT_DAYS = 1;
const MAX_GRANT_DAYS = 365;
const GRANT_STATUS_VALUES = ["active", "expired", "all"];

function validateExpiresInDays(raw) {
    if (raw === undefined || raw === null || raw === "") {
        return DEFAULT_GRANT_DAYS;
    }

    const days = typeof raw === "number" ? raw : Number(raw);
    if (!Number.isInteger(days)) {
        throw new BadRequestError("expiresInDays must be a positive integer");
    }

    if (days < MIN_GRANT_DAYS || days > MAX_GRANT_DAYS) {
        throw new BadRequestError(
            `expiresInDays must be between ${MIN_GRANT_DAYS} and ${MAX_GRANT_DAYS}`
        );
    }

    return days;
}

function validateGrantStatus(raw) {
    if (raw === undefined || raw === null || raw === "") {
        return "all";
    }

    const status = String(raw).trim().toLowerCase();
    if (!GRANT_STATUS_VALUES.includes(status)) {
        throw new BadRequestError(`status must be one of: ${GRANT_STATUS_VALUES.join(", ")}`);
    }

    return status;
}

module.exports = {
    DEFAULT_GRANT_DAYS,
    MIN_GRANT_DAYS,
    MAX_GRANT_DAYS,
    validateExpiresInDays,
    validateGrantStatus
};
