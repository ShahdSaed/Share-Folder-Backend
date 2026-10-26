require("dotenv").config();

function validateEnv() {
    const missingVars = [];

    if (!process.env.JWT_SECRET) {
        missingVars.push("JWT_SECRET");
    }

    if (missingVars.length > 0) {
        throw new Error(
            `[FATAL] Missing required environment variable(s): ${missingVars.join(", ")}. ` +
            `Please ensure they are defined in your .env file or deployment environment.`
        );
    }

    if (process.env.JWT_SECRET.length < 32 && process.env.NODE_ENV === "production") {
        throw new Error(
            `[FATAL] JWT_SECRET must be at least 32 characters long in production for security.`
        );
    }

    return {
        port: Number(process.env.PORT || 3000),
        nodeEnv: process.env.NODE_ENV || "development",
        jwt: {
            secret: process.env.JWT_SECRET,
            expiresIn: process.env.JWT_EXPIRES_IN || "1h",
            algorithm: "HS256"
        },
        db: {
            host: process.env.DB_HOST || "localhost",
            port: Number(process.env.DB_PORT || 3306),
            user: process.env.DB_USER || "root",
            password: process.env.DB_PASSWORD || "",
            database: process.env.DB_NAME || "company_file_hub"
        }
    };
}

const env = validateEnv();

module.exports = env;
