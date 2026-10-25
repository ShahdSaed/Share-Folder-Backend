
require("dotenv").config();

const { PrismaMariaDb } = require("@prisma/adapter-mariadb");

const adapter = new PrismaMariaDb({
    host: process.env.DB_HOST || "localhost",
    port: Number(process.env.DB_PORT || 3306),
    user: process.env.DB_USER || "root",
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME || "company_file_hub",
    connectionLimit: 5
});

const prismaPromise = import("../../generated/prisma/client.ts")
    .then(({ PrismaClient }) => new PrismaClient({ adapter }));

module.exports = prismaPromise;