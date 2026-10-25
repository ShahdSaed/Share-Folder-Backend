
const { PrismaMariaDb } = require("@prisma/adapter-mariadb");
const { PrismaClient } = require("../../generated/prisma/client");

const adapter = new PrismaMariaDb({
    host: "localhost",
    port: 3306,
    user: "root",
    password: process.env.DB_PASSWORD,
    database: "company_file_hub",
    connectionLimit: 5
});

const prisma = new PrismaClient({ adapter });

module.exports = prisma;