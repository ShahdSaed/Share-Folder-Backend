
const env = require("./env");
const { PrismaMariaDb } = require("@prisma/adapter-mariadb");

const adapter = new PrismaMariaDb({
    host: env.db.host,
    port: env.db.port,
    user: env.db.user,
    password: env.db.password,
    database: env.db.database,
    connectionLimit: 5
});

const prismaPromise = import("../../generated/prisma/client.mts")
    .then(({ PrismaClient }) => new PrismaClient({ adapter }));
    
prismaPromise.getPrismaClient = () => prismaPromise;

module.exports = prismaPromise;
