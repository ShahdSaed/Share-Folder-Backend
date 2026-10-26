#!/usr/bin/env node

/**
 * Administrative CLI Script: Initial Administrator Provisioning
 * 
 * Usage:
 *   Interactive:
 *     npm run admin:create
 *   Or with non-committed environment variables:
 *     ADMIN_NAME="System Admin" ADMIN_EMAIL="admin@company.com" ADMIN_PASSWORD="SecurePassword123!" npm run admin:create
 *   Or via CLI arguments:
 *     node scripts/create-admin.js --name "System Admin" --email "admin@company.com" --password "SecurePassword123!"
 */

require("dotenv").config();
const readline = require("readline");
const userRepository = require("../src/modules/users/user.repository");
const auditLogService = require("../src/modules/audit-logs/audit-log.service");
const { hashPassword } = require("../src/utils/password");
const { normalizeAndValidateEmail } = require("../src/utils/validator");
const prismaPromise = require("../src/config/prisma");

function parseArgs() {
    const args = process.argv.slice(2);
    const parsed = {};
    for (let i = 0; i < args.length; i++) {
        if (args[i] === "--name" && args[i + 1]) {
            parsed.name = args[++i];
        } else if (args[i] === "--email" && args[i + 1]) {
            parsed.email = args[++i];
        } else if (args[i] === "--password" && args[i + 1]) {
            parsed.password = args[++i];
        }
    }
    return parsed;
}

function prompt(question, hideInput = false) {
    const rl = readline.createInterface({
        input: process.stdin,
        output: process.stdout
    });

    return new Promise((resolve) => {
        if (!hideInput) {
            rl.question(question, (answer) => {
                rl.close();
                resolve(answer.trim());
            });
        } else {
            // For password masking in terminal
            process.stdout.write(question);
            const stdin = process.stdin;
            const wasRaw = stdin.isRaw;
            if (stdin.setRawMode) stdin.setRawMode(true);
            stdin.resume();

            let input = "";
            const onData = (char) => {
                const c = char.toString("utf8");
                if (c === "\n" || c === "\r" || c === "\u0004") {
                    stdin.removeListener("data", onData);
                    if (stdin.setRawMode) stdin.setRawMode(wasRaw);
                    process.stdout.write("\n");
                    rl.close();
                    resolve(input.trim());
                } else if (c === "\u0008" || c === "\x7f") { // Backspace
                    if (input.length > 0) {
                        input = input.slice(0, -1);
                        process.stdout.write("\b \b");
                    }
                } else if (c === "\u0003") { // Ctrl+C
                    process.exit(1);
                } else {
                    input += c;
                    process.stdout.write("*");
                }
            };

            stdin.on("data", onData);
        }
    });
}

async function run() {
    console.log("==================================================");
    console.log("  Company File Hub - Administrator Provisioning   ");
    console.log("==================================================");

    const args = parseArgs();

    let name = args.name || process.env.ADMIN_NAME;
    let email = args.email || process.env.ADMIN_EMAIL;
    let password = args.password || process.env.ADMIN_PASSWORD;

    if (!name) {
        name = await prompt("Enter administrator full name: ");
    }
    if (!name || name.trim().length === 0) {
        console.error("❌ Error: Administrator name is required.");
        process.exit(1);
    }

    if (!email) {
        email = await prompt("Enter administrator email: ");
    }

    let normalizedEmail;
    try {
        normalizedEmail = normalizeAndValidateEmail(email);
    } catch (err) {
        console.error(`❌ Error: ${err.message}`);
        process.exit(1);
    }

    if (!password) {
        password = await prompt("Enter administrator password (min 10 characters): ", true);
    }

    if (!password || password.length < 10) {
        console.error("❌ Error: Password must be at least 10 characters long.");
        process.exit(1);
    }

    try {
        // 1. Check if user already exists
        const existing = await userRepository.findByEmailWithPassword(normalizedEmail);
        if (existing) {
            console.error(`❌ Error: A user with email '${normalizedEmail}' already exists.`);
            console.error("   Existing accounts are never automatically promoted. Aborting.");
            process.exit(1);
        }

        console.log("🔐 Hashing administrator password with Argon2id...");
        const passwordHash = await hashPassword(password);

        console.log("💾 Creating administrator account in MySQL...");
        const adminUser = await userRepository.create({
            name: name.trim(),
            email: normalizedEmail,
            passwordHash,
            role: "ADMIN",
            isActive: true
        });

        // Record security audit log
        await auditLogService.logEvent({
            userId: adminUser.id,
            action: "ADMIN_PROVISIONED",
            targetType: "USER",
            targetId: adminUser.id,
            ipAddress: "127.0.0.1",
            userAgent: "CLI Script (create-admin)",
            result: "Success"
        });

        console.log("✅ Administrator provisioned successfully!");
        console.log(`   ID:    ${adminUser.id}`);
        console.log(`   Name:  ${adminUser.name}`);
        console.log(`   Email: ${adminUser.email}`);
        console.log(`   Role:  ${adminUser.role}`);
        console.log("==================================================");
    } catch (error) {
        console.error("❌ Failed to provision administrator:", error.message);
        process.exit(1);
    } finally {
        const prisma = await prismaPromise;
        await prisma.$disconnect();
    }
}

run();
