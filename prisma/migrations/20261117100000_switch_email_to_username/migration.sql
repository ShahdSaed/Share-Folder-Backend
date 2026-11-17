-- AlterTable
ALTER TABLE `users` CHANGE COLUMN `email` `username` VARCHAR(255) NOT NULL;

-- UpdateIndex
ALTER TABLE `users` DROP INDEX `users_email_key`, ADD UNIQUE INDEX `users_username_key`(`username`);
