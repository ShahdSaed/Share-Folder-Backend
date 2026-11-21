-- Optional admin-provided description for uploaded files
ALTER TABLE `files` ADD COLUMN `description` VARCHAR(1000) NULL;
