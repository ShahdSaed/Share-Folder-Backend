-- Enforce one grant row per (user, file) pair at the database level.
-- Create the unique index first so the foreign key constraint on user_id continues to be satisfied.
CREATE UNIQUE INDEX `file_access_grants_user_id_file_id_key` ON `file_access_grants`(`user_id`, `file_id`);

-- Drop the old non-unique composite index now that the unique index covers user_id and file_id.
DROP INDEX `file_access_grants_user_id_file_id_idx` ON `file_access_grants`;
