-- copy over data from users --
-- todo: map to user_ids
INSERT INTO auth_password
(user_id, username, pwdhash)
SELECT id, username, pwdhash
FROM users;

-- remove pwdhash column from users --
ALTER TABLE users
DROP COLUMN pwdhash,
DROP COLUMN username;
-- and username from the users table
