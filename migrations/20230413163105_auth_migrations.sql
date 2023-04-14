-- Add migration script here
CREATE TABLE IF NOT EXISTS auth_password (
       user_id INT NOT NULL PRIMARY KEY,
       username TEXT NOT NULL,
       pwdhash TEXT NOT NULL,
       FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_pubkey(
       user_id INT NOT NULL PRIMARY KEY,
       pubkey TEXT NOT NULL,
       FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

-- copy over data from users --
INSERT INTO auth_password
(user_id, username, pwdhash)
SELECT id, username, pwdhash
FROM users;

-- remove pwdhash column from users (WHEN READY) --
ALTER TABLE users
DROP COLUMN pwdhash,
DROP COLUMN username;
