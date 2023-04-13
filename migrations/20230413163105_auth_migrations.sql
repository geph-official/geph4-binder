-- Add migration script here
CREATE TABLE IF NOT EXISTS auth_password(
       user_id INT NOT NULL,
       pwdhash TEXT NOT NULL,
       PRIMARY KEY user_id,
       FOREIGN KEY (user_id) REFERENCES users(id) CASCADE ON DELETE,
);

CREATE TABLE IF NOT EXISTS auth_pubkey(
       user_id INT NOT NULL,
       pubkey TEXT NOT NULL,
       PRIMARY KEY user_id,
       FOREIGN KEY (user_id) REFERENCES users(id) CASCADE ON DELETE,
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
