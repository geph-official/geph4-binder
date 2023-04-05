-- Add migration script here
CREATE TABLE IF NOT EXISTS auth_pubkey(
       user_id INT NOT NULL,
       pubkey TEXT NOT NULL,
       PRIMARY KEY user_id,
       FOREIGN KEY (user_id) REFERENCES users(id),
);
