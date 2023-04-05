CREATE TABLE IF NOT EXISTS auth_pwdhash(
       user_id INT NOT NULL,
       pwdhash TEXT NOT NULL,
       PRIMARY KEY user_id,
       FOREIGN KEY (user_id) REFERENCES users(id),
);
