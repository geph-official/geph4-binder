-- Create a replacement table for `routes` --
CREATE TABLE public.bridge_routes (
    exit_hostname      TEXT NOT NULL,
    bridge_descriptor  BYTEA NOT NULL UNIQUE,
    update_time        TIMESTAMP WITHOUT TIME ZONE NOT NULL,
    FOREIGN KEY (exit_hostname) REFERENCES exits(hostname) ON DELETE CASCADE
);
