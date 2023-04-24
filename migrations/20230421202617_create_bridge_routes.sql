-- Create a replacement table for `routes` --
CREATE TABLE public.bridge_routes (
    hostname         text NOT NULL,
    bridge_address   text NOT NULL,
    bridge_group     text NOT NULL,
    update_time      timestamp without time zone NOT NULL,
    cookie           bytea NOT NULL,
    PRIMARY KEY (bridge_address, bridge_group),
    FOREIGN KEY (hostname) REFERENCES public.exits(hostname) ON DELETE CASCADE
);

-- Delete existing indexes for the old `routes` table.
DROP INDEX IF EXISTS bridge_group_idx, hostname_idx, update_time_idx;

-- Create new indexes --
CREATE INDEX bridge_group_idx ON public.bridge_routes (bridge_group);
CREATE INDEX hostname_idx ON public.bridge_routes (hostname);
CREATE INDEX update_time_idx ON public.bridge_routes (update_time);

