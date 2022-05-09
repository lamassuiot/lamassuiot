CREATE TABLE IF NOT EXISTS public.synchronized_cas (
    connector_id TEXT,
    ca_name TEXT,
    serial_number TEXT,
    creation_ts timestamp,
    PRIMARY KEY (connector_id, ca_name)
);