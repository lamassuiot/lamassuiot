CREATE TABLE IF NOT EXISTS public.device_certificates_history (
    serial_number TEXT PRIMARY KEY,
    device_uuid TEXT,
    issuer_name TEXT,
    status TEXT,
    creation_ts timestamp
);