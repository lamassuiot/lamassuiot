CREATE TABLE IF NOT EXISTS public.ca_issued_certs (
    ca_name TEXT,
    serial_number TEXT,
    PRIMARY KEY (ca_name,serial_number)  
);