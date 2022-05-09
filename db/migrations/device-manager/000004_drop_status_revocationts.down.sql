BEGIN;

ALTER TABLE public.device_certificates_history 
ADD COLUMN status TEXT default '';

ALTER TABLE public.device_certificates_history 
ADD COLUMN revocation_ts TIMESTAMP default '1900-01-01 00:00:00';

COMMIT;