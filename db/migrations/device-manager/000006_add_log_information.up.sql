BEGIN;

ALTER TABLE public.device_logs 
ADD COLUMN log_description TEXT;

COMMIT;