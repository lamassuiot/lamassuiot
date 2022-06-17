BEGIN;

ALTER TABLE public.device_logs DROP COLUMN log_description;

COMMIT;