BEGIN;

ALTER TABLE public.device_information 
RENAME COLUMN key_strength TO key_stregnth;

COMMIT;