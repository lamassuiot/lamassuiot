BEGIN;

ALTER TABLE public.device_information 
RENAME COLUMN key_stregnth TO key_strength;

COMMIT;