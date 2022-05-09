BEGIN;

ALTER TABLE  public.device_information RENAME TO devices;

COMMIT;