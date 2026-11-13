-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
 role_record record;
 ca_ids text[];
 problem text;
BEGIN
 IF to_regclass('ca.certificates') IS NULL OR to_regclass('ca.ca_certificates') IS NULL THEN
  RAISE EXCEPTION 'ca schema not found: migrate the ca schema before the va schema';
 END IF;

 -- Existing CA ids end up in URLs (/crl/<ca-id>) and no escaping survives the path decoding of gin for a '/'.
 SELECT string_agg(id, ', ' ORDER BY id) INTO problem FROM ca.ca_certificates WHERE position('/' IN id) > 0;
 IF problem IS NOT NULL THEN
  RAISE EXCEPTION 'CA ids containing "/" cannot be used in CRL URLs: %. Recreate these CAs with a different id before upgrading', problem;
 END IF;

 CREATE TABLE crl_settings (
  ca_id TEXT NOT NULL,
  legacy_ski TEXT,
  signer_serial_number TEXT,
  validity TEXT,
  refresh_interval TEXT,
  regenerate_on_revoke BOOLEAN,
  status TEXT NOT NULL,
  latest_crl_version NUMERIC,
  latest_crl_valid_from TIMESTAMPTZ,
  latest_crl_valid_until TIMESTAMPTZ,
  CONSTRAINT crl_settings_pkey PRIMARY KEY (ca_id),
  CONSTRAINT crl_settings_legacy_ski_uq UNIQUE (legacy_ski),
  CONSTRAINT crl_settings_status_chk CHECK (status IN ('ACTIVE', 'ARCHIVED'))
 );

 FOR role_record IN SELECT * FROM va_role ORDER BY ca_ski LOOP
  SELECT array_agg(DISTINCT a.id ORDER BY a.id) INTO ca_ids
   FROM ca.certificates c JOIN ca.ca_certificates a ON a.serial_number = c.serial_number
   WHERE c.subject_key_id = role_record.ca_ski;

  IF COALESCE(cardinality(ca_ids), 0) > 1 THEN
   RAISE EXCEPTION 'VA role %: SKI shared by CAs %. Every SKI must belong to a single CA before upgrading: recreate all but one of them on a different key',
    role_record.ca_ski, array_to_string(ca_ids, ', ');
  END IF;

  IF COALESCE(cardinality(ca_ids), 0) = 0 THEN
   -- The CA was deleted (#841). Its own id cannot be recovered: the issuer metadata of a subordinate certificate is the
   -- id of its parent. The last published CRL stays reachable through the old URL.
   -- Its synthetic id must not be the id of a live CA, or /crl/<id> of that CA would resolve to these settings.
   IF EXISTS (SELECT 1 FROM ca.ca_certificates WHERE id = 'legacy-' || role_record.ca_ski) THEN
    RAISE EXCEPTION 'VA role %: CA % has the id reserved for the archived settings of this role, whose CA was deleted. Recreate that CA with a different id before upgrading',
     role_record.ca_ski, 'legacy-' || role_record.ca_ski;
   END IF;
   INSERT INTO crl_settings (ca_id, legacy_ski, signer_serial_number, validity, refresh_interval, regenerate_on_revoke,
     status, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
   VALUES ('legacy-' || role_record.ca_ski, role_record.ca_ski, NULL, role_record.crl_validity, role_record.crl_refresh_interval,
     role_record.crl_regenerate_on_revoke, 'ARCHIVED', role_record.latest_crl_version, role_record.latest_crl_valid_from,
     role_record.latest_crl_valid_until);
  ELSE
   IF NOT EXISTS (SELECT 1 FROM ca.certificates c
     WHERE c.serial_number = role_record.crl_signer_certificate_serial_number AND COALESCE(c.key_id, '') <> '') THEN
    RAISE EXCEPTION 'VA role %, CA %: signer certificate % has no key, so it cannot sign CRLs. Point the role to a signer with a key, or fix the key reference of the certificate, before upgrading',
     role_record.ca_ski, ca_ids[1], role_record.crl_signer_certificate_serial_number;
   END IF;

   INSERT INTO crl_settings (ca_id, legacy_ski, signer_serial_number, validity, refresh_interval, regenerate_on_revoke,
     status, latest_crl_version, latest_crl_valid_from, latest_crl_valid_until)
   VALUES (ca_ids[1], role_record.ca_ski, role_record.crl_signer_certificate_serial_number, role_record.crl_validity,
     role_record.crl_refresh_interval, role_record.crl_regenerate_on_revoke, 'ACTIVE', role_record.latest_crl_version,
     role_record.latest_crl_valid_from, role_record.latest_crl_valid_until);
  END IF;
 END LOOP;

 -- /crl/<id> resolves ca_id first and legacy_ski second, so an id equal to the SKI of another role would take its URL.
 SELECT string_agg(DISTINCT a.id, ', ' ORDER BY a.id) INTO problem
  FROM ca.ca_certificates a JOIN crl_settings s ON s.legacy_ski = a.id AND s.ca_id <> a.id;
 IF problem IS NOT NULL THEN
  RAISE EXCEPTION 'CA ids equal to the SKI of another VA role: %. Their CRL URLs would be ambiguous', problem;
 END IF;

 ALTER TABLE crl_settings ADD CONSTRAINT crl_settings_signer_cert_fk
  FOREIGN KEY (signer_serial_number) REFERENCES ca.certificates (serial_number)
  ON DELETE NO ACTION ON UPDATE CASCADE;
 CREATE INDEX crl_settings_signer_cert_idx ON crl_settings (signer_serial_number);

 DROP TABLE va_role;
END $$;
-- +goose StatementEnd

-- +goose Down
-- BREAKING: this migration cannot be rolled back, so Down does nothing. CRLs generated after the upgrade are stored
-- under the CA ID, where the previous version does not look for them, and archived settings have no signer to go
-- back to va_role. To return to the previous version, restore the database and the CRL bucket from the backup taken
-- before the upgrade.
