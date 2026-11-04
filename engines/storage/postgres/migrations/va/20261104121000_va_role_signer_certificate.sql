-- +goose Up
-- +goose StatementBegin
DO $$
DECLARE
 role_record record;
 candidates text[];
BEGIN
 IF to_regclass('ca.certificates') IS NULL OR to_regclass('ca.ca_certificates') IS NULL THEN
  RAISE EXCEPTION 'ca schema not found: migrate the ca schema before the va schema';
 END IF;
 ALTER TABLE va_role ADD COLUMN crl_signer_certificate_serial_number TEXT;
 FOR role_record IN SELECT ca_ski, crl_subject_key_id_signer FROM va_role ORDER BY ca_ski LOOP
  SELECT array_agg(DISTINCT c.serial_number) INTO candidates
   FROM ca.certificates c JOIN ca.ca_certificates a ON a.serial_number = c.serial_number
   WHERE c.subject_key_id = role_record.crl_subject_key_id_signer;
  IF COALESCE(cardinality(candidates), 0) = 0 THEN
   SELECT array_agg(c.serial_number) INTO candidates FROM ca.certificates c
    WHERE c.subject_key_id = role_record.crl_subject_key_id_signer;
  END IF;
  IF COALESCE(cardinality(candidates), 0) <> 1 THEN
   RAISE EXCEPTION 'cannot resolve signer certificate for VA role %, SKI %: % candidates',
    role_record.ca_ski, role_record.crl_subject_key_id_signer, COALESCE(cardinality(candidates), 0);
  END IF;
  UPDATE va_role SET crl_signer_certificate_serial_number = candidates[1] WHERE ca_ski = role_record.ca_ski;
 END LOOP;
 ALTER TABLE va_role ALTER COLUMN crl_signer_certificate_serial_number SET NOT NULL;
 ALTER TABLE va_role ADD CONSTRAINT va_role_signer_certificate_fk
  FOREIGN KEY (crl_signer_certificate_serial_number) REFERENCES ca.certificates(serial_number)
  ON DELETE RESTRICT ON UPDATE CASCADE;
 CREATE INDEX va_role_signer_certificate_idx ON va_role(crl_signer_certificate_serial_number);
 ALTER TABLE va_role DROP COLUMN crl_subject_key_id_signer;
END $$;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE va_role ADD COLUMN crl_subject_key_id_signer TEXT;
UPDATE va_role r SET crl_subject_key_id_signer = c.subject_key_id
 FROM ca.certificates c WHERE c.serial_number = r.crl_signer_certificate_serial_number;
ALTER TABLE va_role DROP CONSTRAINT va_role_signer_certificate_fk;
DROP INDEX va_role_signer_certificate_idx;
ALTER TABLE va_role DROP COLUMN crl_signer_certificate_serial_number;
-- +goose StatementEnd
