-- +goose Up
-- +goose StatementBegin

    -- Add key_id column to certificates table and populate it with serial_number
    ALTER TABLE certificates ADD COLUMN key_id VARCHAR;

     -- Insert records from ca_certificates into certificates table
    INSERT INTO certificates (
        serial_number,
        metadata,
        issuer_meta_serial_number,
        issuer_meta_id,
        issuer_meta_level,
        status,
        certificate,
        key_strength_meta_type,
        key_strength_meta_bits,
        key_strength_meta_strength,
        subject_common_name,
        subject_organization,
        subject_organization_unit,
        subject_country,
        subject_state,
        subject_locality,
        valid_from,
        valid_to,
        revocation_timestamp,
        revocation_reason,
        type,
        engine_id,
        key_id
    ) SELECT
        serial_number,
        metadata,
        issuer_meta_serial_number,
        issuer_meta_id,
        issuer_meta_level,
        status,
        certificate,
        key_strength_meta_type,
        key_strength_meta_bits,
        key_strength_meta_strength,
        subject_common_name,
        subject_organization,
        subject_organization_unit,
        subject_country,
        subject_state,
        subject_locality,
        valid_from,
        valid_to,
        revocation_timestamp,
        revocation_reason,
        type,
        engine_id,
        key_id
    FROM
        ca_certificates;

    -- Add foreign key constraint to certificates table for certificate_serial_number
    ALTER TABLE ca_certificates
        ADD CONSTRAINT fk_serial_number
        FOREIGN KEY (serial_number) REFERENCES certificates (serial_number)
        ON DELETE CASCADE;

    -- Drop unnecessary columns from ca_certificates table
    ALTER TABLE ca_certificates DROP COLUMN issuer_meta_serial_number;
    ALTER TABLE ca_certificates DROP COLUMN issuer_meta_id;
    ALTER TABLE ca_certificates DROP COLUMN issuer_meta_level;
    ALTER TABLE ca_certificates DROP COLUMN status;
    ALTER TABLE ca_certificates DROP COLUMN certificate;
    ALTER TABLE ca_certificates DROP COLUMN key_strength_meta_type;
    ALTER TABLE ca_certificates DROP COLUMN key_strength_meta_bits;
    ALTER TABLE ca_certificates DROP COLUMN key_strength_meta_strength;
    ALTER TABLE ca_certificates DROP COLUMN subject_common_name;
    ALTER TABLE ca_certificates DROP COLUMN subject_organization;
    ALTER TABLE ca_certificates DROP COLUMN subject_organization_unit;
    ALTER TABLE ca_certificates DROP COLUMN subject_country;
    ALTER TABLE ca_certificates DROP COLUMN subject_state;
    ALTER TABLE ca_certificates DROP COLUMN subject_locality;
    ALTER TABLE ca_certificates DROP COLUMN valid_from;
    ALTER TABLE ca_certificates DROP COLUMN valid_to;
    ALTER TABLE ca_certificates DROP COLUMN revocation_timestamp;
    ALTER TABLE ca_certificates DROP COLUMN revocation_reason;
    ALTER TABLE ca_certificates DROP COLUMN type;
    ALTER TABLE ca_certificates DROP COLUMN engine_id;
    ALTER TABLE ca_certificates DROP COLUMN key_id;


    ALTER TABLE ca_certificates ADD COLUMN validity_type TEXT;
    ALTER TABLE ca_certificates ADD COLUMN validity_time TIMESTAMPTZ NULL;
    ALTER TABLE ca_certificates ADD COLUMN validity_duration TEXT;

    UPDATE ca_certificates
    SET
        validity_type = issuance_expiration_ref::jsonb->>'type',
        validity_duration = issuance_expiration_ref::jsonb->>'duration',
        validity_time = CASE
            WHEN issuance_expiration_ref::jsonb->>'time' IS NOT NULL AND issuance_expiration_ref::jsonb->>'time' <> ''
            THEN (issuance_expiration_ref::jsonb->>'time')::TIMESTAMPTZ
            ELSE NULL
        END;

    ALTER TABLE ca_certificates DROP COLUMN issuance_expiration_ref;


    -- Rename key_strength_meta columns to key_meta columns
    ALTER TABLE certificates RENAME COLUMN key_strength_meta_type TO key_meta_type;
    ALTER TABLE certificates RENAME COLUMN key_strength_meta_strength TO key_meta_strength;
    ALTER TABLE certificates RENAME COLUMN key_strength_meta_bits TO key_meta_bits;

    ALTER TABLE certificates ALTER COLUMN key_meta_type TYPE varchar(255) USING key_meta_type::varchar;

    UPDATE certificates
    SET key_meta_type = CASE
        WHEN key_meta_type = '0' THEN 'UNKNOWN' -- This is the default value used in UnmarshalText
        WHEN key_meta_type = '1' THEN 'RSA'     -- Use Go X509 Public Key Algorithm iota values
        WHEN key_meta_type = '2' THEN 'DSA'     -- Use Go X509 Public Key Algorithm iota values
        WHEN key_meta_type = '3' THEN 'ECDSA'   -- Use Go X509 Public Key Algorithm iota values
        WHEN key_meta_type = '4' THEN 'Ed25519' -- Use Go X509 Public Key Algorithm iota values
        ELSE key_meta_type
    END;

    ALTER TABLE certificates ALTER COLUMN revocation_reason TYPE varchar(255) USING revocation_reason::varchar;

    UPDATE certificates
    SET revocation_reason = CASE
        WHEN revocation_reason = '0' THEN 'Unspecified'         -- Use models.revocation_reason.go values
        WHEN revocation_reason = '1' THEN 'KeyCompromise'       -- Use models.revocation_reason.go values
        WHEN revocation_reason = '2' THEN 'CACompromise'        -- Use models.revocation_reason.go values
        WHEN revocation_reason = '3' THEN 'AffiliationChanged'  -- Use models.revocation_reason.go values
        WHEN revocation_reason = '4' THEN 'Superseded'          -- Use models.revocation_reason.go values
        WHEN revocation_reason = '5' THEN 'CessationOfOperation'-- Use models.revocation_reason.go values
        WHEN revocation_reason = '6' THEN 'CertificateHold'     -- Use models.revocation_reason.go values
        WHEN revocation_reason = '8' THEN 'RemoveFromCRL'       -- Use models.revocation_reason.go values
        WHEN revocation_reason = '9' THEN 'PrivilegeWithdrawn'  -- Use models.revocation_reason.go values
        WHEN revocation_reason = '10' THEN 'AACompromise'       -- Use models.revocation_reason.go values
        ELSE revocation_reason
    END;


-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
