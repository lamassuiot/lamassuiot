-- +goose Up
-- +goose StatementBegin

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
        engine_id
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
        engine_id
    FROM
        ca_certificates;

    -- Add foreign key constraint to certificates table for serial_number
    ALTER TABLE ca_certificates
        ADD CONSTRAINT fk_serial_number
        FOREIGN KEY (serial_number) REFERENCES certificates (serial_number)
        ON DELETE CASCADE;

    -- Drop unnecessary columns from ca_certificates table
    ALTER TABLE ca_certificates DROP COLUMN metadata;
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

    -- Add key_id column to certificates table and populate it with serial_number
    ALTER TABLE certificates ADD COLUMN key_id VARCHAR;
    UPDATE certificates SET key_id = serial_number WHERE type = 'MANAGED';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE certificates DROP COLUMN key_id;
-- +goose StatementEnd
