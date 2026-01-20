-- +goose Up
-- +goose StatementBegin
-- Convert metadata column from text to jsonb for ca_certificates table
ALTER TABLE ca_certificates 
    ALTER COLUMN metadata TYPE jsonb 
    USING CASE 
        WHEN metadata IS NULL OR metadata = '' THEN '{}'::jsonb 
        ELSE metadata::jsonb 
    END;

-- Convert metadata column from text to jsonb for certificates table
ALTER TABLE certificates 
    ALTER COLUMN metadata TYPE jsonb 
    USING CASE 
        WHEN metadata IS NULL OR metadata = '' THEN '{}'::jsonb 
        ELSE metadata::jsonb 
    END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Revert metadata column from jsonb to text for ca_certificates table
ALTER TABLE ca_certificates 
    ALTER COLUMN metadata TYPE text 
    USING metadata::text;

-- Revert metadata column from jsonb to text for certificates table
ALTER TABLE certificates 
    ALTER COLUMN metadata TYPE text 
    USING metadata::text;
-- +goose StatementEnd
