-- +goose Up
-- +goose StatementBegin
-- Convert metadata column from text to jsonb for dms table
ALTER TABLE dms 
    ALTER COLUMN metadata TYPE jsonb 
    USING CASE 
        WHEN metadata IS NULL OR metadata = '' THEN '{}'::jsonb 
        ELSE metadata::jsonb 
    END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Revert metadata column from jsonb to text for dms table
ALTER TABLE dms 
    ALTER COLUMN metadata TYPE text 
    USING metadata::text;
-- +goose StatementEnd
