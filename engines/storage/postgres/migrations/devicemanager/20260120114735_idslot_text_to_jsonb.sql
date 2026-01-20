-- +goose Up
-- +goose StatementBegin
-- Convert identity_slot column from text to jsonb for devices table
ALTER TABLE devices 
    ALTER COLUMN identity_slot TYPE jsonb 
    USING CASE 
        WHEN identity_slot IS NULL OR identity_slot = '' THEN NULL::jsonb 
        ELSE identity_slot::jsonb 
    END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Revert identity_slot column from jsonb to text for devices table
ALTER TABLE devices 
    ALTER COLUMN identity_slot TYPE text 
    USING identity_slot::text;
-- +goose StatementEnd
