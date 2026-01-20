-- +goose Up
-- +goose StatementBegin
-- Convert settings column from text to jsonb for dms table
ALTER TABLE dms 
    ALTER COLUMN settings TYPE jsonb 
    USING CASE 
        WHEN settings IS NULL OR settings = '' THEN '{}'::jsonb 
        ELSE settings::jsonb 
    END;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
-- Revert settings column from jsonb to text for dms table
ALTER TABLE dms 
    ALTER COLUMN settings TYPE text 
    USING settings::text;
-- +goose StatementEnd
