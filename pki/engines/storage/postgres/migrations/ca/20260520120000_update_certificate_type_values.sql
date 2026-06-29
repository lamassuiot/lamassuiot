-- +goose Up
-- +goose StatementBegin
-- Rename CertificateType values in the certificates table:
--   IMPORTED -> IMPORTED_WITH_KEY
--   EXTERNAL -> IMPORTED_WITHOUT_KEY
-- MANAGED remains unchanged.

UPDATE certificates SET "type" = 'IMPORTED_WITH_KEY'    WHERE "type" = 'IMPORTED';
UPDATE certificates SET "type" = 'IMPORTED_WITHOUT_KEY' WHERE "type" = 'EXTERNAL';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE certificates SET "type" = 'IMPORTED' WHERE "type" = 'IMPORTED_WITH_KEY';
UPDATE certificates SET "type" = 'EXTERNAL' WHERE "type" = 'IMPORTED_WITHOUT_KEY';
-- +goose StatementEnd
