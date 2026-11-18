-- +goose Up
CREATE VIEW certificates_view AS
SELECT c.*, COALESCE(k.has_private_key, false) AS has_private_key
FROM certificates c
LEFT JOIN kms.kms_keys k
  ON k.engine_id = c.engine_id AND k.key_id = c.key_id;

-- +goose Down
DROP VIEW IF EXISTS certificates_view;
