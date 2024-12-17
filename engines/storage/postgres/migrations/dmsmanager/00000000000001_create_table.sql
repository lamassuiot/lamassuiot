-- +goose Up
-- +goose StatementBegin
CREATE TABLE dms (
	id text NOT NULL,
	"name" text NULL,
	metadata text NULL,
	creation_date timestamptz NULL,
	settings text NULL,
	CONSTRAINT dms_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE dms;
-- +goose StatementEnd
