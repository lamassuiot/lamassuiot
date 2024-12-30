-- +goose Up
-- +goose StatementBegin
CREATE TABLE devices (
	id text NOT NULL,
	tags text NULL,
	status text NULL,
	icon text NULL,
	icon_color text NULL,
	creation_timestamp timestamptz NULL,
	metadata text NULL,
	dms_owner text NULL,
	identity_slot text NULL,
	extra_slots text NULL,
	events text NULL,
	CONSTRAINT devices_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE devices;
-- +goose StatementEnd
