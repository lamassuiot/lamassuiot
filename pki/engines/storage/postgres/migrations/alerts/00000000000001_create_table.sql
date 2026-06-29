-- +goose Up
-- +goose StatementBegin
CREATE TABLE events (
	event_type text NOT NULL,
	"event" text NULL,
	last_seen timestamptz NULL,
	total_seen int8 NULL,
	CONSTRAINT events_pkey PRIMARY KEY (event_type)
);
CREATE TABLE subscriptions (
	id text NOT NULL,
	user_id text NULL,
	event_type text NULL,
	subscription_date timestamptz NULL,
	conditions text NULL,
	channel text NULL,
	CONSTRAINT subscriptions_pkey PRIMARY KEY (id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE events;
DROP TABLE subscriptions;
-- +goose StatementEnd
