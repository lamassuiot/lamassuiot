-- +goose Up
-- +goose StatementBegin
CREATE TABLE device_events (
	id text NOT NULL,
	device_id text NOT NULL,
	event_ts timestamptz NOT NULL,
	event_type text NOT NULL,
	description text NULL,
	source text NULL,
	structured_fields jsonb NULL,
	CONSTRAINT device_events_pkey PRIMARY KEY (id),
	CONSTRAINT fk_device_events_device FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
);

-- Composite index covers the common access pattern: filter by device_id, ordered by event_ts DESC.
-- It also subsumes lookups by device_id alone, so no separate single-column index is needed.
CREATE INDEX idx_device_events_device_id_event_ts ON device_events (device_id, event_ts DESC);
CREATE INDEX idx_device_events_event_ts ON device_events (event_ts DESC);
CREATE INDEX idx_device_events_event_type ON device_events (event_type);
CREATE INDEX idx_device_events_structured_fields_gin ON device_events USING GIN (structured_fields);

INSERT INTO device_events (id, device_id, event_ts, event_type, description, source, structured_fields)
SELECT
	md5(d.id || ':' || ev.key || ':' || ev.value::text),
	d.id,
	-- Strict ISO 8601 prefix (valid month and day) before attempting the timestamptz cast,
	-- so loose-but-invalid keys like "2026-13-99..." fall through to the fallback branch
	-- instead of aborting the migration.
	CASE
		WHEN ev.key ~ '^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[12][0-9]|3[01])T[0-9]{2}:[0-9]{2}:[0-9]{2}' THEN ev.key::timestamptz
		ELSE COALESCE(d.creation_timestamp, now())
	END,
	COALESCE(ev.value->>'type', 'UNKNOWN'),
	COALESCE(ev.value->>'description', ''),
	COALESCE(NULLIF(ev.value->>'source', ''), 'service/devmanager'),
	CASE
		WHEN jsonb_typeof(ev.value) = 'object' THEN (ev.value - 'type' - 'description' - 'source')
		ELSE '{}'::jsonb
	END
FROM devices d
CROSS JOIN LATERAL jsonb_each(
	CASE
		WHEN d.events IS NULL OR btrim(d.events) = '' THEN '{}'::jsonb
		ELSE d.events::jsonb
	END
) ev;

ALTER TABLE devices DROP COLUMN IF EXISTS events;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE devices ADD COLUMN IF NOT EXISTS events text NULL;

-- Restore the legacy flat JSON shape: structured_fields keys live alongside type/description/source
-- on the event object (matching what the Up migration consumed), not nested under a wrapper key.
UPDATE devices d
SET events = COALESCE(
	(
		SELECT jsonb_object_agg(
				de.event_ts::text,
				jsonb_strip_nulls(
					jsonb_build_object(
						'type', de.event_type,
						'description', de.description,
						'source', NULLIF(de.source, '')
					)
				) || COALESCE(de.structured_fields, '{}'::jsonb)
			)::text
		FROM device_events de
		WHERE de.device_id = d.id
	),
	'{}'
);

DROP TABLE IF EXISTS device_events;
-- +goose StatementEnd
