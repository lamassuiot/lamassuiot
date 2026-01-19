-- +goose Up
-- +goose StatementBegin
CREATE TABLE public.device_events (
	"timestamp" timestamptz NOT NULL,
	device_id varchar NOT NULL,
	"type" varchar NULL,
	message varchar NULL,
	structured_fields jsonb DEFAULT '{}'::jsonb,
	slot_id varchar NULL,
	"source" varchar NULL,
	CONSTRAINT device_events_pk PRIMARY KEY ("timestamp", device_id)
);

ALTER TABLE public.device_events ADD CONSTRAINT device_events_devices_fk FOREIGN KEY (device_id) REFERENCES public.devices(id);

CREATE TABLE public.device_status_updates (
	device_id varchar NOT NULL,
	update_time timestamptz NOT NULL,
	status varchar NULL,
	CONSTRAINT device_status_updates_pk PRIMARY KEY (device_id, update_time)
);

ALTER TABLE public.device_status_updates ADD CONSTRAINT device_status_updates_devices_fk FOREIGN KEY (device_id) REFERENCES public.devices(id);

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
SELECT 'down SQL query';
-- +goose StatementEnd
