-- +goose Up
-- +goose StatementBegin
-- The VA events about CRL settings were renamed when the settings moved from the SKI to the CA ID. Subscriptions match
-- the event type exactly, so they follow the new names. Their conditions are not rewritten: the payload is now the CRL
-- settings of a CA, and a condition on a field of the old payload must be reviewed by hand.
-- The events table is left as is: its rows are the last event seen of each type, in the format of the old payload.
UPDATE subscriptions SET event_type = 'va.crl-settings.update' WHERE event_type = 'va.role.update';
UPDATE subscriptions SET event_type = 'va.crl-settings.init' WHERE event_type = 'va.role.crl.init';
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
UPDATE subscriptions SET event_type = 'va.role.update' WHERE event_type = 'va.crl-settings.update';
UPDATE subscriptions SET event_type = 'va.role.crl.init' WHERE event_type = 'va.crl-settings.init';
-- +goose StatementEnd
