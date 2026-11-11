package migrations

// Alerts creates the latest-events and subscriptions tables.
func Alerts() Migration {
	return Migration{Version: 6, Name: "alerts", Statements: []string{
		`CREATE TABLE events (
			event_type VARCHAR2(512 CHAR) NOT NULL,
			"EVENT" JSON,
			last_seen TIMESTAMP WITH TIME ZONE,
			total_seen NUMBER(19),
			CONSTRAINT lamassu_event_pk PRIMARY KEY (event_type)
		)`,
		`CREATE TABLE subscriptions (
			id VARCHAR2(512 CHAR) NOT NULL,
			user_id VARCHAR2(512 CHAR),
			event_type VARCHAR2(512 CHAR),
			subscription_date TIMESTAMP WITH TIME ZONE,
			conditions JSON,
			channel JSON,
			CONSTRAINT lamassu_subscription_pk PRIMARY KEY (id)
		)`,
		`CREATE INDEX lamassu_sub_user_idx ON subscriptions (user_id)`,
		`CREATE INDEX lamassu_sub_event_idx ON subscriptions (event_type)`,
	}}
}
