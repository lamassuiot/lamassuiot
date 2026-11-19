# Configuration environment overrides

The shared configuration loader reads the YAML file selected by
`LAMASSU_CONFIG_FILE` (or the standard configuration path) and supports
explicit environment-variable overrides for application credentials.

Environment variables take precedence over YAML only for the credential fields
listed below. Other configuration keys are not implicitly read from the
environment.

| Configuration path | Environment variable |
| --- | --- |
| `storage.username` | `LAMASSU_POSTGRES_USERNAME` |
| `storage.password` | `LAMASSU_POSTGRES_PASSWORD` |
| `authz_db.username` | `LAMASSU_AUTHZ_DB_USERNAME` |
| `authz_db.password` | `LAMASSU_AUTHZ_DB_PASSWORD` |
| `publisher_event_bus.basic_auth.username` | `LAMASSU_AMQP_USERNAME` |
| `publisher_event_bus.basic_auth.password` | `LAMASSU_AMQP_PASSWORD` |
| `subscriber_event_bus.basic_auth.username` | `LAMASSU_AMQP_USERNAME` |
| `subscriber_event_bus.basic_auth.password` | `LAMASSU_AMQP_PASSWORD` |
| `subscriber_dlq_event_bus.basic_auth.username` | `LAMASSU_AMQP_USERNAME` |
| `subscriber_dlq_event_bus.basic_auth.password` | `LAMASSU_AMQP_PASSWORD` |
| `smtp_server.username` | `LAMASSU_SMTP_USERNAME` |
| `smtp_server.password` | `LAMASSU_SMTP_PASSWORD` |

Authz schema-specific PostgreSQL credentials are also supported when the
schema is declared in the YAML file:

```yaml
credentials:
  pki:
    provider: postgres
    username: yaml-user
    password: yaml-password
```

For the schema above, the loader binds:

```text
LAMASSU_AUTHZ_CREDENTIALS_PKI_USERNAME
LAMASSU_AUTHZ_CREDENTIALS_PKI_PASSWORD
```

Schema names are converted to uppercase and non-alphanumeric characters are
replaced with `_`. The loader rejects configurations where two schema names
would produce the same environment-variable prefix.

Unset and empty environment variables are treated as unset by Viper, so the
YAML value remains in use. A non-empty environment variable overrides the YAML
value. The loader deliberately does not enable `AutomaticEnv`; only the
explicit credential paths above are eligible for environment overrides.

Kubernetes deployments can inject these variables using `secretKeyRef`.
The corresponding credentials should not also be rendered into a ConfigMap.

## Adding a new credential

Fixed configuration paths are intentionally an allowlist. If a new service
introduces a fixed credential path, add one entry to
`credentialEnvBindings` in `loader.go`, add a focused loader test, and update
this table. This is required so that new environment overrides are explicit
and cannot affect unrelated configuration keys.

The `credentials.<schema>.username` and
`credentials.<schema>.password` paths are the only dynamic exception. Their
schema names are discovered from YAML and mapped to
`LAMASSU_AUTHZ_CREDENTIALS_<SCHEMA>_USERNAME` and
`LAMASSU_AUTHZ_CREDENTIALS_<SCHEMA>_PASSWORD`. An environment variable cannot
create a new schema that is absent from YAML.
