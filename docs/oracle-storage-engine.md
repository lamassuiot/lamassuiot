# Oracle storage engine (in development)

The `oracle` provider uses Oracle Database 26ai and the pure-Go Oracle driver.
It is under development: JSONPath filters and JSON ordering are not yet at
PostgreSQL parity. JSONPath scalar comparisons include explicit type checks to
preserve PostgreSQL JSONB ordering across `null`, string, number, Boolean,
array, and object values, including PostgreSQL's special ordering for empty
arrays; same-type scalars are compared using Oracle's type-specific `*Only()`
methods. Numeric filter literals are bound as exact
decimal values through Oracle `NUMBER`, without a Go `float64` conversion;
values outside Oracle `NUMBER`'s precision or exponent range are rejected.
Oracle-specific numeric JSON families still need differential validation.
JSONPath filters support scalar comparisons, Boolean
operators `&&` and `||`, `exists` (including its negation), nested array path
filters, `in`, `has substring`, `starts with`, array indexes and ranges, quoted member names,
`like_regex` predicate (including the case-insensitive `i` flag, literal
substring `q` flag, and their combination; multiline and dotall flags are
accepted only together with `q`, where PostgreSQL ignores them), and the
shared `number()`, `string()`, `boolean()`, `double()`, `size()`, and `type()`
item methods. Non-empty compared values are passed as SQL binds; an
empty JSON string is emitted as a path literal because Oracle treats an empty
SQL string bind as `NULL`. Negated scalar comparisons and string predicates
are compiled with path-presence and type guards, preserving PostgreSQL's
`unknown` behavior for missing and incompatible values. Comparisons between
two paths are accepted when both paths end in compatible type-producing item
methods (`number()`, `double()`, `string()`, `boolean()`, `size()`, or `type()`),
as required by Oracle's SQL/JSON static type checking. Untyped or incompatible path-to-path
comparisons and other unsupported PostgreSQL JSONPath constructs return an
explicit error; their equivalence still needs implementation and differential
validation. Predicates and generated SQL/JSON paths are capped at Oracle's
32 KiB path-expression limit; compared string values remain bound separately.
JSON sort paths are translated to Oracle SQL/JSON paths. Empty JSON strings
are distinguished from absent and null values. Extracted sort keys use a
CLOB-backed Oracle order type so arrays, objects, and strings are not limited
to `VARCHAR2(4000)`; their serialized text is compared lexically to follow the
PostgreSQL query's current sort key. Character collation and Oracle JSON
serialization still need differential validation. ISO datetime sort keys use
Oracle `TIMESTAMP(6)` conversion to match PostgreSQL's microsecond precision.
Other date and timezone edge cases still need differential validation.
Authorization translates allow-listed source
tables, cascading `LEFT JOIN` paths, scalar comparison and `LIKE` operators,
`IN` predicates, null checks, and `AND`/`OR` combinations into Oracle GORM
clauses; literal values are bound and Oracle numeric Boolean columns are mapped
to `0`/`1`.
Unrecognized joins or predicate syntax, raw queries, and mutations are rejected
with an error. As in the Authz GORM plugin, predicates are skipped for unrelated
association preload tables. Authz schema connections accept `provider: oracle`
and use the Oracle driver when evaluating entity and relation checks. Authz's
own `authz_db` can also use Oracle for principals, grants, and policies; its
Oracle migrations create tables in the connected user's schema. Existing
configurations continue to default to PostgreSQL.

Example Oracle `authz_db` configuration:

```yaml
authz_db:
  provider: oracle
  connect_string: "dbhost:1521/FREEPDB1"
  username: "AUTHZ"
  password: "<secret>"
```

Configure the provider explicitly:

```yaml
storage:
  provider: oracle
  config:
    connect_string: "dbhost:1521/FREEPDB1"
    username: "LAMASSU"
    password: "<secret>"
    max_open_conns: 20
    max_idle_conns: 5
    conn_max_lifetime: "30m"
```

The connection descriptor may use TCPS. Provision a dedicated Oracle user and
schema with permission to create its tables, indexes, views and SQL types. Before
starting services, apply the migrations with credentials supplied through the environment:

```sh
export LAMASSU_ORACLE_CONNECT_STRING='dbhost:1521/FREEPDB1'
export LAMASSU_ORACLE_USERNAME='LAMASSU'
export LAMASSU_ORACLE_PASSWORD='<secret>'
go run ./engines/storage/oracle/cmd/migrate
```

The migrator records a checksum and status for each version and serializes
concurrent runs. Oracle commits DDL implicitly. If a migration fails or is
interrupted, inspect its `STARTED` row in `LAMASSU_SCHEMA_MIGRATIONS` and the
schema state; repair the partial changes before manually reconciling the
migration record. Do not simply retry an interrupted migration. Application
startup checks that all known versions are applied and unchanged.

These migrations create an empty Oracle schema. They do not copy data from an
existing PostgreSQL installation. Oracle treats empty SQL strings as NULL;
some search behavior and field-length limits still require parity validation.
