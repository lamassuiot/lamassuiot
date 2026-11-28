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
PostgreSQL query's current sort key. JSON numbers sort by value on both
engines (Oracle `NUMBER`, PostgreSQL `numeric`), including negatives,
decimals and numbers wider than 20 digits; on Oracle, a number outside
`NUMBER`'s range sorts as if it had no value. Character collation and Oracle JSON
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

Authz applies its Oracle migrations at startup and records them in
`AUTHZ_SCHEMA_MIGRATIONS`. Oracle commits each DDL statement on its own, so
before a migration runs it is recorded as started (`is_applied = 0`), and it
is marked applied (`is_applied = 1`) once it succeeds. If a migration fails or
is interrupted, its row stays at `0` and Authz refuses to start with
`Authz Oracle migration did not finish: manual recovery required`, naming the
version. To recover:

1. Compare the schema with that version's file in
   `connectors/authz/pkg/store/oracle_migrations/` to see which statements were
   applied.
2. Either undo those changes and delete the row
   (`DELETE FROM AUTHZ_SCHEMA_MIGRATIONS WHERE version_id = <version> AND is_applied = 0`),
   so the migration runs again, or apply the remaining statements by hand and
   mark it applied (`UPDATE AUTHZ_SCHEMA_MIGRATIONS SET is_applied = 1 WHERE version_id = <version>`).
3. Restart Authz.

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
existing PostgreSQL installation. Oracle treats empty SQL strings as NULL.
String filters treat NULL in character columns as the empty string PostgreSQL
stores, so "not equal", "not contains" and "not in" keep rows with an empty
value, and empty items in "in" lists are ignored, as on PostgreSQL. Columns
that PostgreSQL also stores as NULL (a certificate's `key_id`, a group's
`parent_id`) are compared as NULL. Equality and list filters on CLOB columns
are evaluated with escaped `LIKE` patterns, because Oracle cannot compare CLOB
values with `=`. Field-length limits still require parity validation.

Sorting by `metadata` with a JSONPath expression
(`sort_by=metadata[jsonpath]$.env`) is supported for certificates, CAs, DMS,
devices and KMS keys, with the same order as PostgreSQL. A plain
`sort_by=metadata` follows Oracle's JSON ordering, which differs from
PostgreSQL's `jsonb` ordering; use a JSONPath expression when the order must
match. Some sorts that PostgreSQL accepts are rejected on Oracle:

- KMS `public_key` (a CLOB) and `tags` (a JSON array).
- JSONPath sorts on Authz principals and policies when the Authz database is
  Oracle; the API answers them with 400.

Character columns are ordered and paginated with
`NLSSORT(column, 'NLS_SORT=BINARY')`, so results match PostgreSQL's binary
ordering whatever the session's `NLS_SORT` or `NLS_COMP` (the driver derives
them from the client's `NLS_LANGUAGE`). Migration 9 adds function-based indexes
on those expressions for the columns each repository paginates by, so the first
page and each keyset page are served by an index range scan. With
`NLS_COMP=LINGUISTIC` set explicitly, Oracle still returns correct results but
sorts the rows after the keyset cursor instead of stopping after one page.
Under `MAX_STRING_SIZE=STANDARD`, `NLSSORT` truncates its key to 2000 bytes,
so two identifiers that share their first 2000 bytes would compare as equal;
this needs identifiers of over 500 four-byte characters.
