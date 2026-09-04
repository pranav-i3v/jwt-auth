# authz-starter (jwt-auth)

Production-grade Spring Boot 3.x / Spring Security 6.x starter that provides **JWT (RS256)
validation and endpoint authorization** for GAS microservices. This library is
**validation-only** - it never issues, signs, or refreshes tokens (that responsibility belongs
exclusively to `auth-service`).

## What it does

1. Fetches the RSA public key (PEM, X.509 SubjectPublicKeyInfo) from **AWS Secrets Manager** and
   caches it in-memory, refreshing every `authz.public-key.cache-ttl` (default: 1 hour).
2. Registers a `JwtAuthenticationFilter` (plain `jakarta.servlet.Filter`, so it re-validates on
   every dispatch it is registered for - not just the initial `REQUEST` one):
   - Extracts and validates the `Authorization: Bearer <jwt>` header.
   - Rejects missing / malformed / expired / bad-signature tokens with **401**.
   - Rejects blacklisted tokens (`token_blacklist` table) with **401**.
   - Populates claims (`userId`, `username`, `roles`, `permissions`, `region`, `zone`) into the
     Spring Security `SecurityContext` as an `AuthenticatedUser` principal.
   - Calls the `sp_check_endpoint_authorization` stored procedure to authorize the specific
     endpoint + HTTP method; denies with **403** on failure.
   - Records every request outcome to `endpoint_access_log` (async by default).
3. Ships a default, stateless `SecurityFilterChain` so it works out-of-the-box; consuming services
   can override any bean (`@ConditionalOnMissingBean` throughout).

## Data access

All database work sits in `com.pranav.jwtauth.repository`; `AuthorizationService` holds only policy
(the `authz.*` enable flags, fail-closed blacklist behaviour, fail-open/fail-closed handling of
authorization errors) and no SQL.

| Repository | Backing | Table / call |
| --- | --- | --- |
| `TokenBlacklistRepository` | Spring Data JPA | `token_blacklist` (read) |
| `EndpointAccessLogRepository` | Spring Data JPA | `endpoint_access_log` (insert) |
| `EndpointAuthorizationRepository` | Spring Data JPA, `@Query(nativeQuery = true)` | `sp_check_endpoint_authorization` |

`EndpointAuthorizationRepository.checkEndpointAuthorization` calls the routine with
`SELECT ... FROM sec.sp_check_endpoint_authorization(:userId, :endpointPath, :httpMethod)`. This
relies on PostgreSQL's ability to select from a function with `OUT` parameters directly in a `FROM`
clause - the result columns are named after the `OUT` parameters. Columns are aliased in the query to
match the `EndpointAuthorizationRow` projection's accessor names, so the mapping is by column name,
not ordinal - a column reordering in the routine won't silently flip authorization decisions.

Because `@Query` is a compile-time annotation, the function name in it is a literal, not the runtime
`authz.authorization.stored-procedure-name` property - a JDBC bind parameter can carry a value, not
a SQL identifier. If your routine has a different name, declare your own
`EndpointAuthorizationRepository` bean (`@ConditionalOnMissingBean` backs off automatically).

Two notes for consuming services:

- The library's entities are registered with the application's `EntityManagerFactory` automatically
  (`AuthzEntityScanRegistrar`), alongside - not instead of - the application's own entity packages.
- Both entities assume the table's primary key column is named `id`. Adjust the `@Column(name = ...)`
  on `TokenBlacklistEntry.id` / `EndpointAccessLog.id` if your schema differs.

## Adding to a microservice

```xml
<dependency>
    <groupId>com.pranav</groupId>
    <artifactId>jwt-auth</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

The consuming service must supply a `javax.sql.DataSource` (a JDBC driver + `spring.datasource.*`)
pointing at the shared auth database, and AWS credentials resolvable via the default AWS credential
provider chain (env vars, instance profile, IRSA, etc.).

This starter depends on `spring-boot-starter-data-jpa`, so services that pull it in get Hibernate
and an `EntityManagerFactory` whether or not they use JPA themselves. Keep `spring.jpa.hibernate.ddl-auto`
at its default (`none` for non-embedded databases) - this library never generates schema.

## Configuration

See `authz.*` properties in `JwtProperties`. Minimal example:

```yaml
authz:
  issuer: gas-auth-service
  public-key:
    secret-name: gas/auth/jwt-public-key
    region: ap-south-1

spring:
  datasource:
    url: jdbc:mysql://localhost:3306/gas_auth
    username: gas_app
    password: ${DB_PASSWORD}
```

## Expected authorization function contract

Must live in the `sec` schema and be selectable from a `FROM` clause - a PostgreSQL function with
`OUT` parameters, not a `PROCEDURE`:

```sql
CREATE FUNCTION sec.sp_check_endpoint_authorization(
    p_user_id BIGINT, p_endpoint_path VARCHAR, p_http_method VARCHAR,
    OUT p_is_authorized BOOLEAN,
    OUT p_authorization_reason VARCHAR
) RETURNS record ...
```

Expected to return a single row. `EndpointAuthorizationResult.mfaRequired` / `.rateLimited` /
`.message` are not populated by this routine and stay at their defaults (`false` / `null`).
