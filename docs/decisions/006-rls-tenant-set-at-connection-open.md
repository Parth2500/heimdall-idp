# DR-006: Row-level security sets the tenant when a connection opens

- Date: 2026-10-19
- Status: Accepted. Decided by Claude.
- Affects: D20 and the row-level security section of the schema design.

## Before

The first plan was `SET LOCAL app.tenant_id` in each transaction.

## After

`TenantConnectionInterceptor` runs `set_config('app.tenant_id', @tenant, false)` each time EF Core opens a connection.

## Reason

EF Core runs most commands outside an explicit transaction. `SET LOCAL` would need a transaction around every command. Each open sets the value again, and Npgsql resets the session state when a connection returns to the pool.

## Consequences

Each connection open costs one extra round trip. A test turns the Npgsql reset off and checks that the interceptor alone stops a tenant value from leaking to the next request.
