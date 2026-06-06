# mini-oauth2

A minimal, from-scratch OAuth2-style system built with Spring Boot. It has two independent services:

- **Auth server** (`:9000`) — authenticates users/clients and issues, refreshes and revokes JWTs.
- **Resource server** (`:8081`) — validates those JWTs and serves a sample protected `payments` API.

Access/refresh tokens are HS256 JWTs (hand-rolled, `at+jwt` / `rt+jwt`). A shared **Redis**
store holds access-token revocations so the resource server can reject a revoked token instantly. The
auth server uses an in-memory **H2** database (PostgreSQL-compatible SQL).

## Layout

Single Maven module, two `@SpringBootApplication` entry points, packages by responsibility:

```
ru.yandex.practicum.oauth0
├── common   # shared: AuthProperties, JwtCodec (manual HS256), RevocationStore (Redis + in-memory)
├── auth     # AuthApp: controller / service / dto / repository / model — issues & manages tokens
└── rs       # ResourceApp: JwtAuthFilter (401) + ScopeChecker (403) + PaymentsController
```

`mvn package` builds two runnable jars via classifier executions: `target/oauth-zero-1.0-SNAPSHOT-auth.jar`
and `…-rs.jar`.

## Configuration

| Setting | Where | Default |
|---|---|---|
| `accessttl`, `refreshttl`, `skew`, `issuer` | `config/auth.json` | 900s / 30d / 30s / `mini-oauth2` |
| `auth_secret` (HMAC key, Base64) | **`AUTH_SECRET` env var** | _(empty in JSON on purpose)_ |
| client_credentials scopes | `oauth.client-scopes.<clientId>` in `application.properties` | `payments-service` → read+write |

The signing secret is never committed: `config/auth.json` leaves `auth_secret` blank and both services
read it from the `AUTH_SECRET` environment variable. Copy the example env file (it carries a throwaway
dev key) before running:

```bash
cp .env.example .env        # provides AUTH_SECRET; .env is git-ignored
```

## Run with Docker Compose

Brings up Redis + both services:

```bash
cp .env.example .env
docker compose up --build
```

- Auth server → http://localhost:9000
- Resource server → http://localhost:8081

## Run locally (without Docker)

Needs a Redis on `localhost:6379` (`docker run -p 6379:6379 redis:7-alpine`, or `redis-server`), then:

```bash
export AUTH_SECRET=9Sg24fTI7Obt8+IoDlNQqiT9dkOzgzDrO2YasMKdMBQ=

# Terminal 1 — auth server (:9000)
mvn spring-boot:run -Dspring-boot.run.main-class=ru.yandex.practicum.oauth0.auth.AuthApp

# Terminal 2 — resource server (:8081)
mvn spring-boot:run -Dspring-boot.run.main-class=ru.yandex.practicum.oauth0.rs.ResourceApp
```

Or build once and run the jars: `mvn -DskipTests package` then
`java -jar target/oauth-zero-1.0-SNAPSHOT-auth.jar` and `…-rs.jar`.

## Seeded data

| Principal | Credentials | Scopes |
|---|---|---|
| user `alice` | `alice` / `password` | `payments:read`, `payments:write` |
| user `bob` | `bob` / `password` | `payments:read` |
| client `payments-service` | `payments-service` / `secret` | `payments:read`, `payments:write` |

## Endpoints

| Method | Path | Auth | Notes |
|---|---|---|---|
| POST | `/token?grantType=PASSWORD` | JSON body `{username,password}` | → access **+ refresh** |
| POST | `/token?grantType=CLIENT_CREDENTIALS` | `Authorization: Basic` | → access only |
| POST | `/token/refresh` | JSON body `{refreshToken}` | rotates; replay → 400 + family revoked |
| POST | `/token/revoke` | `Authorization: Basic` + `{token}` | always 200 on valid client auth |
| GET | `/api/payments` | `Authorization: Bearer` | needs scope `payments:read` |
| POST | `/api/payments` | `Authorization: Bearer` | needs scope `payments:write` |

Status codes: bad credentials → **401**; bad/expired/replayed refresh → **400**; bad/expired/revoked
access token at the resource server → **401**; valid token without the required scope → **403**.

## Example requests

Get a token as a user (password grant) and capture the access token:

```bash
curl -s -X POST 'http://localhost:9000/token?grantType=PASSWORD' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password"}'
# => {"accessToken":"<jwt>","tokenType":"Bearer","expiresIn":900,"refreshToken":"<jwt>"}

AT=$(curl -s -X POST 'http://localhost:9000/token?grantType=PASSWORD' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"password"}' \
  | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p')
```

Call the protected API:

```bash
curl -i http://localhost:8081/api/payments -H "Authorization: Bearer $AT"          # 200
curl -i -X POST http://localhost:8081/api/payments -H "Authorization: Bearer $AT" \
  -H 'Content-Type: application/json' -d '{"amount":4200,"currency":"USD"}'         # 200
```

Service-to-service token (client_credentials — no refresh token):

```bash
curl -s -X POST 'http://localhost:9000/token?grantType=CLIENT_CREDENTIALS' \
  -u 'payments-service:secret'
```

Refresh (rotates the pair):

```bash
RT=$(curl -s -X POST 'http://localhost:9000/token?grantType=PASSWORD' \
  -H 'Content-Type: application/json' -d '{"username":"alice","password":"password"}' \
  | sed -n 's/.*"refreshToken":"\([^"]*\)".*/\1/p')

curl -s -X POST http://localhost:9000/token/refresh \
  -H 'Content-Type: application/json' -d "{\"refreshToken\":\"$RT\"}"
```

Revoke an access token (then the resource server returns 401 for it):

```bash
curl -i -X POST http://localhost:9000/token/revoke \
  -u 'payments-service:secret' \
  -H 'Content-Type: application/json' -d "{\"token\":\"$AT\"}"
```

## Tests

Integration tests cover every endpoint (200/400/401/403, rotation and reuse-detection). They use an
in-memory revocation store, so **no Docker/Redis is required**:

```bash
mvn test
```

## Notes / design choices

- **Manual JWT (HS256)** via `javax.crypto.Mac` + Base64URL — no JWT library (`common/jwt/JwtCodec`).
- The access-token scope claim is named **`scope`** (space-delimited, per RFC 9068).
- Clients have no roles in the data model, so **client_credentials scopes come from configuration**.
- Refresh reuse: replaying a rotated token marks the whole `family_id` revoked (committed in its own
  transaction) and returns 400, forcing re-authentication.
- Local/Docker runs use **H2** (PostgreSQL-compatible DDL in `schema.sql`); a Postgres profile can be
  added for production.
