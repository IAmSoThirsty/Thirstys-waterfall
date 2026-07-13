# Web API Auth Operator Setup

Status: local evidence only. Target production acceptance still requires target
secret rotation evidence plus target proof that the shared revocation store is
mounted and used by every worker or host that serves API traffic.

## Required Environment

- `THIRSTYS_ENV=production`
- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `THIRSTYS_ADMIN_USERNAME`
- `THIRSTYS_ADMIN_PASSWORD_HASH`
- `CORS_ORIGINS` set to explicit trusted origins, never `*`
- `THIRSTYS_ALLOW_DEMO_LOGIN=false`
- `JWT_REVOCATION_DB_PATH` set to a writable SQLite path shared by every API
  worker/container in the same environment.

## Session Policy

- Access tokens expire after 1 hour.
- Refresh tokens expire after 30 days.
- `/api/auth/logout` revokes the presented access or refresh token JTI in the
  configured revocation store.
- `/api/auth/session-policy` returns token lifetimes and revocation scope for an
  authenticated operator.
- If `JWT_REVOCATION_DB_PATH` is set, the revocation store is SQLite-backed and
  shared by workers that use the same writable database path.

## Remaining Target Requirements

- Run secret rotation on the target host and capture evidence.
- Capture evidence that every target worker/container uses the same
  `JWT_REVOCATION_DB_PATH`.
- Capture target login, logout, revoked-token rejection, and refresh evidence.
