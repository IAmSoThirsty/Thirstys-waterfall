# Web API Auth Operator Setup

Status: local evidence only. Target production acceptance still requires target
secret rotation evidence and a shared revocation store when more than one worker
or host serves API traffic.

## Required Environment

- `THIRSTYS_ENV=production`
- `SECRET_KEY`
- `JWT_SECRET_KEY`
- `THIRSTYS_ADMIN_USERNAME`
- `THIRSTYS_ADMIN_PASSWORD_HASH`
- `CORS_ORIGINS` set to explicit trusted origins, never `*`
- `THIRSTYS_ALLOW_DEMO_LOGIN=false`

## Session Policy

- Access tokens expire after 1 hour.
- Refresh tokens expire after 30 days.
- `/api/auth/logout` revokes the presented access or refresh token JTI in the
  current process.
- `/api/auth/session-policy` returns token lifetimes and revocation scope for an
  authenticated operator.

## Remaining Target Requirements

- Run secret rotation on the target host and capture evidence.
- Use a shared revocation store for multi-worker or multi-host deployments.
- Capture target login, logout, revoked-token rejection, and refresh evidence.
