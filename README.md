# Meshery Remote Provider

Starter implementation of a Meshery Remote Provider for Tata Consulting.

This repository provides the documented Meshery remote-provider entrypoints:

- `GET /capabilities`
- `GET /{version}/capabilities`
- `GET /login`
- `GET /logout`

It also includes a small authenticated surface for the capabilities it advertises:

- `GET /api/identity/users/profile`
- `GET /api/users`
- `GET /api/identity/orgs`
- `GET /api/credentials`
- `POST /api/credentials`
- `GET /api/credentials/{id}`
- `PUT /api/credentials/{id}`
- `DELETE /api/credentials/{id}`
- `GET /api/environments`
- `POST /api/environments`
- `GET /api/environments/{id}`
- `PUT /api/environments/{id}`
- `DELETE /api/environments/{id}`
- `GET /api/workspaces`
- `GET /api/connections`
- `POST /api/connections`
- `GET /api/connections/{id}`
- `PUT /api/connections/{id}`
- `DELETE /api/connections/{id}`

## What this scaffold is

This is a starter provider, not a full production identity platform. The login flow is intentionally lightweight so the repository starts with a working Meshery-facing contract:

1. Meshery redirects the browser to `/login?source=<base64-meshery-callback-base-url>`.
2. The provider issues a development token and provider session cookie.
3. The provider redirects back to Meshery at `/api/user/token` with `token` and `session_cookie` query parameters.

## Connections CRUD

The starter provider now exposes an authenticated in-memory Connections API for local development and remote-provider contract testing.

- `GET /api/connections` returns paginated connection data and supports `page`, `pageSize`, `pagesize`, `search`, and `q` query parameters.
- `POST /api/connections` creates a connection from JSON input.
- `GET`, `PUT`, and `DELETE /api/connections/{id}` fetch, update, and remove individual connections.

Connection payloads accept both Meshery-style snake_case fields like `sub_type` and `credential_id` and camelCase variants like `subType` and `credentialId`.

Credential collection requests support `page`, `pageSize`, `pagesize`, `search`, and `q` query parameters, and the list response includes both camelCase and snake_case pagination keys.

Environment collection requests support the same pagination and search query parameters as credentials and connections, and the item endpoint now supports deletion.

## Credentials CRUD

Credentials are stored in-memory for development. The API supports create, list, read, update, and delete operations across `/api/credentials` and `/api/credentials/{id}` and accepts both `subType` and `sub_type`.

## Environments CRUD

Environments are also stored in-memory for development. The API seeds a default environment, supports full CRUD at `/api/environments` and `/api/environments/{id}`, and accepts both `organizationId` and `organization_id`.

## Run locally

```bash
go run ./cmd/provider
```

The server listens on `:8080` by default.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `PORT` | `8080` | HTTP listen port |
| `PUBLIC_BASE_URL` | empty | Public URL reported in the capabilities payload |
| `PROVIDER_NAME` | `Tata Consulting` | Provider display name |
| `PACKAGE_VERSION` | `v0.1.0` | Provider package version surfaced to Meshery |
| `JWT_SECRET` | `change-me-for-real-deployments` | HMAC secret for the development token flow |
| `DEFAULT_USER_ID` | `0f6f66c7-68f4-4b11-8d9a-d5f27f95ad8e` | Default Meshery user UUID |
| `DEFAULT_USER_HANDLE` | `hamza-mohd` | Default external user handle |
| `DEFAULT_USER_EMAIL` | `hamza.mohd@tata-consulting.example` | Default user email |
| `DEFAULT_USER_FIRST_NAME` | `Mohd` | Default user first name |
| `DEFAULT_USER_LAST_NAME` | `Hamza Shaikh` | Default user last name |

## Productionizing

For a production remote provider, replace the development login flow with your real identity system and expand the advertised capabilities only after their backing APIs exist. In practice that usually means:

1. Replacing the development token minting with OIDC or your upstream IdP.
2. Returning real organizations, workspaces, environments, and user data.
3. Serving extension packages if you want provider-backed Meshery UI extensions.
4. Adding token refresh and introspection endpoints if your deployment requires them.
