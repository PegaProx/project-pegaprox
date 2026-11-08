# API description

`docs/openapi.json` is an OpenAPI 3.1 description of the PegaProx HTTP API. It
exists so that integrations (an Ansible collection, a community Terraform
provider, your own scripts) do not have to reverse engineer the API from the
web UI.

## What it is generated from

It is not written by hand. It is produced from the live Flask route table:

```
venv/bin/python -m pegaprox.cli.gen_openapi -o docs/openapi.json
```

Everything in it that describes *routing and access* is derived from the running
application, so it cannot quietly disagree with the code:

| In the spec | Comes from |
|---|---|
| paths, methods | `app.url_map` |
| path parameters and their types | the werkzeug converter on each rule |
| tags | the blueprint the route belongs to |
| summary, description | the handler docstring |
| `x-pegaprox-permissions`, `x-pegaprox-roles` | the `require_auth` decorator |
| `x-pegaprox-auth` | see below |

Every instance also serves it, built from its own route table, to anyone signed
in (a session or an API token):

```
GET /api/pegaprox/openapi.json
```

The web UI renders that document under user menu > API reference: every route by
area with its method, path, permission, parameters and description, with a search
that also takes a URL copied from the browser (`/api/clusters/c1/vms` finds
`/api/clusters/{cluster_id}/vms`). It only reads; nothing there sends a request to
the routes it lists.

`tests/test_openapi_matches_the_routes.py` regenerates the description and
compares it to the committed file, including the permissions. Add a route, remove
one, or change what a route demands, and that test goes red until the file is
regenerated.

## `x-pegaprox-auth`

Not every route uses the `@require_auth` decorator, and "no decorator" does not
mean "no authentication". Three values:

- `decorator` - guarded by `@require_auth`; any permissions are listed
- `inline` - authenticates itself (websocket handshakes, WebAuthn, the session
  list); it will still answer 401, the decorator is just not how it gets there
- `public` - genuinely reachable without credentials (login, health, the OIDC
  redirect legs, the SPA shell, the opt-in public status page)

## What is NOT in it yet

**Request and response body schemas.** Flask does not carry them, and a guessed
schema is worse than an absent one, so bodies are described as generic JSON
objects. These are being filled in per resource group by hand. If you are
building against a specific endpoint and need its shape pinned down, open an
issue and say which one; that is a much better use of the effort than
speculatively documenting all 839 operations.

## Authentication

Two schemes, both described in the spec:

- `Authorization: Bearer pgx_...` - an API token from Settings > API Tokens.
  This is what automation should use. A token is capped by its own role and by
  what its owner holds at the time of the call, and it reaches no cluster its
  owner cannot. A custom role on a token has to be global or belong to the
  tenant its owner works in; a token whose role no longer resolves there is
  refused.
- `X-Session-ID` - an interactive session from `POST /api/auth/login`. State
  changing calls also need an `Origin` header or `X-Requested-With:
  XMLHttpRequest`, otherwise the CSRF gate rejects them.
