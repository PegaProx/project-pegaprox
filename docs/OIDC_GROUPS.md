# Custom OIDC group claims

PegaProx reads group memberships from the `groups` claim in the ID token by
default. If your provider uses another name, open **Settings → OIDC / Entra ID →
Advanced**, set **Groups claim** to that name, and save the OIDC settings.

For example, an Okta application that issues:

```json
{"groups_proxmox": ["proxmox-operators", "proxmox-admins"]}
```

uses `groups_proxmox` in this field. Existing group-to-role mappings still use the
group values, such as `proxmox-operators`. The setting is saved in the database
and survives application updates; no source modification is needed. An
administrator can also save it as `oidc_groups_claim` through
`POST /api/settings/server`.

The name is an exact, case-sensitive top-level ID-token key, not a dotted path.
Names containing dots or URI syntax are supported. Blank restores `groups`;
names are limited to 256 printable characters. Configure your provider to include
the claim as a JSON array of group values in the ID token, with the scopes required
by that provider. This option
does not read additional claims from UserInfo or change Entra Graph group fetching.

When a custom name is set, PegaProx does not fall back to `groups`. An explicitly
empty list can revoke group-derived access, while a missing claim or a claim
marked as incomplete preserves the existing completeness rules. Test with a
non-administrator account and retain a local administrator login while changing
identity-provider mappings.
