# PegaProx test suite

## Authorization / tenant-isolation regression suite

The single biggest security risk in a multi-tenant cluster manager is **broken
access control** (BOLA / IDOR / tenant escape) — and static scanners (Aikido,
CodeAnt) can't see logic-level authorization bugs. Historically these were caught
only by hand review (#490 / #493 / #495 / #555 …). This suite turns those
invariants into permanent, executable guards so they can't silently regress.

### Running

```bash
pip install -r requirements-dev.txt   # once
python -m pytest                       # from the repo root
```

No live PVE/ESXi/XCP-ng cluster is required. `user_can_access_vm`,
`get_user_clusters`, `has_permission` etc. only read the DB (users, tenants,
vm_acls, pool_permissions), so each test seeds a **throwaway encrypted DB** in a
temp dir and asserts an access decision.

### How the harness works (`conftest.py`)

* `gevent.monkey.patch_all()` runs first (auth/db import gevent internals).
* The `db` fixture points `pegaprox.core.db.{CONFIG_DIR,DATABASE_FILE,KEY_FILE}`
  at a per-test temp dir, resets **both** DB singletons (`_db` and
  `PegaProxDB._instance`), and clears rbac's process-global caches
  (`tenants_db`, `_custom_roles_cache`, `_vm_acls_cache`, `_pool_membership_cache`)
  so tests are fully order-independent.
* The `seed` fixture exposes `seed.user()`, `seed.tenant()`, `seed.vm_acl()`,
  `seed.pool()` bound to that DB.

### Files

| File | Covers |
|------|--------|
| `test_authz_isolation.py` | cross-tenant BOLA, cluster scoping, VM-ACL additive/restrictive model, the #555 pool/ACL cluster-reach guard, admin bypass, denied-perm subtraction |
| `test_authz_api_token.py` | API-token privilege floor (`min(token, owner)`), no admin-bypass for an admin-owned viewer token, mint-ceiling |
| `test_authz_pool.py` | pool.admin vs granular pool perms, pool grant does not leak to non-member VMs or across clusters |

### Broken-access-control regression guard

`test_vm_acl_inherit_role_false_restricts_to_listed_perms` guards a
**broken-access-control bug that has been fixed**: the `vm_acls` table now has
an `inherit_role` column (added with an idempotent migration), so an ACL saved
with `inherit_role=False` (the UI's "custom permissions" mode) is honoured and
`user_can_access_vm` restricts to the listed perms instead of granting full
access. Coercion is strict on both write paths, so a stringy `"false"` cannot
re-broaden access. The test now passes as a plain assertion (no `xfail`); keep
it — it fails if the column, migration, or restrictive read is ever regressed.
