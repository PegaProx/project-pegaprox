"""Generate an OpenAPI 3.1 description of the PegaProx HTTP API.

MK Sep 2026 (#104, #693) - external tooling (an Ansible collection, a community
Terraform provider) kept stalling on the same thing: there is no machine-readable
description of the API. Hand-writing one for 800-odd routes would be stale the
week after, so this reads the live Flask url_map instead and is regenerated from
the running app.

What is derived, and therefore trustworthy:
  * paths, methods, path parameters (typed from the werkzeug converter)
  * the blueprint each route belongs to (tag)
  * the handler docstring (summary + description)
  * the permissions / roles require_auth demands, published as _pp_auth and
    emitted as x-pegaprox-permissions so a generator can reason about scope

What is NOT derived: request and response BODY schemas. Flask does not carry
them and guessing would be worse than leaving them out, so bodies are described
as generic JSON objects. Those are filled in per resource group by hand; see
docs/openapi-schemas.md for which ones are done.

Usage:  venv/bin/python -m pegaprox.cli.gen_openapi [-o openapi.json]
"""
import argparse
import inspect
import json
import re
import sys

# A handler without @require_auth is not automatically public: several
# authenticate inline (the websocket-adjacent ones, webauthn, the session list)
# because they answer 401 themselves rather than through the decorator. Calling
# those "unauthenticated" in a published spec would be a lie, so the handler is
# checked for the helpers that actually establish an identity (_code_refs).
_INLINE_AUTH = ('_require_session', 'validate_session(', 'validate_api_token(',
                'validate_ws_token', 'validate_sse_token', 'WS_INTERNAL_SECRET',
                '_metrics_token', 'metrics_public',
                # MK Sep 2026 - the automated installer presents an installation
                # token; it has no session and never will, but it is not public.
                '_profile_for_token', '_run_for_callback_token',
                # #625 - the other PegaProx instance of a standby pair
                '_peer_or_refuse', 'accept_pairing',
                # and its witness: the code at pairing, its signature after
                'accept_witness', 'witness_verdict', 'request_witness')

# ...and those two take that token only, so advertising apiToken/sessionId on them
# sends an integrator straight into a 403.
_INSTALL_TOKEN_AUTH = ('_profile_for_token', '_run_for_callback_token')

# Same for the standby pair: the peer header and nothing else. The pairing route
# is authenticated by the one-time code in its body, which no scheme describes.
_HA_PEER_AUTH = ('_peer_or_refuse', 'witness_verdict', 'request_witness')
_HA_PAIRING_AUTH = ('accept_pairing', 'accept_witness')
# the witness code bundle: the witness's signature, or the open witness code in the body
_HA_WITNESS_CODE = ('witness_code_ok',)

_CONVERTER_TYPES = {
    'int': ('integer', None),
    'float': ('number', None),
    'string': ('string', None),
    'path': ('string', 'path'),
    'uuid': ('string', 'uuid'),
    'default': ('string', None),
}

# Not part of the public API surface: the SPA shell, static assets, the health
# probe's unauthenticated twin and the websocket upgrade endpoints (a socket is
# not describable as an OpenAPI operation).
_SKIP_ENDPOINT = re.compile(r'^(static|.*\.static)$')
_SKIP_RULE = re.compile(r'^/(static|images|favicon|assets)\b|websocket|/ws/')


def _split_rule(rule):
    """werkzeug rule -> (openapi path, [parameter objects])"""
    params, out = [], []
    for part in re.split(r'(<[^>]+>)', str(rule)):
        if not part.startswith('<'):
            out.append(part)
            continue
        inner = part[1:-1]
        conv, _, name = inner.rpartition(':')
        conv = (conv or 'default').split('(')[0]
        typ, fmt = _CONVERTER_TYPES.get(conv, _CONVERTER_TYPES['default'])
        schema = {'type': typ}
        if fmt:
            schema['format'] = fmt
        params.append({'name': name, 'in': 'path', 'required': True, 'schema': schema})
        out.append('{%s}' % name)
    return ''.join(out), params


def _code_refs(fn):
    """(names, strings) of the compiled handler, nested functions included: every
    global and attribute it looks up, and every string constant it holds.

    MK Sep 2026 (#625) - this used to read the source text. inspect.getsource takes
    the line numbers from the code object and the lines from the file as it is on
    disk now, so an edit to the module while the app was up (a test run next to the
    editor) handed back the wrong block, and /api/ha/peer/snapshot and step-down
    were written down as 'public'. The code object is what runs."""
    code = getattr(inspect.unwrap(fn), '__code__', None)
    if code is None:
        return None
    names, strings, todo = set(), [], [code]
    while todo:
        code = todo.pop()
        names.update(code.co_names)
        for const in code.co_consts:
            if inspect.iscode(const):
                todo.append(const)
            elif isinstance(const, str):
                strings.append(const)
    return names, strings


def _refers_to(refs, markers):
    names, strings = refs
    for tok in markers:
        tok = tok.rstrip('(')
        # a name it calls, or one it mentions in a string (the settings key metrics_public)
        if tok in names or any(tok in s for s in strings):
            return True
    return False


def _auth_kind(fn, decorated):
    """'decorator' | 'inline' | 'public' - how this route establishes identity."""
    if decorated:
        return 'decorator'
    refs = _code_refs(fn)
    if refs is None:
        return 'unknown'
    return 'inline' if _refers_to(refs, _INLINE_AUTH) else 'public'


def _uses(fn, markers):
    refs = _code_refs(fn)
    return refs is not None and _refers_to(refs, markers)


def _doc(fn):
    src = inspect.unwrap(fn)
    doc = inspect.getdoc(src) or ''
    if not doc:
        return None, None
    head, _, rest = doc.partition('\n\n')
    return ' '.join(head.split()), (rest.strip() or None)


def build(app):
    paths = {}
    for rule in app.url_map.iter_rules():
        if _SKIP_ENDPOINT.match(rule.endpoint) or _SKIP_RULE.search(str(rule)):
            continue
        fn = app.view_functions.get(rule.endpoint)
        if fn is None:
            continue
        path, params = _split_rule(rule)
        auth = getattr(fn, '_pp_auth', None)
        summary, description = _doc(fn)
        tag = rule.endpoint.split('.')[0]
        for method in sorted(rule.methods - {'HEAD', 'OPTIONS'}):
            op = {
                'operationId': f"{rule.endpoint}_{method.lower()}",
                'tags': [tag],
                'responses': {
                    '200': {'description': 'Success'},
                    '400': {'description': 'Bad request'},
                },
            }
            if summary:
                op['summary'] = summary
            if description:
                op['description'] = description
            if params:
                op['parameters'] = params
            if method in ('POST', 'PUT', 'PATCH'):
                op['requestBody'] = {
                    'required': False,
                    'content': {'application/json': {'schema': {'type': 'object'}}},
                }
            kind = _auth_kind(fn, auth is not None)
            op['x-pegaprox-auth'] = kind
            if kind in ('decorator', 'inline'):
                op['security'] = [{'apiToken': []}, {'sessionId': []}]
                op['responses']['401'] = {'description': 'Not authenticated'}
            if kind == 'inline' and _uses(fn, _INSTALL_TOKEN_AUTH):
                op['security'] = [{'installToken': []}]
                op['responses'].pop('401', None)
                op['responses']['403'] = {'description': 'Unknown, revoked or spent token'}
            if kind == 'inline' and _uses(fn, _HA_PEER_AUTH) and _uses(fn, _HA_WITNESS_CODE):
                # MK Oct 2026 (#625): or no scheme at all, the open code in the body
                op['security'] = [{'haPeer': []}, {}]
                op['responses']['401'] = {'description': 'Not the witness of this group'}
                op['responses']['403'] = {'description': 'Wrong, expired or spent witness code'}
            elif kind == 'inline' and _uses(fn, _HA_PEER_AUTH):
                op['security'] = [{'haPeer': []}]
                op['responses']['401'] = {'description': 'Not the paired instance'}
                op['responses']['410'] = {'description': 'HA_REMOVED: the caller was removed '
                                                         'from the group'}
            elif kind == 'inline' and _uses(fn, _HA_PAIRING_AUTH):
                op['security'] = []
                op['responses'].pop('401', None)
                op['responses']['403'] = {'description': 'Wrong, expired or spent pairing code'}
            if auth is not None:
                if auth['perms'] or auth['roles']:
                    op['responses']['403'] = {'description': 'Insufficient permissions'}
                if auth['perms']:
                    op['x-pegaprox-permissions'] = auth['perms']
                if auth['roles']:
                    op['x-pegaprox-roles'] = auth['roles']
            _place(app, paths, path, method.lower(), op, rule.endpoint)
    _dedupe_operation_ids(paths)
    return paths


def _place(app, paths, path, method, op, endpoint):
    """Write one operation, resolving a doubly-registered URL the way the app does.

    MK Sep 2026 (daily scan) - seven URLs carry two registrations from two
    blueprints. An OpenAPI document can hold one operation per path+method, and
    a plain assignment kept whichever iter_rules() yielded last. For two of the
    seven that is a different handler with a different permission, so the
    document named a permission the app does not enforce: /ha GET advertised
    cluster.view while the served handler demands ha.view. Anyone provisioning a
    token from the document got a 403.

    werkzeug's own matcher decides, because it is what answers the request. The
    loser is recorded rather than dropped - a second registration on a live URL
    is worth seeing, and silently hiding it is how it stayed unnoticed.
    """
    slot = paths.setdefault(path, {})
    previous = slot.get(method)
    if previous is None:
        slot[method] = op
        return
    served = _served_endpoint(app, path, method)
    keep, drop = (op, previous) if served == endpoint else (previous, op)
    shadowed = list(keep.get('x-pegaprox-shadowed-by', []))
    for other in (drop.get('operationId', '').rsplit('_', 1)[0],):
        if other and other not in shadowed:
            shadowed.append(other)
    keep['x-pegaprox-shadowed-by'] = shadowed
    slot[method] = keep


_PLACEHOLDER = re.compile(r'\{[^}]+\}')


def _served_endpoint(app, path, method):
    """Which endpoint werkzeug picks for this path+method, or None."""
    probe = _PLACEHOLDER.sub('x1', path)
    try:
        return app.url_map.bind('localhost').match(probe, method=method.upper())[0]
    except Exception:
        return None


def _dedupe_operation_ids(paths):
    """operationId has to be unique across the document.

    A handful of handlers are registered on more than one rule (path aliases),
    so endpoint+method alone collides. Disambiguate the whole colliding group -
    not just the later members - so the ids stay stable no matter what order
    iter_rules() hands them back in.
    """
    from collections import defaultdict
    seen = defaultdict(list)
    for path, ops in paths.items():
        for method, op in ops.items():
            seen[op['operationId']].append((path, method))
    for base, where in seen.items():
        if len(where) < 2:
            continue
        for path, method in where:
            slug = re.sub(r'[^a-zA-Z0-9]+', '_', path).strip('_')
            paths[path][method]['operationId'] = f"{base}__{slug}"



def spec(app, version):
    return {
        'openapi': '3.1.0',
        'info': {
            'title': 'PegaProx API',
            'version': version,
            'description': (
                'Multi-cluster management API for Proxmox VE, ESXi and XCP-ng.\n\n'
                'Generated from the live route table. Path, method, parameter, tag '
                'and permission information is derived from the application itself. '
                'Request and response body schemas are being filled in per resource '
                'group and are described as generic objects until then.'
            ),
            'license': {'name': 'AGPL-3.0-only',
                        'url': 'https://www.gnu.org/licenses/agpl-3.0.html'},
        },
        'servers': [{'url': '/', 'description': 'The PegaProx instance itself'}],
        'components': {
            'securitySchemes': {
                'apiToken': {
                    'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'pgx_*',
                    'description': 'An API token from Settings > API Tokens. '
                                   'Send as: Authorization: Bearer pgx_...',
                },
                'installToken': {
                    'type': 'http', 'scheme': 'bearer', 'bearerFormat': 'pgxai_*',
                    'description': 'An automated-installation token. The installer sends it '
                                   'as Authorization: Bearer <name>:<token> '
                                   '(--answer-auth-token); ?token=<token> works too.',
                },
                'haPeer': {
                    'type': 'apiKey', 'in': 'header', 'name': 'X-PegaProx-Peer',
                    'description': 'Only for the other members of a standby group: the '
                                   'instance id of the caller, with X-PegaProx-Peer-Ts, '
                                   '-Nonce and -Sig, an Ed25519 signature over method, '
                                   'path, body, time, nonce and the instance id of the '
                                   'receiver, under the key every other member holds since '
                                   'the pairing. A member paired before the keys sends '
                                   '<its instance id>:<its own secret> until it has '
                                   'published one.',
                },
                'sessionId': {
                    'type': 'apiKey', 'in': 'header', 'name': 'X-Session-ID',
                    'description': 'A session id from POST /api/auth/login. '
                                   'State-changing calls also need an Origin header '
                                   'or X-Requested-With: XMLHttpRequest for the CSRF gate.',
                },
            },
        },
        'paths': spec_paths(app),
    }


def spec_paths(app):
    return build(app)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split('\n')[0])
    ap.add_argument('-o', '--out', default='openapi.json')
    args = ap.parse_args(argv)

    from pegaprox.app import create_app
    from pegaprox.constants import PEGAPROX_VERSION

    app = create_app()
    doc = spec(app, PEGAPROX_VERSION)
    with open(args.out, 'w', encoding='utf-8') as fh:
        json.dump(doc, fh, indent=2, ensure_ascii=False, sort_keys=False)
        fh.write('\n')
    ops = sum(len(v) for v in doc['paths'].values())
    gated = sum(1 for p in doc['paths'].values() for o in p.values()
                if 'x-pegaprox-permissions' in o or 'x-pegaprox-roles' in o)
    from collections import Counter
    kinds = Counter(o.get('x-pegaprox-auth') for p in doc['paths'].values()
                    for o in p.values())
    print(f"{args.out}: {len(doc['paths'])} Pfade, {ops} Operationen, "
          f"{gated} mit Rechte-Angabe")
    print("  Authentifizierung: " + ', '.join(f"{k}={v}" for k, v in sorted(kinds.items())))
    return 0


if __name__ == '__main__':
    sys.exit(main())
