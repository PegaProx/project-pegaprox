"""Every family a compliance mapping names has a label for the report.

The BSI IT-Grundschutz refs of the password and access controls sit in ORP.4, and
FAMILY_LABELS had no ORP, so the BSI and VS-NfD reports showed the bare code with a dash
for its name in the coverage table. The walk covers every framework, so a family added to
a mapping without its label shows up here.
"""
import pytest

from pegaprox.core import compliance_mapping as cm


def test_every_mapped_family_has_a_label():
    missing = {}
    for fw, mapping in cm.FRAMEWORK_MAPPING.items():
        for control, refs in mapping.items():
            for ref in refs:
                if ref.get('family') not in cm.FAMILY_LABELS:
                    missing.setdefault(ref.get('family'), set()).add(f'{fw}:{control}')
    assert not missing, missing


@pytest.mark.parametrize('framework', ['bsi', 'vs-nfd'])
def test_the_mapping_route_names_the_orp_layer(api, seed, framework):
    r = api.as_user(seed.user('root_admin', role='admin')).get(f'/api/compliance/mapping?framework={framework}')
    assert r.status_code == 200, r.get_data(as_text=True)
    body = r.get_json()
    families = {ref['family'] for refs in body['mapping'].values() for ref in refs}
    assert 'ORP' in families
    assert body['family_labels']['ORP'] == 'Organisation und Personal'
