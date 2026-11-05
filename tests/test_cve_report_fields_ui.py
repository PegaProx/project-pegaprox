"""The CVE Scanner of the classic layouts sorts and prints what the scan sends.

A scan row carries `cve` and `urgency` (manager.scan_node_packages). The PDF export read
`cve_id` and `severity`, so every row of the report printed "-", and the table sorted with
`order[u] || 1`, which files high (0) together with medium. Both pieces are taken from the
built bundle and run in the browser on rows of the scan's shape. LW Nov 2026
"""
import os
import re

from test_ha_ui import browser  # noqa: F401

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ROWS = [
    {'cve': 'CVE-2026-0002', 'package': 'libssl3', 'urgency': 'medium', 'fix_type': 'apt'},
    {'cve': 'CVE-2026-0001', 'package': 'openssh-server', 'urgency': 'high', 'fix_type': 'apt'},
    {'cve': 'CVE-2026-0003', 'package': 'curl', 'urgency': 'low', 'fix_type': 'pve_upgrade'},
    {'cve': 'CVE-2026-0004', 'package': 'bash', 'urgency': 'unknown', 'fix_type': 'apt'},
]


def _bundle():
    with open(os.path.join(ROOT, 'web', 'index.html'), encoding='utf-8') as fh:
        return fh.read()


def _piece(pattern):
    found = re.findall(pattern, _bundle(), re.S)
    assert len(found) == 1, (pattern, len(found))
    return found[0]


def _run(browser, expr):  # noqa: F811
    ctx = browser.new_context()
    try:
        page = ctx.new_page()
        return page.evaluate(f'(rows) => ({expr})', ROWS)
    finally:
        ctx.close()


def test_the_table_puts_high_before_medium(browser):  # noqa: F811
    cmp = _piece(r'node\.cves\.sort\((\(a,\s*b\)\s*=>\s*\{\s*const order\s*=\s*\{\s*high:\s*0.*?\})\)\.map')
    order = _run(browser, f'rows.slice().sort({cmp}).map(r => r.urgency)')
    # an urgency the table does not know stays beside medium, as before
    assert order == ['high', 'medium', 'unknown', 'low'], order


def test_the_pdf_rows_print_the_cve_and_its_urgency(browser):  # noqa: F811
    mapper = _piece(r"rows:\s*node\.cves\.map\((c\s*=>\s*\[[^\]]*c\.fix_type[^\]]*\])\)")
    rows = _run(browser, f'rows.map({mapper})')
    assert rows[1] == ['CVE-2026-0001', 'openssh-server', 'high', 'apt'], rows
    assert all(r[0].startswith('CVE-') and r[2] != '-' for r in rows), rows
