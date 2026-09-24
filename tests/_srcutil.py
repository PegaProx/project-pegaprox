"""Shared helper for the tests that assert against source.

Several regression tests check that a particular guard is present in a particular
handler. They used to do it by slicing a fixed number of characters after the `def`
(`src[i:i + 900]`), which is not the handler - it is a guess about how long the handler
is. Twice in one night a guard that was still there moved past the cutoff because a few
lines were added above it, and the test went red for a reason unrelated to what it
guards. Somebody then has to work out which of the two it is, every time.

Short windows elsewhere (`src[i:i + 60]`) are a different thing: those assert that two
things sit next to each other, and the tightness is the point. Those stay.

MK Sep 2026
"""
import re


def handler_body(src, marker, nested=False):
    """The full body of one definition, from `marker` to the next sibling definition.

    `marker` is normally `'def some_handler('`. Pass nested=True for a method inside a
    class defined in a function, where the next sibling is indented.
    """
    i = src.index(marker)
    rest = src[i + len(marker):]
    if nested:
        pattern = r'\n        def |\n    class |\nclass |\ndef '
    else:
        pattern = r'\n@bp\.route|\ndef |\nclass '
    ends = [m.start() for m in re.finditer(pattern, rest)]
    return src[i:i + len(marker) + (min(ends) if ends else len(rest))]
