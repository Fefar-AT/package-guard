"""The recognition table: one source of truth for what counts as acquisition.

The table is DATA, in `recognition.json`, loaded here at import. `parser.py`
keeps no verb list of its own, so a verb cannot be added to the parser without
adding it to the table.

One table, not two vocabularies: a loose regex over raw text and a tokenized
dispatcher kept by hand will drift apart, and a verb one knows and the other
does not becomes an ungated install (`uv sync 2>&1 | tail -40` is the shape).

Standard library only.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

TABLE_PATH = Path(__file__).resolve().parent / "recognition.json"
TABLE = json.loads(TABLE_PATH.read_text(encoding="utf-8"))

METACHARS = set(TABLE["metacharacters"])
PEEL_WRAPPERS = set(TABLE["peel_wrappers"])
RECURSIVE_WRAPPERS = set(TABLE["recursive_wrappers"])
CD_COMMANDS = set(TABLE["cd_commands"])
FOREIGN = TABLE["foreign"]["managers"]
FOREIGN_SAFE = set(TABLE["foreign"]["safe_verbs"])

INSTALLERS = TABLE["installers"]
_BY_HEAD = {}
for _inst in INSTALLERS:
    for _head in _inst["heads"]:
        _BY_HEAD[_head] = _inst

_NPM = _BY_HEAD["npm"]
NPM_COMMANDS = tuple(_NPM["commands"])
NPM_ALIASES = dict(_NPM["aliases"])


# --------------------------------------------------------------------------
# npm resolves verbs through abbrev(): camelCase, then aliases, then ANY
# unambiguous prefix. 87 spellings reach an acquiring verb; a hand-written list
# can never be complete, which is the argument for deriving it.
# --------------------------------------------------------------------------

def _abbrev(words):
    """npm's abbrev(): map every unambiguous prefix to its word.

    An exact word always wins over being a prefix of a longer one.
    """
    words = sorted(set(words))
    table = {}
    for word in words:
        for size in range(1, len(word)):
            prefix = word[:size]
            table[prefix] = None if prefix in table else word
    for word in words:
        table[word] = word
    return {k: v for k, v in table.items() if v is not None}


_ABBREV = _abbrev(list(NPM_COMMANDS) + list(NPM_ALIASES))


def npm_deref(verb):
    """Resolve an npm verb spelling to its canonical command, or None."""
    if not verb:
        return None
    if any(char.isupper() for char in verb):
        verb = re.sub(r"([A-Z])", lambda m: "-" + m.group(1).lower(), verb)
    if verb in NPM_COMMANDS:
        return verb
    if verb in NPM_ALIASES:
        return NPM_ALIASES[verb]
    canonical = _ABBREV.get(verb)
    seen = 0
    while canonical in NPM_ALIASES and seen < 10:
        canonical = NPM_ALIASES[canonical]
        seen += 1
    return canonical


def lookup(head):
    """The installer entry for a command basename, or None."""
    return _BY_HEAD.get(head)


def normalize(installer, verb):
    """Canonicalise a verb for this installer."""
    if installer.get("normalize") == "npm_deref":
        return npm_deref(verb)
    return verb


def classify(installer, verb):
    """'acquire' | 'inert' | 'unknown' for a canonical verb."""
    if verb in installer.get("acquire", {}):
        return "acquire"
    if verb in set(installer.get("inert", ())):
        return "inert"
    return "unknown"


def samples():
    """Every canonical acquisition sample command, for the conformance tests."""
    out = []
    for installer in INSTALLERS:
        for verb, spec in installer.get("acquire", {}).items():
            out.append((installer["heads"][0], verb, spec["sample"], spec["handler"]))
        for name, sub in (installer.get("subtables") or {}).items():
            for verb, spec in sub.get("acquire", {}).items():
                out.append((installer["heads"][0], "%s %s" % (name, verb),
                            spec["sample"], spec["handler"]))
    return out


# --------------------------------------------------------------------------
# The generated fallback hint.
#
# Used ONLY where the lexer could not analyse the text (unbalanced quotes, an
# unlexable wrapper payload). It is derived from the table, never hand-edited,
# so it cannot drift from the dispatcher the way `_ACQ_HINT` did.
# --------------------------------------------------------------------------

def _npm_spellings():
    """Every spelling that derefs to an acquiring npm verb."""
    acquiring = set(_NPM["acquire"])
    found = {s for s in _ABBREV if npm_deref(s) in acquiring}
    found |= {a for a in NPM_ALIASES if npm_deref(a) in acquiring}
    found |= acquiring
    return sorted(found, key=len, reverse=True)


def _build_hint():
    alternatives = []
    for installer in INSTALLERS:
        heads = "|".join(re.escape(h) for h in installer["heads"])
        # Versioned interpreters: pip3.12, python3.13.
        if "pip" in installer["heads"]:
            heads = r"pip[0-9.]*"
        if installer.get("head_only"):
            alternatives.append(r"%s\s+" % heads)
            continue
        verbs = (_npm_spellings() if installer.get("normalize") == "npm_deref"
                 else sorted(installer.get("acquire", {}), key=len, reverse=True))
        if verbs:
            alternatives.append(r"(?:%s)\s+(?:%s)\b" % (heads, "|".join(re.escape(v) for v in verbs)))
        for name, sub in (installer.get("subtables") or {}).items():
            subverbs = sorted(sub.get("acquire", {}), key=len, reverse=True)
            if subverbs:
                alternatives.append(r"(?:%s)\s+%s\s+(?:%s)\b" % (
                    heads, re.escape(name), "|".join(re.escape(v) for v in subverbs)))
    alternatives.append(r"python[0-9.]*\s+-m\s+pip\s+install\b")
    for manager in FOREIGN:
        alternatives.append(r"%s\s+" % re.escape(manager))
    return re.compile(
        r"(?:^|[\s;&|(`'\"])(?:\S*[\\/])?(?:" + "|".join(alternatives) + r")"
    )


ACQUISITION_HINT = _build_hint()


def acquisition_hint():
    return ACQUISITION_HINT


def render_table():
    """Render the table as a markdown block.

    Documentation embeds this rendering byte for byte, so it never keeps its
    own copy of the data.
    """
    rows = ["| head | acquiring verbs | inert verbs |", "|---|---|---|"]
    for installer in INSTALLERS:
        heads = " / ".join("`%s`" % h for h in installer["heads"])
        acquiring = [v or "(bare)" for v in sorted(installer.get("acquire", {}))]
        for name, sub in sorted((installer.get("subtables") or {}).items()):
            acquiring += ["%s %s" % (name, v) for v in sorted(sub.get("acquire", {}))]
        inert = len(installer.get("inert", []))
        for name, sub in (installer.get("subtables") or {}).items():
            inert += len(sub.get("inert", []))
        rows.append("| %s | %s | %d |" % (
            heads, ", ".join("`%s`" % a for a in acquiring), inert))
    rows.append("| %s | *(all denied)* | %d safe read-only verbs |" % (
        " / ".join("`%s`" % m for m in sorted(FOREIGN)), len(FOREIGN_SAFE)))
    return "\n".join(rows)
