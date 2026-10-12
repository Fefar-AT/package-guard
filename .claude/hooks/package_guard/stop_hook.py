#!/usr/bin/env python3
# /// script
# requires-python = "==3.11.*"
# ///
"""Package Guard — Claude Code Stop hook.

Refuses to let the agent end its turn while reviews opened in THIS session
are still unresolved: verdict `review_required`, identity neither vetted
(approved by the user) nor declined (rejected by the user).

Blocking is done with exit code 2 + a reason on stderr, which Claude Code
feeds back to the agent as the next thing to act on.

A running `package-vetter` subagent counts as progress. The harness runs
subagents in the background and delivers their report as a later user turn,
so ending the turn is how the agent receives it; blocking here would make a
well-behaved agent burn turns insisting it was still waiting. The launch and
the report are both visible in the session transcript, which is how "vetter
in flight" is told apart from "stalled".

Loop guard: we block at most MAX_NAGS consecutive times against the SAME
pending set. Any progress (a review approved or declined) resets the count,
so an agent that is working keeps being pushed, while an agent that is stuck
is released after MAX_NAGS refusals and can never be trapped.

Standard library only.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

# The floor, checked before the siblings are imported (see hook.py). Exit 0: a
# Stop hook that fails closed traps the session with no way out.
if sys.version_info < (3, 11):
    print(
        "Package Guard stop hook: needs Python 3.11 or newer; this interpreter is "
        f"{sys.version_info.major}.{sys.version_info.minor}. Allowing stop.",
        file=sys.stderr,
    )
    sys.exit(0)

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Module-level, so main()'s handler cannot catch it. Unlike hook.py this fails
# OPEN: a Stop hook that fails closed traps the session with no way out, which is
# the same reasoning as main() below. The PreToolUse hook is the gate; this one
# only nags.
try:
    import disk_guard  # noqa: E402
    import store  # noqa: E402
    import transcript  # noqa: E402
except Exception as _exc:  # pragma: no cover - exercised by test_import_guard
    print(
        f"Package Guard stop hook: modules failed to load ({_exc.__class__.__name__}: {_exc}); "
        "allowing stop. Package Guard requires Python 3.11+.",
        file=sys.stderr,
    )
    sys.exit(0)

MAX_NAGS = 3

# A vetter launch older than this with no report is treated as dead rather than
# in flight, so a subagent that dies silently cannot relax the gate for the rest
# of the session. A vetter normally reports within a few minutes.
VETTER_STALE_SECONDS = 15 * 60

# The transcript vocabulary lives in transcript.py, shared with the approve
# gate. These module-level aliases keep the names this module has always used.
_VETTER_AGENT = transcript.VETTER_AGENT
_ASYNC_LAUNCH = transcript.ASYNC_LAUNCH
_NOTIFICATION = transcript.NOTIFICATION
_TOOL_USE_ID = transcript.TOOL_USE_ID
_walk = transcript.walk
_strings = transcript.strings
_parse_timestamp = transcript.parse_timestamp


def pending_reviews(root, session_id: str, verdicts=None, answered=()) -> list:
    """Unresolved review_required reports created in this session.

    `verdicts` is `transcript.vetter_verdicts(...)`: it carries the alternative
    the vetter named per review, so a review answered by installing that
    alternative counts as settled. `answered` is `transcript.answered(...)`:
    reviews the human has already been asked about and answered.
    """
    verdicts = verdicts or {}
    pending = []
    seen_identities = set()
    for report in store.iter_reports(root):
        if report.get("session_id") != session_id or report["verdict"] != "review_required":
            continue
        identity = report["resolved_identity"]
        key = (identity["ecosystem"], identity["name"], identity["version"], identity["registry"])
        if key in seen_identities:
            continue  # a duplicate review of the same identity counts once
        if store.is_vetted(root, identity) or store.is_declined(root, identity):
            continue
        if store.is_review_declined(root, report["review_id"]):
            continue
        # The user approved another version of this package, or
        # the alternative the vetter named, after this review opened. That is
        # the decision; this review is not pending and needs no decline --
        # which would be permanent, and about a package nobody judged unsafe.
        verdict = verdicts.get(report["review_id"]) or {}
        if store.superseded_by(root, report, verdict.get("alternative")) is not None:
            continue
        # The vetter said DO_NOT_RECOMMEND and nothing was installed. That is
        # the decision: the package was passed over. A decline would say
        # "never install this here", which nobody said, and nagging for one
        # would block a finished session. If the package IS on disk,
        # disk_guard's findings catch it; if the user later approves it, it is
        # vetted.
        if verdict.get("verdict") == "DO_NOT_RECOMMEND":
            continue
        # The human was asked and answered. Whatever they said -- not now,
        # skip it, no at the prompt -- is theirs; pushing the agent again only
        # makes it re-ask, or offer a permanent decline nobody wanted.
        if report["review_id"] in answered:
            continue
        seen_identities.add(key)
        pending.append(report)
    return pending


# ---------------------------------------------------------------------------
# Is a package-vetter subagent still working?
# ---------------------------------------------------------------------------

def _peer_sender(record) -> str | None:
    """The agent id a subagent's hand-back came from, or None.

    Current builds deliver a background subagent's report as a message from
    that agent: a `user` record whose harness-written `origin` is
    `{"kind": "peer", "from": <agent id>}`, or, while the main agent is still
    in its turn, a `queued_command` attachment carrying the same origin.
    """
    origin = record.get("origin")
    if record.get("type") == "attachment":
        attachment = record.get("attachment")
        origin = attachment.get("origin") if (
            isinstance(attachment, dict) and attachment.get("type") == "queued_command") else None
    elif record.get("type") != "user":
        return None
    if isinstance(origin, dict) and origin.get("kind") == "peer" and isinstance(origin.get("from"), str):
        return origin["from"]
    return None


def vetter_status(transcript_path, now=None) -> dict | None:
    """What this session's background package-vetter launches are doing.

    `in_flight`: one was launched under `VETTER_STALE_SECONDS` ago and has not
    reported. `stale`: one was launched longer ago than that and never
    reported. `reported`: at least one has reported. None when the transcript
    cannot be read.

    Reads the session transcript (JSONL). The records that matter: the Agent
    tool_use that launched the vetter, its tool_result (which says whether the
    launch was backgrounded, and names the background agent's id), and the
    report: a <task-notification> naming the launch's tool-use id, or a
    hand-back from the launch's agent id (`_peer_sender`). The vetter
    has no tool to message its parent mid-run, so any message from its agent
    id is its report.
    """
    lines = transcript.read_lines(transcript_path)
    if lines is None:
        return None
    launched = {}  # tool_use id -> launch time
    backgrounded = set()
    agents = {}  # agent id -> tool_use id
    reported = set()
    senders = set()
    for raw in lines:
        # Cheap pre-filter: only records that can matter are parsed.
        if (_VETTER_AGENT not in raw and _ASYNC_LAUNCH not in raw and _NOTIFICATION not in raw
                and '"peer"' not in raw):
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        for node in _walk(record):
            kind = node.get("type")
            if kind == "tool_use" and node.get("name") == "Agent":
                if (node.get("input") or {}).get("subagent_type") == _VETTER_AGENT:
                    launched[node.get("id")] = _parse_timestamp(record.get("timestamp"))
            elif kind == "tool_result" and node.get("tool_use_id") in launched:
                texts = list(_strings(node.get("content")))
                if any(_ASYNC_LAUNCH in text for text in texts):
                    backgrounded.add(node["tool_use_id"])
                agent = transcript._launch_agent_id(record, "\n".join(texts))
                if agent:
                    agents[agent] = node["tool_use_id"]
        for text in _strings(record):
            if _NOTIFICATION in text:
                reported.update(_TOOL_USE_ID.findall(text))
        sender = _peer_sender(record)
        if sender:
            senders.add(sender)
    reported |= {agents[agent] for agent in senders if agent in agents}
    now = now or datetime.now(timezone.utc)
    status = {"in_flight": False, "stale": False,
              "reported": any(use in reported for use in launched)}
    for tool_use_id, started in launched.items():
        if tool_use_id not in backgrounded or tool_use_id in reported or started is None:
            continue
        if (now - started).total_seconds() < VETTER_STALE_SECONDS:
            status["in_flight"] = True
        else:
            status["stale"] = True
    return status


def vetter_in_flight(transcript_path, now=None) -> bool:
    """True when a package-vetter was launched this session and has not reported.

    A missing or unreadable transcript yields False -- the stricter answer,
    never looser. See `vetter_status` for what counts as a report.
    """
    status = vetter_status(transcript_path, now)
    return bool(status and status["in_flight"])


def asked_the_user(event: dict, pending, findings) -> bool:
    """True when the turn ends on a question naming every open package.

    That is route (c) of the block message, taken. Blocking it would push an
    agent that had already asked to ask again until the cap released it. A
    package is asked about when one sentence names its `name@version` as a
    whole token and contains `?` (`transcript.asks_about`). Anything less -- a
    statement that it will wait, even one followed by an unrelated question,
    one package of two, a longer version that merely starts with the pending
    one -- is still pushed.
    """
    text = event.get("last_assistant_message")
    if not isinstance(text, str) or not text:
        text = transcript.final_text(event.get("transcript_path"))
    if not text or "?" not in text:
        return False
    names = [r["resolved_identity"] for r in pending] + list(findings)
    return all(transcript.asks_about(text, f"{n['name']}@{n['version']}") for n in names)


# ---------------------------------------------------------------------------
# Decision
# ---------------------------------------------------------------------------

def _relaunch_line(vetters) -> str:
    """What to do about a vetter that has not reported, given `vetter_status`.

    "Launch it again" only for a launch that went stale with no report. A
    vetter that reported is done: its hand-back is in the conversation, and a
    second run would only repeat it. With no transcript to read (`None`) the
    conditional form is all that can be said.
    """
    stale = (f"If you launched one more than {VETTER_STALE_SECONDS // 60} minutes ago and "
             "have no report, it did not finish: launch it again.")
    if vetters is None:
        return " " + stale
    if vetters.get("stale"):
        return (f" A package-vetter you launched more than {VETTER_STALE_SECONDS // 60} minutes "
                "ago has not reported; it did not finish: launch it again.")
    if vetters.get("reported"):
        return (" The package-vetter you launched has reported: act on its verdicts; a second "
                "run for the ids it covered would only repeat them.")
    return ""


def render_block(pending, nag: int, root, vetters=None) -> str:
    """The block message. `vetters` is `vetter_status(...)`, or None when the
    transcript could not be read."""
    ids = " ".join(r["review_id"] for r in pending)
    lines = [
        f"PACKAGE_GUARD_PENDING_REVIEWS ({nag}/{MAX_NAGS}): you cannot stop yet — "
        f"{len(pending)} package review(s) opened this session are unresolved."
    ]
    if nag > 1:
        lines.append("No progress since the last push: the same reviews are still open.")
    for report in pending:
        identity = report["resolved_identity"]
        lines.append(
            f"- {report['review_id']}  {identity['ecosystem']}:{identity['name']}@{identity['version']}"
        )
    lines += [
        "Close the loop before ending the turn. Exactly one of:",
        f"  (a) not vetted yet: Agent tool -> package-vetter with review ids [{ids}], then for "
        f"every RECOMMEND run: {store.cli_command(root, 'approve', '<ids>')}. An id whose "
        "denial said `reputation: established` needs no vetter: run approve for it directly.",
        "  (b) the user said never to install it: run "
        f"{store.cli_command(root, 'decline', '<ids>')} -- a permission prompt, permanent -- "
        "and tell the user why.",
        "  (c) you are blocked and need the user's decision: ask them a direct question "
        "naming the package(s) — do not end the turn silently.",
        "A review answered by approving another version or the vetter's alternative is "
        "already settled; it needs nothing.",
        "Run the guard CLI exactly as written: a simple standalone command, no `cd`, no `&&`.",
        "A running package-vetter counts as progress: its report arrives as a notification, "
        "and you may end the turn to wait for it — run no other package command meanwhile."
        + _relaunch_line(vetters),
    ]
    return "\n".join(lines)


def evaluate(event: dict, root) -> str | None:
    """Return a block reason, or None to allow stopping."""
    session_id = event.get("session_id")
    if not isinstance(session_id, str) or not session_id:
        return None
    store_error = None
    path = event.get("transcript_path")
    try:
        mine = [r for r in store.iter_reports(root) if r.get("session_id") == session_id]
        open_reviews = [r for r in mine if r.get("verdict") == "review_required"]
        labels = {r["review_id"]: "{name}@{version}".format(**r["resolved_identity"])
                  for r in open_reviews}
        created = {r["review_id"]: _parse_timestamp(r.get("created_at")) for r in open_reviews}
        pending = pending_reviews(
            root, session_id, transcript.vetter_verdicts(path, mine),
            transcript.answered(path, labels, created))
    except store.StoreError as exc:
        pending, store_error = [], exc
    # A turn may not end with an unreviewed package on disk either. Findings
    # are PROJECT-scoped, not session-scoped, so the nag cap below is what
    # guarantees a session that cannot resolve them is still released -- the
    # same never-trap rule that applies to reviews.
    try:
        findings = disk_guard.open_findings(root)
    except store.StoreError as exc:
        findings = []
        store_error = store_error or exc
    if not pending and not findings and store_error is None:
        return None
    vetters = vetter_status(path)
    if (pending or findings) and vetters and vetters["in_flight"]:
        # The report arrives as a user turn; letting the agent stop is how it
        # gets there. Not counted as a nag: the pending set is unchanged and
        # will be pushed again once the report is in and reviews are still open.
        return None
    if store_error is None and asked_the_user(event, pending, findings):
        # Route (c) taken. Not counted as a nag, for the same reason
        # as the in-flight case: the next stop without a question is pushed.
        return None
    fingerprint = "store-error" if store_error else " ".join(
        sorted([r["review_id"] for r in pending] + [f["finding_id"] for f in findings])
    )
    if store.load_stop_nags(root, session_id, fingerprint) >= MAX_NAGS:
        return None  # loop guard: no progress after MAX_NAGS pushes — release
    nag = store.record_stop_nag(root, session_id, fingerprint)
    if store_error is not None:
        return (
            f"PACKAGE_GUARD_ERROR ({nag}/{MAX_NAGS}): Package Guard state is unavailable "
            f"({store_error}). Tell the user before stopping; do not repair "
            ".claude/package-guard/ yourself."
        )
    blocks = []
    if pending:
        blocks.append(render_block(pending, nag, root, vetters))
    if findings:
        blocks.append(disk_guard.render_block(
            findings, root,
            header=(
                f"({nag}/{MAX_NAGS}) you cannot stop yet — {len(findings)} direct "
                "dependenc" + ("y is" if len(findings) == 1 else "ies are") +
                " installed that no human approved. Review or remove before ending the turn; "
                "if you cannot, ask the user a direct question naming the package(s) — do not "
                "end the turn silently."
            ),
            declined_check=lambda identity: store.is_declined(root, identity),
        ))
    return "\n\n".join(blocks)


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except ValueError:
        # A Stop hook that fails closed would trap the session; fail open loudly.
        print("Package Guard stop hook: malformed JSON input; allowing stop.", file=sys.stderr)
        return 0
    if not isinstance(event, dict):
        return 0
    try:
        root = store.project_root(__file__)
        reason = evaluate(event, root)
    except Exception as exc:
        print(f"Package Guard stop hook: internal failure ({exc.__class__.__name__}: {exc}); allowing stop.",
              file=sys.stderr)
        return 0
    if reason is None:
        return 0
    print(reason, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
