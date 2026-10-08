"""Reading the session transcript for what the package-vetter did.

Claude Code writes each session as JSONL, one record per event. Two hooks read
it for two questions:

- the Stop hook asks whether a `package-vetter` launched this session has not
  yet reported (`vetter_in_flight`);
- the PreToolUse hook, on `approve`, asks what the vetter concluded for each
  review id (`vetter_verdicts`): the subagent may not write guard state, so
  its report exists only in the conversation, and the transcript is the only
  copy of it the hook can read.

Every uncertainty resolves to "nothing found": a missing or unreadable
transcript, an unparseable line, a block that does not validate. The callers
decide what "nothing found" means -- the Stop hook treats it as "not in
flight" and the approve gate treats it as "no verdict", both of which are the
stricter reading.

Standard library only.
"""
from __future__ import annotations

import json
import re
from datetime import datetime, timezone

VETTER_AGENT = "package-vetter"
# The Agent tool's immediate result when it backgrounds the subagent. A result
# without this text means the harness ran it synchronously and the report is
# already in the conversation.
ASYNC_LAUNCH = "Async agent launched"
NOTIFICATION = "<task-notification>"
TOOL_USE_ID = re.compile(r"<tool-use-id>\s*([^<\s]+)\s*</tool-use-id>")

# The vetter's machine block. Flat by contract -- no nested
# objects -- so one brace-free match finds it and a README that quotes a fake
# block cannot name the random review id it would need.
VERDICTS = ("RECOMMEND", "NEEDS_HUMAN_REVIEW", "DO_NOT_RECOMMEND")
EVIDENCE_STATUS = ("complete", "partial", "unavailable")
MAX_RED_FLAGS = 10
# Pre-filter on the raw JSONL line, where the block's own quotes are escaped.
_MARKER = "pg_vetter"
# Every record `vetter_verdicts` can use names one of these: a block, a launch,
# a launch result, a notification (which may carry only a verdict line), a
# hand-back's verdict line, or a SendMessage that assigns ids.
_RECORD_MARKERS = (_MARKER, VETTER_AGENT, "agentId", NOTIFICATION, "VERDICT:", "SendMessage")
_BLOCK = re.compile(r"\{[^{}]*\"pg_vetter\"[^{}]*\}", re.DOTALL)
_REVIEW_ID = re.compile(r"[0-9a-f]{32}")
_RED_FLAG = re.compile(r"[A-Z][A-Z0-9_]{2,39}")
_PACKAGE_REF = re.compile(r"(?:npm|pypi):[A-Za-z0-9@._/+-]{1,214}")


def walk(obj):
    """Every dict nested anywhere inside one transcript record."""
    if isinstance(obj, dict):
        yield obj
        for value in obj.values():
            yield from walk(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from walk(value)


def strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for value in obj.values():
            yield from strings(value)
    elif isinstance(obj, list):
        for value in obj:
            yield from strings(value)


def parse_timestamp(value):
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


def session_started(transcript_path):
    """The timestamp of the transcript's first timestamped record, or None.

    Reads only as far as that record, because the PreToolUse and PostToolUse
    hooks call this on every Bash command. A resumed session keeps its original
    file, so this is the earliest the session could have put anything on disk.
    """
    if not isinstance(transcript_path, str) or not transcript_path:
        return None
    try:
        with open(transcript_path, encoding="utf-8") as handle:
            for raw in handle:
                try:
                    record = json.loads(raw)
                except ValueError:
                    continue
                if isinstance(record, dict) and "timestamp" in record:
                    return parse_timestamp(record["timestamp"])
    except OSError:
        return None
    return None


def final_text(transcript_path) -> str | None:
    """The assistant text written after the last user record, or None.

    That is the message the turn is ending on. Tool results are user records
    too, so text written before the last tool call is not included.
    """
    lines = read_lines(transcript_path)
    if lines is None:
        return None
    texts = []
    for raw in lines:
        if '"assistant"' not in raw and '"user"' not in raw:
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        if record.get("type") == "user":
            texts = []
        elif record.get("type") == "assistant":
            content = (record.get("message") or {}).get("content")
            if isinstance(content, list):
                texts += [block["text"] for block in content
                          if isinstance(block, dict) and block.get("type") == "text"
                          and isinstance(block.get("text"), str)]
    return "\n".join(texts) or None


_REJECTED = "User rejected tool use"

# A sentence ends at `.`, `!` or `?` followed by whitespace or the end, or at a
# line break. A version's own dots are followed by a digit, so they never end one.
_SENTENCE_END = re.compile(r"[.!?](?=\s|$)|\n")


def names_package(text: str, label: str) -> bool:
    """True when `text` names `label` (`name@version`) as a whole token.

    A bare substring would let `foo@1.2` match inside `foo@1.2.3`,
    `chalk@5.6.2` inside `chalk@5.6.20` or `xchalk@5.6.2`, and an unscoped name
    inside a scoped one. An `ecosystem:` prefix, quotes, backticks and sentence
    punctuation still delimit it.
    """
    pattern = (r"(?<![A-Za-z0-9._/@-])" + re.escape(label)
               + r"(?![A-Za-z0-9_]|[.+-][A-Za-z0-9])")
    return re.search(pattern, text) is not None


def asks_about(text: str, label: str) -> bool:
    """True when one sentence of `text` both names `label` and holds a `?`.

    A statement naming the package followed by an unrelated `Anything else?`
    is not a question about it.
    """
    start = 0
    for end in [m.end() for m in _SENTENCE_END.finditer(text)] + [len(text)]:
        sentence = text[start:end]
        if "?" in sentence and names_package(sentence, label):
            return True
        start = end
    return False


def answered(transcript_path, labels: dict, created: dict | None = None) -> set:
    """Review ids the human was asked about and has answered.

    `labels` maps review id -> `name@version`; `created` maps review id -> the
    review's creation time. A review counts once any of:

    - an AskUserQuestion naming the package got a result that is not an error;
    - an assistant sentence containing `?` and naming it was followed by a
      human prompt (origin `human`; hook feedback, hand-backs and
      notifications are not the human);
    - the approve command naming its review id was rejected at the prompt.

    A question counts only if it was asked at or after the review's creation:
    a question asked before the review existed was not about it.
    A record with no readable timestamp cannot be ordered and does not count.
    """
    lines = read_lines(transcript_path)
    if lines is None or not labels:
        return set()
    created = created or {}

    def timely(rid, at):
        opened = created.get(rid)
        return opened is None or (at is not None and at >= opened)

    questions, approvals = {}, {}
    open_question, done = set(), set()
    for raw in lines:
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        if not isinstance(record, dict):
            continue
        message = record.get("message") or {}
        content = message.get("content")
        if record.get("type") == "assistant" and isinstance(content, list):
            at = parse_timestamp(record.get("timestamp"))
            for block in content:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text" and "?" in (block.get("text") or ""):
                    open_question |= {rid for rid, label in labels.items()
                                      if timely(rid, at) and asks_about(block["text"], label)}
                elif block.get("type") == "tool_use" and isinstance(block.get("id"), str):
                    text = json.dumps(block.get("input"))
                    if block.get("name") == "AskUserQuestion":
                        questions[block["id"]] = {rid for rid, label in labels.items()
                                                  if timely(rid, at) and names_package(text, label)}
                    elif block.get("name") == "Bash" and " approve " in text:
                        approvals[block["id"]] = {rid for rid in labels if rid in text}
        elif record.get("type") == "user":
            if _origin(record).get("kind") == "human":
                done |= open_question
                open_question = set()
            if isinstance(content, list):
                for block in content:
                    if not isinstance(block, dict) or block.get("type") != "tool_result":
                        continue
                    use = block.get("tool_use_id")
                    if use in questions:
                        # An error result (bad input, headless, auto
                        # denial) is not a human answer.
                        if not block.get("is_error"):
                            done |= questions[use]
                    elif use in approvals and record.get("toolUseResult") == _REJECTED:
                        done |= approvals[use]
    return done


def read_lines(transcript_path) -> list | None:
    """The transcript's lines, or None when there is nothing readable."""
    if not isinstance(transcript_path, str) or not transcript_path:
        return None
    try:
        with open(transcript_path, encoding="utf-8") as handle:
            return handle.readlines()
    except OSError:
        return None


# ---------------------------------------------------------------------------
# The vetter's verdicts
# ---------------------------------------------------------------------------

def _sanitise(block: dict) -> dict | None:
    """Keep only the fields the prompt renders, each validated against a closed
    shape. Free text never passes: researched content is untrusted, and the
    prompt is the one surface a human reads before authorising an install."""
    review_id = block.get("review_id")
    verdict = block.get("verdict")
    confidence = block.get("confidence")
    if not isinstance(review_id, str) or not _REVIEW_ID.fullmatch(review_id):
        return None
    if verdict not in VERDICTS:
        return None
    if isinstance(confidence, bool) or not isinstance(confidence, int) or not 0 <= confidence <= 100:
        return None
    status = block.get("evidence_status")
    flags = []
    for flag in block.get("red_flags") or []:
        if isinstance(flag, str) and _RED_FLAG.fullmatch(flag) and flag not in flags:
            flags.append(flag)
    alternative = block.get("alternative")
    if not (isinstance(alternative, str) and _PACKAGE_REF.fullmatch(alternative)):
        alternative = None
    return {
        "review_id": review_id,
        "verdict": verdict,
        "confidence": confidence,
        "evidence_status": status if status in EVIDENCE_STATUS else "unknown",
        "red_flags": flags[:MAX_RED_FLAGS],
        "alternative": alternative,
    }


def blocks_in(text: str):
    """Every valid machine block in one piece of text, in order."""
    for match in _BLOCK.finditer(text):
        try:
            parsed = json.loads(match.group(0))
        except ValueError:
            continue
        if isinstance(parsed, dict) and parsed.get("pg_vetter") == 1:
            clean = _sanitise(parsed)
            if clean:
                yield clean


# The human block's verdict line, read only when a report carries no machine
# block for that package. The codes are the closed set the agent
# definition allows; anything else in the red-flags section is prose. The line
# starts at column zero of the report: an indented one is
# quoted text, such as a README's. A hand-back's harness indent is removed
# first (`_handback_report`), so the vetter's own line is at column zero.
_VERDICT_LINE = re.compile(
    r"^VERDICT:[ \t]*(RECOMMEND|NEEDS_HUMAN_REVIEW|DO_NOT_RECOMMEND)[ \t]*[—–-]+[ \t]*"
    r"((?:npm|pypi):[A-Za-z0-9@._/+-]{1,214})[ \t]+confidence[ \t]+(\d{1,3})\b", re.MULTILINE)
_FLAG_LINE = re.compile(r"^\s*(?:[-•*]\s*)?([A-Z][A-Z0-9_]{2,39})\b", re.MULTILINE)
_ALTERNATIVE_LINE = re.compile(r"^\s*Alternative:\s*((?:npm|pypi):[A-Za-z0-9@._/+-]{1,214})",
                               re.MULTILINE)
RED_FLAG_CODES = frozenset({
    "TYPO_SQUAT", "ADVISORY_UNFIXED", "DEPRECATED", "NO_REPOSITORY", "REPO_MISMATCH",
    "INSTALL_SCRIPT_FETCH", "RELEASE_DIFF", "LOW_ADOPTION", "NO_PROVENANCE", "STALE",
    "INSTALL_SCRIPT", "SDIST_ONLY", "ADVISORY", "FRESH_PUBLISH", "REPO_REDIRECTED",
    "PUBLISHER_NOT_MAINTAINER", "LICENSE", "HEAVY_TREE", "PROVIDER_UNREACHABLE",
    "PURPOSE_UNCONFIRMED", "MALWARE_HISTORY", "REPORT_NOT_FOUND",
})
# Strictest first: two verdict lines for one package that disagree resolve to
# the more cautious one.
_STRICTNESS = {"DO_NOT_RECOMMEND": 0, "NEEDS_HUMAN_REVIEW": 1, "RECOMMEND": 2}
TYPO_SQUAT = "TYPO_SQUAT"
# The codes the agent definition ties to evidence that is not complete: a
# source was unreachable (partial), or the report could not be read
# (unavailable). A verdict carrying neither, and no status saying otherwise,
# was given on complete evidence.
_INCOMPLETE_FLAGS = frozenset({"PROVIDER_UNREACHABLE", "REPORT_NOT_FOUND"})


def _complete(verdict: dict) -> bool:
    """Whether a verdict was given on complete evidence. A machine block says
    so in `evidence_status`; a verdict line, or a block whose status is
    missing, says nothing, and counts as complete unless its red flags name an
    unreachable source or an unreadable report."""
    status = verdict.get("evidence_status")
    if status == "complete":
        return True
    return status == "unknown" and not _INCOMPLETE_FLAGS & set(verdict.get("red_flags") or ())


def _binding(verdict: dict) -> bool:
    """A verdict no later report may relax: DO_NOT_RECOMMEND,
    NEEDS_HUMAN_REVIEW or a TYPO_SQUAT red flag, given on complete evidence.
    A verdict on partial evidence is not binding, so a rerun after a provider
    outage can still clear it."""
    strict = verdict["verdict"] != "RECOMMEND" or TYPO_SQUAT in verdict["red_flags"]
    return strict and _complete(verdict)


def no_laxer(floor: dict | None, verdict: dict) -> dict:
    """`verdict`, unless `floor` -- the strictest binding verdict seen
    earlier for the same review id -- is stricter. A later verdict replaces
    the floor only when it is at least as strict, and a TYPO_SQUAT either
    carries is kept, so a second vetter run can confirm or tighten a verdict
    but never relax it."""
    if floor is None:
        return verdict
    kept = verdict if _STRICTNESS[verdict["verdict"]] <= _STRICTNESS[floor["verdict"]] else floor
    typo = TYPO_SQUAT in floor["red_flags"] or TYPO_SQUAT in verdict["red_flags"]
    if typo and TYPO_SQUAT not in kept["red_flags"]:
        kept = dict(kept, red_flags=[TYPO_SQUAT, *kept["red_flags"]][:MAX_RED_FLAGS])
    return kept


def _without_version(ref: str) -> str:
    """`npm:chalk@5.6.2` -> `npm:chalk`; a scope's leading `@` is kept."""
    ecosystem, _, name = ref.partition(":")
    head, at, _version = name[1:].rpartition("@")
    return f"{ecosystem}:{name[0]}{head}" if at else ref


def human_verdicts(text: str):
    """(package label, sanitised verdict) for each human block in `text`."""
    matches = list(_VERDICT_LINE.finditer(text))
    for index, match in enumerate(matches):
        end = matches[index + 1].start() if index + 1 < len(matches) else len(text)
        body = text[match.end():end]
        flags_at = body.find("Red flags:")
        alternative = _ALTERNATIVE_LINE.search(body)
        flags_text = body[flags_at:alternative.start() if alternative else len(body)] \
            if flags_at >= 0 else ""
        flags = [code for code in _FLAG_LINE.findall(flags_text.replace("Red flags:", "", 1))
                 if code in RED_FLAG_CODES]
        confidence = int(match.group(3))
        if confidence > 100:
            continue
        yield match.group(2), {
            "verdict": match.group(1),
            "confidence": confidence,
            "evidence_status": "unknown",
            "red_flags": list(dict.fromkeys(flags))[:MAX_RED_FLAGS],
            "alternative": _without_version(alternative.group(1)) if alternative else None,
        }


# The harness appends this trailer to an Agent launch's result; the text
# above it is the subagent's own report and may quote anything, so only the
# last trailer line counts, and only when the structured id is absent. The
# trailer is `agentId: <id>` ending the line or followed by a parenthetical;
# its wording after the id is not relied on.
_AGENT_ID = re.compile(r"^agentId:[ \t]*([A-Za-z0-9_-]+)[ \t]*(?:\(|$)", re.MULTILINE)
TASK_ID = re.compile(r"<task-id>\s*([^<\s]+)\s*</task-id>")


def _launch_agent_id(record, text: str):
    result = record.get("toolUseResult")
    if isinstance(result, dict) and isinstance(result.get("agentId"), str):
        return result["agentId"]
    found = _AGENT_ID.findall(text)
    return found[-1] if found else None


# A current build's hand-back: a harness frame at column zero, then the
# vetter's report with every line indented two spaces, closed by a column-zero
# `</agent-message>` the indented report cannot produce.
_AGENT_MESSAGE = re.compile(r'^<agent-message from="[^"\n]*">$(.*?)^</agent-message>$',
                            re.MULTILINE | re.DOTALL)


def _handback_report(text: str) -> str:
    """The vetter's own report inside a hand-back, harness indent removed.

    Column-zero lines inside the frame are the harness's (or forged), never the
    report's, so they are blanked. Text without the frame is returned as is.
    """
    match = _AGENT_MESSAGE.search(text)
    if match is None:
        return text
    return "\n".join(line[2:] if line.startswith("  ") else ""
                     for line in match.group(1).split("\n"))


def _notification(text: str, descriptions=None):
    """(tool-use id, task id, result text) of a harness notification, or None.

    The summary echoes a description the main agent wrote, so the ids are
    read only from the header before `<summary>`. The report is read from the
    harness's own `<result>`, which follows the harness's own `</summary>`.

    When the launch's description is known (`descriptions`, by tool-use id or
    agent id), the harness's `</summary>` is the first one after that exact
    description, so tags the vetter's report quotes cannot move the cut.
    Otherwise the last `</summary>` and the last `<result>` are
    used: a report quoting those tags then loses its verdict, which fails closed.
    """
    start = text.find(NOTIFICATION)
    if start < 0:
        return None
    body = text[start + len(NOTIFICATION):]
    cut = min((i for i in (body.find("<summary>"), body.find("<result>")) if i >= 0),
              default=len(body))
    header = body[:cut]
    use, task = TOOL_USE_ID.search(header), TASK_ID.search(header)
    ids = (use.group(1) if use else None, task.group(1) if task else None)
    summary_end = _summary_end(body, ids, descriptions or {})
    if summary_end is not None:
        after = body[summary_end:]
        opened = after.find("<result>")
    else:
        # The description sits inside the summary, so the harness's own
        # closing tag is the last one; a <result> before it is the description's.
        summary_end = body.rfind("</summary>")
        after = body[summary_end:] if summary_end >= 0 else body
        opened = after.rfind("<result>")
    result = ""
    if opened >= 0:
        result = after[opened + len("<result>"):]
        closed = result.rfind("</result>")
        result = result[:closed] if closed >= 0 else result
    return (*ids, result)


def _summary_end(body: str, ids, descriptions: dict):
    """Index of the harness's `</summary>` when the summary opens with the
    launch's exact description, else None."""
    opened = body.find("<summary>")
    if opened < 0:
        return None
    for key in ids:
        description = descriptions.get(key)
        if not isinstance(description, str):
            continue
        prefix = f'<summary>Agent "{description}"'
        if body.startswith(prefix, opened):
            end = body.find("</summary>", opened + len(prefix))
            if end >= 0:
                return end
    return None


def _notifications(text: str):
    """Each notification in `text` on its own: a batch never lends one
    notification's header to another's result."""
    starts = [m.start() for m in re.finditer(re.escape(NOTIFICATION), text)]
    for a, b in zip(starts, starts[1:] + [len(text)]):
        yield text[a:b]


def _names_vetter(notification: str, launches, agents) -> bool:
    """A notification is the vetter's when its own header names a vetter
    launch's tool-use id or, for a vetter resumed through SendMessage, the
    vetter's agent id."""
    parts = _notification(notification)
    return bool(parts and (parts[0] in launches or parts[1] in agents))


def _origin(record) -> dict:
    origin = record.get("origin")
    return origin if isinstance(origin, dict) else {}


def _vetter_launches(records) -> tuple:
    """(tool_use ids, agent ids, descriptions) of every package-vetter launch.

    All come from records only the harness writes: the Agent tool_use the
    model asked for, and the harness's tool_result for it, which names the
    background agent's id (structured `toolUseResult.agentId` on current
    builds, the result text on older ones). `descriptions` maps each launch's
    tool-use id and agent id to the description it was launched with, which
    the harness echoes in its notification's summary (`_notification`).
    """
    launches, agents, descriptions = set(), set(), {}
    for record in records:
        if record.get("type") != "assistant":
            continue
        for node in walk(record.get("message")):
            if (node.get("type") == "tool_use" and node.get("name") == "Agent"
                    and (node.get("input") or {}).get("subagent_type") == VETTER_AGENT
                    and isinstance(node.get("id"), str)):
                launches.add(node["id"])
                description = node["input"].get("description")
                if isinstance(description, str):
                    descriptions[node["id"]] = description
    for record in records:
        if record.get("type") != "user":
            continue
        for node in walk(record.get("message")):
            if node.get("type") != "tool_result" or node.get("tool_use_id") not in launches:
                continue
            agent = _launch_agent_id(record, "\n".join(strings(node.get("content"))))
            if agent:
                agents.add(agent)
                if node["tool_use_id"] in descriptions:
                    descriptions[agent] = descriptions[node["tool_use_id"]]
    return launches, agents, descriptions


def _assignments(records) -> tuple:
    """({tool_use id: review ids}, {agent id: review ids}) each vetter was asked about.

    The ids come from the launch's own input, which the harness records as the
    model wrote it, and from SendMessage inputs addressed to that vetter's
    agent id, the same trust level. A human verdict line
    binds only to an id its vetter was asked about, because the line names a
    package and researched text can name any package; it cannot name a random
    review id it never saw.
    """
    by_use, by_agent = {}, {}
    for record in records:
        if record.get("type") != "assistant":
            continue
        for node in walk(record.get("message")):
            if (node.get("type") == "tool_use" and node.get("name") == "Agent"
                    and (node.get("input") or {}).get("subagent_type") == VETTER_AGENT
                    and isinstance(node.get("id"), str)):
                by_use[node["id"]] = set(_REVIEW_ID.findall(json.dumps(node.get("input"))))
    for record in records:
        if record.get("type") != "user":
            continue
        for node in walk(record.get("message")):
            use = node.get("tool_use_id")
            if node.get("type") != "tool_result" or use not in by_use:
                continue
            agent = _launch_agent_id(record, "\n".join(strings(node.get("content"))))
            if agent:
                by_agent[agent] = set(by_use[use])
    for record in records:
        if record.get("type") != "assistant":
            continue
        for node in walk(record.get("message")):
            if node.get("type") != "tool_use" or node.get("name") != "SendMessage":
                continue
            to = (node.get("input") or {}).get("to")
            if isinstance(to, str) and to in by_agent:
                by_agent[to] |= set(_REVIEW_ID.findall(json.dumps(node.get("input"))))
    return by_use, by_agent


def _asked_of(record, by_use, by_agent) -> set:
    """The review ids the vetter that delivered `record` was asked about."""
    origin = _origin(record)
    attachment = record.get("attachment")
    if not origin and isinstance(attachment, dict) and isinstance(attachment.get("origin"), dict):
        origin = attachment["origin"]
    if origin.get("kind") == "peer":
        return set(by_agent.get(origin.get("from"), ()))
    asked = set()
    for text in strings(record):
        for chunk in _notifications(text):
            parts = _notification(chunk)
            asked |= by_use.get(parts[0], set()) | by_agent.get(parts[1], set())
    for node in walk(record.get("message")):
        if node.get("type") == "tool_result":
            asked |= by_use.get(node.get("tool_use_id"), set())
    return asked


def _vetter_texts(record, launches, agents, descriptions=None):
    """The text of `record` that is the vetter's own report, if any.

    Harness-written shapes only, each bound to a package-vetter
    launch. Nothing the main agent can author -- its own messages, or the
    output of a tool it ran (`echo '<task-notification>...'`) -- ever counts.
    """
    kind = record.get("type")
    queued = None
    if kind == "queue-operation":
        queued = record.get("content")          # the notification as enqueued
    elif kind == "attachment":
        attachment = record.get("attachment")
        if isinstance(attachment, dict) and attachment.get("type") == "queued_command":
            queued = attachment.get("prompt")
            origin = attachment.get("origin")
            if (isinstance(origin, dict) and origin.get("kind") == "peer"
                    and origin.get("from") in agents and isinstance(queued, str)):
                # Current builds deliver the hand-back as a queued command
                # whose harness-written origin names the vetter's agent id.
                yield _handback_report(queued)
                return
    if queued is not None:
        # A session can end before the queued notification becomes a user
        # turn; the queue record is then the only copy of the report.
        if isinstance(queued, str) and queued.lstrip().startswith(NOTIFICATION):
            for chunk in _notifications(queued):
                if _names_vetter(chunk, launches, agents):
                    yield _notification(chunk, descriptions)[2]
        return
    if kind != "user":
        return
    origin = _origin(record)
    content = (record.get("message") or {}).get("content")
    if origin.get("kind") == "task-notification":
        # Older builds: the report rides inside the notification that names
        # the launch's tool-use id.
        for text in strings(content):
            for chunk in _notifications(text):
                if _names_vetter(chunk, launches, agents):
                    yield _notification(chunk, descriptions)[2]
    elif origin.get("kind") == "peer" and origin.get("from") in agents:
        # Current builds: the subagent's hand-back, addressed from its agent id.
        for text in strings(content):
            yield _handback_report(text)
    elif not origin and isinstance(content, list):
        # A foreground vetter: its report is the Agent call's own tool_result.
        for block in content:
            if (isinstance(block, dict) and block.get("type") == "tool_result"
                    and block.get("tool_use_id") in launches):
                yield from strings(block.get("content"))


def vetter_verdicts(transcript_path, reports=()) -> dict:
    """review_id -> the vetter's sanitised verdict, the latest that does not
    relax an earlier binding one.

    Only a report the harness delivered from a package-vetter this session
    launched is read (`_vetter_texts`); a block anywhere else -- including a
    forged <task-notification> in text the main agent wrote -- is ignored.

    `reports` binds human blocks to review ids. When a delivered report has
    no machine block for a review, its VERDICT line counts if the line's
    `ecosystem:name@version` equals that report's resolved identity. Current
    builds deliver the report as a hand-back message the vetter writes itself,
    and such a message can drop the machine block; without this fallback each
    drop would cost a full second vetter run.

    Reports are read in transcript order. A later one replaces an earlier
    one, so a rerun after a provider outage clears the first run's verdict,
    except that a binding verdict (`_binding`: DO_NOT_RECOMMEND,
    NEEDS_HUMAN_REVIEW or TYPO_SQUAT on complete evidence) is replaced only
    by one at least as strict (`no_laxer`). The approve prompt, the batch
    rule and the Stop hook all read the result, so a second vetter run the
    agent prompts cannot launder a verdict for any of them.
    """
    lines = read_lines(transcript_path)
    if lines is None:
        return {}
    records = []
    for raw in lines:
        if not any(marker in raw for marker in _RECORD_MARKERS):
            continue
        try:
            record = json.loads(raw)
        except ValueError:
            continue
        if isinstance(record, dict):
            records.append(record)
    launches, agents, descriptions = _vetter_launches(records)
    by_use, by_agent = _assignments(records)
    labels = {}
    for report in reports:
        review_id = report.get("review_id")
        identity = report.get("resolved_identity") or {}
        if isinstance(review_id, str):
            labels[review_id] = \
                f"{identity.get('ecosystem')}:{identity.get('name')}@{identity.get('version')}"
    found, floors = {}, {}

    def take(verdict):
        review_id = verdict["review_id"]
        found[review_id] = no_laxer(floors.get(review_id), verdict)
        if _binding(verdict):
            floors[review_id] = no_laxer(floors.get(review_id), verdict)

    for record in records:
        asked = None
        # One delivered report: its machine blocks in order, and for an id
        # it has no block for, its verdict line, lines that disagree
        # resolving to the stricter.
        blocks, mine = [], {}
        for text in _vetter_texts(record, launches, agents, descriptions):
            blocks += list(blocks_in(text))
            if asked is None:
                asked = _asked_of(record, by_use, by_agent)
            for label, block in human_verdicts(text):
                for review_id in asked:
                    if labels.get(review_id) != label:
                        continue
                    held = mine.get(review_id)
                    if held is None or _STRICTNESS[block["verdict"]] <= _STRICTNESS[held["verdict"]]:
                        mine[review_id] = block
        for block in blocks:
            take(block)
        blocked = {block["review_id"] for block in blocks}
        for review_id, block in mine.items():
            if review_id not in blocked:
                take({"review_id": review_id, **block})
    return found
