#!/usr/bin/env python3
# /// script
# requires-python = ">=3.11"
# ///
"""Package Guard CLI: show / approve / decline / undecline / revoke / reconcile / audit.

Every subcommand accepts one or more review ids — never a free-form package
identity. The PreToolUse hook intercepts every state-changing verb and asks
the user via Claude Code's permission prompt (one prompt listing every
package) before this ever runs. `decline` records that the user rejected a
specific review so the same exact identity is never reviewed again or
re-proposed; `undecline` reverses that, behind the same prompt.

`approve` is all-or-nothing: every id is validated before anything is
written, so a hard-denied or declined id in the list fails the whole call.

Standard library only.
"""
from __future__ import annotations

import sys
import time
from pathlib import Path

# The floor, checked before the siblings are imported (see hook.py). Exit 2: this
# writes trust state, so a half-loaded CLI must not run. The hook refuses to show
# an approval prompt for a CLI call it cannot recognise, so this failing is safe.
if sys.version_info < (3, 11):
    print(
        "Package Guard: needs Python 3.11 or newer (manifest parsing uses tomllib); "
        f"this interpreter is {sys.version_info.major}.{sys.version_info.minor}. "
        "Nothing was changed.",
        file=sys.stderr,
    )
    sys.exit(2)

sys.path.insert(0, str(Path(__file__).resolve().parent))
# Guarded for the same reason as the three hooks: an unhandled ImportError here
# would exit 1 with a traceback in the middle of an approval, which reads like a
# crash rather than a refusal. Nothing has been written at this point.
try:
    import disk_guard  # noqa: E402
    import manifest as pg_manifest  # noqa: E402
    import store  # noqa: E402
    import vetting  # noqa: E402
except Exception as _exc:  # pragma: no cover - exercised by test_import_guard
    print(
        f"Package Guard: CLI modules failed to load ({_exc.__class__.__name__}: {_exc}); "
        "nothing was changed. Package Guard requires Python 3.11+.",
        file=sys.stderr,
    )
    sys.exit(2)

USAGE = (
    "usage: cli.py show <review-id>... | cli.py approve <review-id>... | "
    "cli.py decline <review-id>... | cli.py undecline <review-id>... | "
    "cli.py revoke <review-id>... | cli.py reconcile | cli.py audit"
)
_COMMANDS = ("show", "approve", "decline", "undecline", "revoke")
# Take no arguments: each acts on state the guard already holds — whatever the
# reconciliation layer has found on disk, and whatever vetted.json approves.
_NO_ARGUMENT_COMMANDS = ("reconcile", "audit")
# Warn this many days before the trust catalog expires. The catalog is never
# refreshed automatically, so the audit is where a coming expiry is announced.
_CATALOG_WARN_DAYS = 30


def _label(identity: dict) -> str:
    return f"{identity['ecosystem']}:{identity['name']}@{identity['version']}"


def _summary(report: dict, root) -> str:
    identity = report["resolved_identity"]
    osv = report["mandatory_checks"].get("osv", {})
    evidence = report.get("evidence", {})
    status = report["verdict"]
    if store.is_vetted(root, identity):
        status += " (vetted)"
    elif store.is_review_declined(root, report["review_id"]):
        status += " (declined by user)"
    else:
        # Version supersession only: the vetter's alternative is named in the
        # session transcript, which this command does not have.
        later = store.superseded_by(root, report)
        if later is not None:
            status += f" (superseded by {_label(later)}, approved {later.get('approved_at')})"
    lines = [
        f"Review {report['review_id']} ({report['created_at']})",
        f"Package: {_label(identity)}",
        f"Registry: {identity['registry']}",
        f"Verdict: {status}",
        f"OSV ids: {', '.join(osv.get('ids') or []) or 'no matching OSV record was returned'}",
        f"Repository: {evidence.get('repository_url') or 'none listed'}",
        f"Install scripts: {', '.join(evidence.get('install_scripts') or []) or 'none'}",
    ]
    for finding in report.get("hard_findings") or []:
        lines.append(f"Hard finding: {finding}")
    for signal in report.get("risk_signals") or []:
        lines.append(f"Risk signal: {signal}")
    reputation = (report.get("optional_checks") or {}).get("reputation")
    if isinstance(reputation, dict):
        lines.append(f"Reputation: {reputation.get('tier')}")
        trust = reputation.get("trust")
        if isinstance(trust, dict):
            lines.append(f"User identity trust: {trust.get('status')} (catalog {trust.get('catalog_version')})")
            lines.append("Identity trust does not grant this project's exact-version installation approval.")
        for reason in reputation.get("unmet") or []:
            lines.append(f"  unmet: {reason}")
    else:
        lines.append("Reputation: not checked")
    if report.get("retry_command"):
        lines.append(f"Retry command: {report['retry_command']}")
    return "\n".join(lines)


def _dedupe(ids):
    seen = []
    for rid in ids:
        if rid not in seen:
            seen.append(rid)
    return seen


def _load_all(root, review_ids):
    """Load every report up front so a bad id fails before any write."""
    reports = []
    for rid in review_ids:
        reports.append(store.load_report(root, rid))
    return reports


def _approve(root, reports) -> int:
    problems = []
    for report in reports:
        rid = report["review_id"]
        if report["verdict"] == "hard_deny":
            problems.append(
                f"{rid} ({_label(report['resolved_identity'])}) is hard-denied and cannot be approved"
            )
        elif store.is_review_declined(root, rid) or store.is_declined(root, report["resolved_identity"]):
            problems.append(f"{rid} ({_label(report['resolved_identity'])}) was declined by the user")
    if problems:
        print("error: nothing approved. " + "; ".join(problems) + ".", file=sys.stderr)
        return 1
    for report in reports:
        identity = report["resolved_identity"]
        evidence = report.get("evidence") or {}
        artifacts = evidence.get("artifacts") if identity["ecosystem"] == "pypi" else (
            [evidence["integrity"]] if isinstance(evidence.get("integrity"), str) else None)
        added = store.add_vetted(root, identity, review_id=report["review_id"], artifacts=artifacts)
        suffix = "" if added else " (was already vetted)"
        print(f"Approved {_label(identity)} from {identity['registry']}{suffix}")
    return 0


def _decline(root, reports) -> int:
    for report in reports:
        identity = report["resolved_identity"]
        if store.is_vetted(root, identity):
            print(
                f"error: {_label(identity)} is already vetted; withdraw the approval with "
                f"`cli.py revoke {report['review_id']}` first if you want to revoke it.",
                file=sys.stderr,
            )
            return 1
    for report in reports:
        identity = report["resolved_identity"]
        added = store.add_declined(root, identity, review_id=report["review_id"])
        suffix = "" if added else " (was already declined)"
        print(f"Declined {_label(identity)} (review {report['review_id']}){suffix}")
    return 0


def _undecline(root, reports) -> int:
    """Reverse a decline; the identity becomes reviewable again.

    Nothing is approved by this: the report stays `review_required` and the
    next install goes through the vetter and the approve prompt as usual.
    """
    for report in reports:
        identity = report["resolved_identity"]
        removed = store.remove_declined(root, identity)
        suffix = "" if removed else " (was not declined)"
        print(f"Undeclined {_label(identity)} (review {report['review_id']}){suffix}")
    return 0


def _revoke(root, reports) -> int:
    """Withdraw an approval; the identity needs a new review to install.

    Nothing is declined. A copy already on disk becomes a reconciliation
    finding on the next hook advance, with removal as the way out.
    """
    for report in reports:
        identity = report["resolved_identity"]
        removed = store.remove_vetted(root, identity)
        suffix = "" if removed else " (was not vetted)"
        print(f"Revoked {_label(identity)} (review {report['review_id']}){suffix}")
    return 0


def _reconcile(root) -> int:
    """Open a review of every unreviewed package already installed.

    This lives in the CLI and not in a hook because it makes network calls.
    Hooks in this layer make none, which is the structural reason
    reconciliation cannot reintroduce the PreToolUse timeout fail-open: an
    ordinary Bash command has no hook deadline to blow.

    It only OPENS reviews. It never writes vetted.json, so the approval gate is
    unchanged, and it never writes declined.json.
    """
    result = disk_guard.reconcile(root, project_root=root, detected_by="cli")
    for finding, reason in result.closed:
        print(f"Closed {finding['ecosystem']}:{finding['name']}@{finding['version']} ({reason})")
    if not result.findings:
        print("Nothing unreviewed on disk.")
        return 0

    ids, blocked = [], []
    for finding in result.findings:
        identity = {k: finding[k] for k in ("ecosystem", "name", "version", "registry")}
        label = f"{identity['ecosystem']}:{identity['name']}@{identity['version']}"
        if store.is_declined(root, identity):
            # The user rejected this exact version and it is installed
            # anyway. Removal is the resolution, not a fresh review.
            blocked.append(f"{label} was declined by the user; remove it, do not review it")
            continue
        review_id = finding.get("review_id")
        if not review_id:
            request = pg_manifest.as_request(
                identity["name"], identity["version"],
                f"(found on disk in {finding['source']})",
                "npm" if identity["ecosystem"] == "npm" else "pypi",
            )
            report = vetting.create_review(request, root, session_id=None)
            review_id = report["review_id"]
            disk_guard.record_review(root, identity, review_id)
            if report["verdict"] == "hard_deny":
                findings_text = "; ".join(report.get("hard_findings") or []) or "hard denial"
                blocked.append(f"{label} is HARD-DENIED ({findings_text}); remove it")
                continue
        print(f"Review {review_id}  {label}  [{finding['source']}]")
        for path in finding.get("paths") or []:
            print(f"  {path}")
        print(f"  remove with: {disk_guard.removal_command(finding)}")
        ids.append(review_id)

    for problem in blocked:
        print(f"BLOCKED: {problem}")
    if ids:
        joined = " ".join(ids)
        print("")
        print("Next: Agent tool -> subagent_type package-vetter, ONCE, with the review ids "
              f"whose reputation is unresolved (run `show` on [{joined}]); an established id "
              "needs no vetter. Then for every RECOMMEND or established id, one simple "
              "standalone command:")
        print(f"  {store.cli_command(root, 'approve', joined)}")
        print("Approving closes the finding. Removing the package closes it too, with no "
              "permanent record.")
    return 0


def _print_catalog_status() -> None:
    """Announce the trust catalog's expiry; advisory, never the exit
    status. The audit's status stays a pure OSV/malware signal."""
    info = vetting.trusted_catalog.describe()
    version = info.get("catalog_version")
    days = info.get("days_left")
    if info["status"] == "unavailable":
        print(f"trust catalog: not readable ({info.get('reason')})")
    elif info["status"] == "expired" or (isinstance(days, int) and days <= 0):
        print(f"trust catalog {version}: EXPIRED — established shortcuts are off; "
              "refresh or retire trusted-packages.json")
    elif isinstance(days, int) and days <= _CATALOG_WARN_DAYS:
        print(f"trust catalog {version}: expires in {days} day(s) — "
              "refresh or retire trusted-packages.json")
    else:
        print(f"trust catalog {version}: {days} day(s) until expiry")


def _audit(root) -> int:
    """Re-check every approved version against OSV, live.

    The hook runs this same audit before an install, from a cache that is a
    day old at most. Here it is always live and always records, which is what
    makes it the answer to the hook's `PACKAGE_GUARD_REVIEW_BUDGET`: an
    approved set too large for the hook's per-ecosystem call cap is checked
    here instead, outside any hook deadline.

    It writes only the audit cache. Nothing is approved, declined or revoked:
    a MAL hit prints the `revoke` command for a human to run, and that command
    shows its own prompt. The exit status carries the finding:
    0 clean, 1 on a malware hit or a provider failure, so a script or CI step
    can act on it without parsing the output.
    """
    _print_catalog_status()
    entries = store.load_vetted(root)["packages"]
    plan = vetting.audit_batches(entries)
    if not plan:
        print("Nothing approved to audit.")
        return 0
    try:
        advisories, calls = vetting.audit_vetted(entries)
    except vetting.ProviderError as exc:
        print(f"error: the OSV audit failed ({exc}); nothing was checked.", file=sys.stderr)
        return 1
    checked = sum(len(chunk) for _ecosystem, chunk in plan)
    digest = store.vetted_digest(root)
    if digest:
        store.record_transitive_check(root, digest, {
            "checked_at": store.utcnow(), "checked_at_epoch": time.time(),
            "packages": checked, "advisories": advisories,
        })
    by_label = {f"{e.get('ecosystem')}:{e.get('name')}@{e.get('version')}": e
                for e in entries if isinstance(e, dict)}
    malware = []
    for ecosystem, chunk in plan:
        for name, version in chunk:
            label = f"{ecosystem}:{name}@{version}"
            ids = advisories.get(label) or []
            print(f"{label}  {', '.join(ids) if ids else 'clean'}")
            if any(i.startswith("MAL-") for i in ids):
                malware.append(label)
    print(f"\n{checked} approved version(s) checked against OSV in {calls} batch call(s).")
    for label in malware:
        entry = by_label.get(label) or {}
        rid = store.vetted_review_id(
            root, {k: entry.get(k) for k in ("ecosystem", "name", "version", "registry")})
        print(f"MALWARE: {label} — withdraw the approval with:")
        print(f"  {store.cli_command(root, 'revoke', rid)}" if rid else
              f"  no review id is recorded for {label}; ask the user to remove the approval")
    return 1 if malware else 0


def main(argv) -> int:
    if argv and argv[0] in _NO_ARGUMENT_COMMANDS:
        run = {"reconcile": _reconcile, "audit": _audit}[argv[0]]
        try:
            return run(store.project_root(__file__))
        except store.StoreError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if len(argv) < 2 or argv[0] not in _COMMANDS:
        print(USAGE, file=sys.stderr)
        return 2
    command, review_ids = argv[0], _dedupe(argv[1:])
    try:
        root = store.project_root(__file__)
        reports = _load_all(root, review_ids)
        if command == "show":
            print("\n\n".join(_summary(r, root) for r in reports))
            return 0
        if command == "approve":
            return _approve(root, reports)
        if command == "undecline":
            return _undecline(root, reports)
        if command == "revoke":
            return _revoke(root, reports)
        return _decline(root, reports)
    except store.StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
