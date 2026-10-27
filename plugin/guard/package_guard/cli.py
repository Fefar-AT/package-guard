#!/usr/bin/env python3
# /// script
# requires-python = "==3.11.*"
# ///
"""Package Guard CLI: show / approve / decline / undecline / revoke / reconcile / audit / mode.

`mode` shows or changes the guard's mode (enforce, warn, off; see mode.py).
Turning it down needs a person at a terminal; the hook refuses it from Claude.

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

import json
import os
import re
import sys
import time
from concurrent import futures
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
    import baseline  # noqa: E402
    import bench_config  # noqa: E402
    import bench_gate  # noqa: E402
    import disk_guard  # noqa: E402
    import manifest as pg_manifest  # noqa: E402
    import mode as pg_mode  # noqa: E402
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
    "cli.py revoke <review-id>... | cli.py reconcile | cli.py audit | "
    "cli.py baseline plan|show|approve|revoke|list|export|import ... | "
    "cli.py git-owners list|add|remove ... | "
    "cli.py bench-config apply|check [--bench <dir>] [--toolchain name==version]... [--no-symlinks] | "
    "cli.py mode [enforce [--project] | warn|off --reason <why> [--project] "
    "[--for 90m|8h|7d | --permanent]] "
    "(optionally `<subcommand> --root <project>` to name the project)"
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


# `show` re-fetches the evidence it prints, under the same kind of budget as the
# approve prompt's refresh. Past it, or on a provider failure, the stored
# review-time evidence is printed and labelled as such.
_SHOW_REFRESH_SECONDS = 60.0
_SHOW_WORKERS = 8


def _refresh(reports) -> dict:
    """review_id -> a fresh vetting.gather() result, or None when it failed."""
    if not reports:
        return {}

    def fetch(report):
        identity = report["resolved_identity"]
        request = pg_manifest.as_request(
            identity["name"], identity["version"], "(show refresh)", identity["ecosystem"])
        if identity["ecosystem"] != "pypi":
            return vetting.gather(request)
        # The interpreter the review judged the wheels against, and where it
        # came from, as the approve prompt's refresh does.
        source = vetting.reviewed_python_source(report)
        if source:
            return vetting.gather(request, python=vetting.reviewed_python(report), python_source=source)
        return vetting.gather(request, python=vetting.reviewed_python(report))

    pool = futures.ThreadPoolExecutor(max_workers=min(_SHOW_WORKERS, len(reports)))
    submitted = {report["review_id"]: pool.submit(fetch, report) for report in reports}
    done, _not_done = futures.wait(list(submitted.values()), timeout=_SHOW_REFRESH_SECONDS)
    pool.shutdown(wait=False, cancel_futures=True)
    return {rid: (future.result() if future in done and future.exception() is None else None)
            for rid, future in submitted.items()}


def _view(report: dict, found) -> dict | None:
    """The stored report with its evidence replaced by a fresh gather, or None
    when the refresh did not produce evidence to print."""
    if not isinstance(found, dict) or any(
            str(f).startswith("mandatory provider failure") for f in found.get("hard_findings") or []):
        return None
    view = dict(report)
    view["mandatory_checks"] = found.get("mandatory") or report.get("mandatory_checks") or {}
    view["evidence"] = found.get("evidence") or {}
    view["optional_checks"] = dict(report.get("optional_checks") or {},
                                   provenance=found.get("provenance"),
                                   reputation=found.get("reputation"))
    if "release_continuity" in found:
        view["optional_checks"]["release_continuity"] = found["release_continuity"]
    view["risk_signals"] = found.get("risk_signals") or []
    view["hard_findings"] = found.get("hard_findings") or []
    return view


def _age(days) -> str:
    if not isinstance(days, int) or isinstance(days, bool):
        return "unknown"
    return f"{days // 365}y ({days} days)" if days >= 365 else f"{days} day(s)"


def _count(value) -> str:
    return f"{value:,}" if isinstance(value, int) and not isinstance(value, bool) else "unknown"


def _yes_no(value, yes: str, no: str) -> str:
    return yes if value is True else no if value is False else "unknown"


def _evidence_lines(report: dict) -> list:
    """Every fact the approve prompt leaves out, one labelled line each."""
    identity = report["resolved_identity"]
    evidence = report.get("evidence") or {}
    optional = report.get("optional_checks") or {}
    osv = (report.get("mandatory_checks") or {}).get("osv") or {}
    lines = [
        "Vulnerability/malware database (OSV) ids: "
        f"{', '.join(osv.get('ids') or []) or 'no matching record was returned'}",
        f"Repository: {evidence.get('repository_url') or 'none listed'}",
    ]
    if identity.get("ecosystem") == "pypi":
        lines.append("Install-time code: " + (vetting.assumed_wheel(evidence) or {
            "wheel": "wheel (none)", "sdist-only": "sdist only (setup.py may run)",
            "sdist-build": "no wheel for this platform (setup.py may run)",
        }.get(evidence.get("distribution"), "not determined")))
    else:
        lines.append(f"Install scripts: {', '.join(evidence.get('install_scripts') or []) or 'none'}")
    provenance = optional.get("provenance")
    if isinstance(provenance, dict):
        attested = "attested" + (f" ({provenance['url']})" if provenance.get("url") else "") \
            if provenance.get("attested") else "not attested"
    else:
        attested = "not checked"
    maintainers = [str(m) for m in evidence.get("maintainers") or []]
    lines += [
        f"Provenance: {attested}",
        f"Publisher: {evidence.get('publisher') or 'not recorded'}"
        + (f" (npm trusted publishing: {evidence['trusted_publisher']})"
           if evidence.get("trusted_publisher") else ""),
        f"Maintainers: {', '.join(maintainers) or 'none listed'}",
        f"Age: package {_age(evidence.get('package_age_days'))}, "
        f"version {_age(evidence.get('version_age_days'))}",
        f"Releases: {_count(evidence.get('release_count'))}; "
        f"dependencies: {_count(evidence.get('dependency_count'))}",
        f"License: {evidence.get('license') or 'none declared'} "
        f"({evidence.get('license_class') or 'class not recorded'})",
    ]
    reputation = optional.get("reputation")
    if isinstance(reputation, dict):
        trust = reputation.get("trust")
        # A trust-catalog identity skips the popularity research: unknown
        # there means not asked, not unreadable.
        skipped = ("not checked (trust catalog identity)"
                   if isinstance(trust, dict) and trust.get("status") == "trusted" else None)
        manifest = reputation.get("manifest") if isinstance(reputation.get("manifest"), dict) else {}
        near = [n for n in reputation.get("near_names") or [] if isinstance(n, dict)]
        # PyPI's near names carry the top list's monthly counts.
        period = "month" if identity.get("ecosystem") == "pypi" else "week"
        near_text = ", ".join(f"{n.get('name')} ({_count(n.get('weekly_downloads'))}/{period})"
                              for n in near)
        if reputation.get("lookalike_of"):
            near_text += f"; possible lookalike of {reputation['lookalike_of']}"
        downloads = reputation.get("weekly_downloads")
        lines += [
            f"Weekly downloads: {skipped if downloads is None and skipped else _count(downloads)}",
            "Repository manifest: " + {
                True: "names this package", False: "names a different package",
            }.get(manifest.get("names_package"), skipped or "could not be read")
            + (f" ({manifest['url']})" if manifest.get("url") else ""),
            f"Near names: {near_text or skipped or 'none found'}",
        ]
        if isinstance(trust, dict):
            line = f"Trust: {trust.get('status')}"
            if trust.get("status") == "trusted":
                line += (f" identity (catalog {trust.get('catalog_version')}, canonical repository "
                         f"{trust.get('repository')}); this does not grant this project's approval")
            elif trust.get("reason"):
                line += f" ({trust.get('reason')})"
            lines.append(line)
        lines.append(f"Reputation: {reputation.get('tier')}")
        for reason in reputation.get("unmet") or []:
            lines.append(f"  unmet: {reason}")
    else:
        lines.append("Reputation: not checked")
    continuity = optional.get("release_continuity")
    if isinstance(continuity, dict):
        lines.append(
            f"Release continuity: baseline {continuity.get('baseline') or 'none'}; "
            f"this version {_yes_no(continuity.get('attested'), 'attested', 'not attested')}; "
            f"baseline {_yes_no(continuity.get('baseline_attested'), 'attested', 'not attested')}; "
            f"publisher {_yes_no(continuity.get('same_publisher'), 'same as the baseline', 'changed')}; "
            f"new install scripts: {', '.join(map(str, continuity.get('new_install_scripts') or [])) or 'none'}; "
            f"new dependencies: {', '.join(map(str, continuity.get('new_dependencies') or [])) or 'none'}")
    for finding in report.get("hard_findings") or []:
        lines.append(f"Hard finding: {finding}")
    for signal in report.get("risk_signals") or []:
        lines.append(f"Risk signal: {signal}")
    return lines


def _summary(report: dict, root, found=None) -> str:
    """Everything the review holds, with its evidence refreshed when `found`
    carries a fresh gather, and stamped with both times either way."""
    identity = report["resolved_identity"]
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
    view = _view(report, found)
    stamp = (f"Evidence: refreshed {store.utcnow()}; reviewed {report.get('created_at')}"
             if view is not None else
             f"Evidence: as of the review, {report.get('created_at')} (the refresh did not finish)")
    lines = [
        f"Review {report['review_id']} ({report.get('created_at')})",
        f"Package: {_label(identity)}",
        f"Registry: {identity['registry']}",
        f"Verdict: {status}",
        stamp,
    ] + _evidence_lines(view if view is not None else report)
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
        if identity["ecosystem"] == "pypi":
            artifacts = evidence.get("artifacts")
        else:
            # npm: the registry's SRI integrity and, since Yarn Classic locks name some tarballs
            # by sha1 only, `dist.shasum` as `sha1-<base64>` (vetting._npm_sha1_artifacts).
            artifacts = ([evidence["integrity"]] if isinstance(evidence.get("integrity"), str) else []) \
                + [a for a in (evidence.get("artifacts") or []) if isinstance(a, str)]
            artifacts = artifacts or None
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
    """`reconcile`: the disk, then the problems the post-hook recorded for a bench."""
    return max(_reconcile_disk(root), _bench_recheck(root))


def _bench_recheck(root) -> int:
    """Ask each problem the post-hook recorded for a bench whether it is still true; the ones that
    are not are cleared. 1 while any remains."""
    problems = bench_gate.read_problems(root)
    if not problems:
        return 0
    still = [p for p in problems if bench_gate.still_holds(root, p.get("check"))]
    if not still:
        bench_gate.clear_problems(root)
        print(f"Cleared {len(problems)} recorded bench problem(s): none of them holds any more.")
        return 0
    bench_gate._write_json(root, bench_gate.PROBLEMS_FILE, {"schema_version": 1, "problems": still})
    print(f"{len(still)} recorded bench problem(s) still hold; bench commands stay refused:")
    for problem in still:
        print(f"- {problem.get('text', '?')}")
    return 1


def _reconcile_disk(root) -> int:
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
        if finding["version"] == disk_guard.inventory.UNIDENTIFIED:
            # No registry identity exists to review or approve.
            blocked.append(f"{label} could not be identified from disk; remove it: "
                           f"{disk_guard.removal_command(finding)}")
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
        # The hook's own split and order, so every command printed here is one
        # approve accepts: recommended ids first, then the decision ids.
        import hook as pg_hook
        established, unresolved, lookalikes = [], [], []
        for rid in ids:
            try:
                report = store.load_report(root, rid)
            except store.StoreError:
                report = {}
            if vetting.is_established(report):
                established.append(rid)
            elif report and pg_hook._lookalike_of(report):
                lookalikes.append(rid)
            else:
                unresolved.append(rid)
        print("")
        if established:
            print(f"Next, the established ids [{' '.join(established)}]: recommended, no vetter "
                  "needed. Say in one line per package whether it is the mainstream choice for "
                  "its purpose, then approve them first, each command exactly as written and as a "
                  "simple standalone command, one after another:")
            for command in pg_hook._approve_commands(root, established):
                print(f"  {command}")
        if unresolved or lookalikes:
            vetted = " ".join(unresolved + lookalikes)
            print(f"{'Then' if established else 'Next'}: Agent tool -> subagent_type "
                  f"package-vetter, ONCE, with the unresolved review ids [{vetted}]. Once its "
                  "report is in, approve in this order, never both kinds in one approve, at "
                  f"most {pg_hook._APPROVE_BATCH_MAX} ids per approve, each a simple standalone "
                  "command: the RECOMMEND ids first, then, after one short chat line per package "
                  "naming its red flags first, then your suggestion, the NEEDS_HUMAN_REVIEW ids.")
            print(f"  {store.cli_command(root, 'approve', '<RECOMMEND ids>')}")
            print(f"  {store.cli_command(root, 'approve', '<NEEDS_HUMAN_REVIEW ids>')}")
            print("A DO_NOT_RECOMMEND, TYPO_SQUAT or lookalike id gets no approve command: "
                  "approve it alone, only if the user asks."
                  + (f" Lookalike ids: [{' '.join(lookalikes)}]." if lookalikes else ""))
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
    """`audit`: the approved packages, then the approved baselines. Either one
    finding malware, or a provider that failed, makes the status 1."""
    status = _audit_vetted(root)
    return max(status, _audit_baselines(root))


def _audit_baselines(root) -> int:
    """Re-check every approved baseline against OSV, in as many batches as it
    takes, and write the cache the hook reads. The hook never asks
    OSV about a baseline: one bench is about 2,000 packages, over its call cap."""
    docs, problems = baseline.load_approved(root)
    for problem in problems:
        print(f"BASELINE UNREADABLE (it covers nothing): {problem}")
    if not docs:
        return 1 if problems else 0
    try:
        result = baseline.audit_baselines(root, vetting.query_osv_batch, vetting.OSV_BATCH_SIZE)
    except vetting.ProviderError as exc:
        print(f"error: the OSV audit of the baselines failed ({exc}); nothing was recorded.", file=sys.stderr)
        return 1
    status = 1 if problems else 0
    calls = result.pop("_calls")
    for bid in sorted(result):
        entry = result[bid]
        print(f"baseline {bid}: {entry['entries']} identities, {entry['advisories']} with advisories "
              f"(information), {'MALWARE' if entry['malware'] else 'no malware'}")
        for line in entry["malware"]:
            status = 1
            print(f"MALWARE: {line} - the baseline covers nothing until it is revoked and a person approves a new one:")
            print(f"  {store.cli_command(root, 'baseline', 'revoke ' + bid)}")
    print(f"{len(result)} baseline(s) checked against OSV in {calls} batch call(s).")
    return status


def _audit_vetted(root) -> int:
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


_MODE_VALUE_OPTIONS = ("--reason", "--for")
_MODE_FLAG_OPTIONS = ("--project", "--permanent")
_MODE_LOG_LINES = 10


def _parse_mode(args):
    """(mode or None, {option: value}). Raises ValueError on anything else:
    an unknown or repeated option, a second mode, a missing reason, or `--for`
    with `--permanent`."""
    chosen, options, i = None, {}, 0
    while i < len(args):
        token = args[i]
        if token in _MODE_VALUE_OPTIONS or token in _MODE_FLAG_OPTIONS:
            if token in options:
                raise ValueError(f"{token} is given twice")
            if token in _MODE_FLAG_OPTIONS:
                options[token] = True
                i += 1
                continue
            if i + 1 >= len(args):
                raise ValueError(f"{token} needs a value")
            options[token] = args[i + 1]
            i += 2
            continue
        if token.startswith("-"):
            raise ValueError(f"unknown option {token!r}")
        if chosen is not None:
            raise ValueError(f"name one mode, not {chosen!r} and {token!r}")
        if token not in pg_mode.MODES:
            raise ValueError(f"unknown mode {token!r}; use enforce, warn or off")
        chosen = token
        i += 1
    if chosen is None and options:
        raise ValueError("options need a mode: enforce, warn or off")
    if chosen == "enforce" and set(options) - {"--project"}:
        raise ValueError("enforce takes only --project")
    if chosen in ("warn", "off"):
        if not str(options.get("--reason") or "").strip():
            raise ValueError(f'{chosen} needs a reason: --reason "<why>"')
        if "--for" in options and "--permanent" in options:
            raise ValueError("use --for or --permanent, not both")
    return chosen, options


def _mode_status(root) -> int:
    print(pg_mode.describe(pg_mode.effective(root)))
    print()
    for layer, path, state in pg_mode.layers(root):
        print(f"  {layer:<9}{state}")
        if path is not None:
            print(f"  {'':<9}{path}")
    entries = pg_mode.read_log(root, _MODE_LOG_LINES)
    if entries:
        print("\nRecent changes (newest last):")
        for entry in entries:
            details = " ".join(f"{k}={entry[k]}" for k in
                               ("scope", "mode", "reason", "by", "expires_at", "code", "command")
                               if entry.get(k) is not None)
            print(f"  {entry.get('at', '?')}  {entry.get('event', '?')}  {details}")
    return 0


def _mode_enforce(root, scope) -> int:
    pg_mode.set_mode(root, "enforce", scope)
    print("Cleared your personal setting." if scope == "local" else
          "Cleared the project setting (.claude/package-guard/mode.json); commit the removal.")
    current = pg_mode.effective(root)
    print(pg_mode.describe(current))
    if current.mode != "enforce" and current.scope == "project":
        print("The project setting still applies. To clear it:\n  "
              + store.human_command(root, "mode", "enforce --project"))
    elif current.mode != "enforce" and current.scope == "local":
        print("Your personal setting still applies. To clear it:\n  "
              + store.human_command(root, "mode", "enforce"))
    try:
        caught = disk_guard.follow_mode(root, current.mode)
        if caught:
            pg_mode.append_log(root, {"event": "caught-up", "count": len(caught)})
        findings = disk_guard.open_findings(root)
    except store.StoreError as exc:
        print(f"The disk-findings record is unreadable ({exc}); package commands stay blocked "
              "until it is repaired.")
        return 0
    if findings:
        count = len(findings)
        print(f"\n{count} unreviewed package{'' if count == 1 else 's'} on disk "
              f"wait{'s' if count == 1 else ''} for review; package commands stay blocked "
              "until each is approved or removed:")
        for finding in findings:
            print(f"  - {disk_guard._label(finding)}  [{finding.get('source')}]")
    return 0


def _mode_down(root, chosen, scope, options) -> int:
    current = pg_mode.effective(root)
    if current.scope == "policy" and current.locked:
        print(f"error: {pg_mode.describe(current)} Nothing was changed.", file=sys.stderr)
        return 1
    try:
        duration = (None if options.get("--permanent") else
                    pg_mode.parse_duration(options["--for"]) if "--for" in options else
                    pg_mode.DEFAULT_DURATION)
    except ValueError as exc:
        print(f"error: {exc}. Nothing was changed.", file=sys.stderr)
        return 1
    # Claude's Bash tool has no terminal on stdin; the hook refuses this call
    # from Claude before it gets here, and this is the second lock.
    if not sys.stdin.isatty():
        print(f"error: `mode {chosen}` must be run by a person in their own terminal. "
              "Claude's commands, and `!` commands in Claude Code, have no terminal to "
              "confirm in; open a separate terminal window. Nothing was changed.",
              file=sys.stderr)
        return 1
    who = "you in this project" if scope == "local" else "everyone on this project"
    span = "with no expiry" if duration is None else f"for {options.get('--for') or '24h'}"
    effect = ("its refusals become warnings" if chosen == "warn"
              else "Claude's package installs are not checked")
    print(f"This turns Package Guard {chosen.upper()} for {who}, {span}: {effect}.")
    try:
        answer = input(f"Type '{chosen}' to confirm: ")
    except EOFError:
        answer = ""
    if answer.strip() != chosen:
        print("error: not confirmed. Nothing was changed.", file=sys.stderr)
        return 1
    # What is installed now, so that what arrives while the guard is down is
    # reviewed once it is back. The hooks take it too if this one fails.
    try:
        disk_guard.take_snapshot(root)
    except (OSError, store.StoreError) as exc:
        print(f"warning: could not record what is installed now ({exc}); the hooks will try "
              "again.", file=sys.stderr)
    pg_mode.set_mode(root, chosen, scope, options["--reason"], duration)
    print(pg_mode.describe(pg_mode.effective(root)))
    if scope == "project":
        print("Commit .claude/package-guard/mode.json so the team sees the change in review.")
    back = "enforce --project" if scope == "project" else "enforce"
    print("Turn it back on with:\n  " + store.human_command(root, "mode", back))
    return 0


def _mode(root, args) -> int:
    """`mode` shows every layer; `mode enforce` clears one; `mode warn|off`
    sets one, for a person at a terminal only."""
    try:
        chosen, options = _parse_mode(args)
    except ValueError as exc:
        print(f"error: {exc}. Nothing was changed.\n{USAGE}", file=sys.stderr)
        return 1
    if chosen is None:
        return _mode_status(root)
    scope = "project" if options.get("--project") else "local"
    if chosen == "enforce":
        return _mode_enforce(root, scope)
    return _mode_down(root, chosen, scope, options)


# ---------------------------------------------------------------------------
# baseline / git-owners (v1.12, P4)
# ---------------------------------------------------------------------------

def _baseline_seams():
    """The network and subprocess calls `baseline plan` makes. Tests replace this."""
    import baseline_plan
    return baseline_plan.Seams()


def _confirm_human(word, message) -> bool:
    """A person at a terminal types `word`: the model of `mode warn`. Claude's
    commands have no terminal on stdin, and the hook refuses these verbs from
    Claude before they get here; this is the second lock."""
    if not sys.stdin.isatty():
        print("error: this must be run by a person in their own terminal. Claude's commands, and `!` "
              "commands in Claude Code, have no terminal to confirm in; open a separate terminal window. "
              "Nothing was changed.", file=sys.stderr)
        return False
    print(message)
    try:
        answer = input(f"Type '{word}' to confirm: ")
    except EOFError:
        answer = ""
    if answer.strip() != word:
        print("error: not confirmed. Nothing was changed.", file=sys.stderr)
        return False
    return True


def _take_option(args, name, many=False):
    """(values, remaining args). `--name value` and `--name=value`; raises ValueError
    when a value is missing, or when a single-valued option is given twice."""
    values, rest, i = [], [], 0
    while i < len(args):
        token = args[i]
        if token == name:
            if i + 1 >= len(args):
                raise ValueError(f"{name} needs a value")
            values.append(args[i + 1])
            i += 2
        elif token.startswith(name + "="):
            values.append(token[len(name) + 1:])
            i += 1
        else:
            rest.append(token)
            i += 1
    if values and not many and len(values) > 1:
        raise ValueError(f"{name} is given twice")
    return values, rest


def _baseline_usage():
    return ("usage: cli.py baseline plan --app apps/<x> [--base <id>]... [--python-version 3.10] | "
            "plan <https://github.com/owner/repo> <ref> | show <id> | list | export <id> | import <file> | "
            "approve <id> | revoke <id>")


def _baseline(root, args) -> int:
    if not args:
        print(_baseline_usage(), file=sys.stderr)
        return 2
    verb, rest = args[0], list(args[1:])
    try:
        if verb == "plan":
            return _baseline_plan(root, rest)
        if verb == "show" and len(rest) == 1:
            return _baseline_show(root, rest[0])
        if verb == "list" and not rest:
            return _baseline_list(root)
        if verb == "export" and len(rest) == 1:
            doc = baseline.export_document(root, rest[0])
            print(json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False))
            return 0
        if verb == "import" and len(rest) == 1:
            return _baseline_import(root, rest[0])
        if verb == "approve":
            return _baseline_approve(root, rest)
        if verb == "revoke" and len(rest) == 1:
            return _baseline_revoke(root, rest[0])
    except ValueError as exc:
        print(f"error: {exc}\n{_baseline_usage()}", file=sys.stderr)
        return 2
    except baseline.BaselineError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(_baseline_usage(), file=sys.stderr)
    return 2


def _print_plan(root, result) -> None:
    doc = result["document"]
    owners = baseline.load_owners(root)[0]
    print(baseline.prompt_text(doc, owners))
    for note in result["notes"]:
        print(f"NOTE: {note}")
    print(f"\nProposal {doc['id']} written. A person approves it with:\n  "
          + store.cli_command(root, "baseline", f"approve {doc['id']}"))
    if baseline.all_builds(doc):
        print(f"It lists {len(baseline.all_builds(doc))} packages that build from source at install. A person "
              "approves it, in their own terminal, with one typed confirmation of the whole list:\n  "
              + store.human_command(root, "baseline", f"approve {doc['id']}"))


def _baseline_plan(root, args) -> int:
    import baseline_plan
    bases, args = _take_option(args, "--base", many=True)
    versions, args = _take_option(args, "--python-version")
    apps, args = _take_option(args, "--app")
    unknown = [a for a in args if a.startswith("-")]
    if unknown:
        raise ValueError(f"unknown option {unknown[0]!r}")
    if apps and not args:
        kwargs = {"app_dir": apps[0]}
    elif not apps and len(args) == 2:
        kwargs = {"url": args[0], "ref": args[1]}
    else:
        raise ValueError("name an app (--app apps/<x>) or a URL and a ref")
    seams = _baseline_seams()
    try:
        result = baseline_plan.plan(root, seams, base_ids=bases, python_version=versions[0] if versions else None,
                                    **kwargs)
    except baseline_plan.PlanError as exc:
        print(f"error: no proposal was written. {exc}", file=sys.stderr)
        return 1
    baseline.save_proposal(root, result["document"])
    _print_plan(root, result)
    return 0


def _baseline_show(root, bid) -> int:
    try:
        doc = baseline.load(root, bid)
    except baseline.BaselineError:
        doc = baseline.load(root, bid, proposal=True)
    print(baseline.summary_text(doc, baseline.load_owners(root)[0]))
    return 0


def _baseline_list(root) -> int:
    rows = 0
    for proposal in (False, True):
        for bid in baseline.list_ids(root, proposals=proposal):
            try:
                doc = baseline.load(root, bid, proposal=proposal)
            except baseline.BaselineError as exc:
                print(f"{bid}  UNREADABLE ({exc})")
                rows += 1
                continue
            app = doc["app"]
            state = "approved" if not proposal else ("proposal" if doc.get("approvable", True) else "proposal (malware: unapprovable)")
            print(f"{bid}  {state:<9}  {app['name']} {app['commit'][:12]}  {app['git_url']}")
            rows += 1
    if not rows:
        print("No baselines.")
    return 0


def _baseline_import(root, path) -> int:
    """A shared baseline is a proposal, and only a proposal: the plan is run again
    from the file's URL, commit and compile settings, and the file is accepted
    only when this machine computes the very same id. A file Claude wrote by hand
    names a repository and a commit and nothing else it says is believed."""
    import baseline_plan
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError) as exc:
        print(f"error: {path} cannot be read ({exc}).", file=sys.stderr)
        return 1
    claimed = baseline.proposal_from_import(data)
    app, compile_ = claimed["app"], claimed["python"]["compile"]
    seams = _baseline_seams()
    if compile_["uv"] != seams.uv_version():
        print(f"error: the file was planned with uv {compile_['uv']} and this machine has uv "
              f"{seams.uv_version()}: the id covers the compile settings, so the plan would differ. Install the "
              "same uv, or plan afresh. Nothing was written.", file=sys.stderr)
        return 1
    try:
        result = baseline_plan.plan(root, seams, url=app["git_url"], ref=app["commit"], base_ids=claimed["base"],
                                    python_version=compile_["python_version"],
                                    exclude_newer=compile_["exclude_newer"], dir_name=app["dir_name"])
    except baseline_plan.PlanError as exc:
        print(f"error: the file could not be re-planned. {exc}", file=sys.stderr)
        return 1
    if result["document"]["id"] != claimed["id"]:
        print(f"error: re-planning {app['git_url']}@{app['commit'][:12]} gives {result['document']['id']}, not "
              f"{claimed['id']}: the file does not describe that commit's dependency set. Nothing was written.",
              file=sys.stderr)
        return 1
    baseline.save_proposal(root, result["document"])
    _print_plan(root, result)
    return 0


def _baseline_approve(root, args) -> int:
    unknown = [a for a in args if a.startswith("-")]
    if unknown or len(args) != 1:
        raise ValueError("approve takes one baseline id and no option")
    doc = baseline.load(root, args[0], proposal=True)
    if doc.get("approvable") is False or doc["evidence"]["osv"]["malware"]:
        print(f"error: {doc['id']} cannot be approved: OSV lists malware in it "
              f"({'; '.join(doc['evidence']['osv']['malware'][:3])}). Nothing was approved.", file=sys.stderr)
        return 1
    owners = baseline.load_owners(root)[0]
    why = baseline.owner_problem(doc["app"]["git_url"], owners)
    if why:
        print(f"error: {why}. Nothing was approved.", file=sys.stderr)
        return 1
    builds = baseline.all_builds(doc)
    print(baseline.prompt_text(doc, owners))
    if builds and not _confirm_human(
            "build", f"\nThese {len(builds)} packages will be built from source on your machine, and their setup "
                     "code will run, when the bench installs. Approving confirms exactly this list:\n  "
                     + "\n  ".join(builds)):
        return 1
    # OSV again, after the click: a MAL- that appeared since the plan refuses the write.
    seams = _baseline_seams()
    entries = baseline.audit_entries(doc)
    malware, advisories, checked = [], 0, 0
    try:
        for ecosystem, pairs in entries.items():
            for start in range(0, len(pairs), vetting.OSV_BATCH_SIZE):
                for pair, ids in seams.osv_batch(ecosystem, pairs[start:start + vetting.OSV_BATCH_SIZE]).items():
                    checked += 1
                    advisories += 1 if ids else 0
                    malware += [f"{ecosystem}:{pair[0]}@{pair[1]} {i}" for i in ids if i.startswith("MAL-")]
    except vetting.ProviderError as exc:
        print(f"error: OSV did not answer ({exc}); nothing was approved.", file=sys.stderr)
        return 1
    if malware:
        print(f"error: OSV now lists malware: {'; '.join(malware[:5])}. Nothing was approved.", file=sys.stderr)
        return 1
    approved = baseline.approve_document(doc)
    baseline.write_approved(root, approved)
    baseline.clear_latch(root, doc["id"])  # a person's approval, after a clean re-query, ends an earlier revocation
    baseline.record_audit(root, doc["id"], checked, advisories, [])
    print(f"Approved {doc['id']} ({doc['app']['name']} {doc['app']['commit'][:12]}).")
    return 0


def _baseline_revoke(root, bid) -> int:
    if not baseline.revoke(root, bid):
        print(f"error: {bid} is not an approved baseline.", file=sys.stderr)
        return 1
    print(f"Revoked {bid}. Its document is a proposal again; nothing is declined.")
    return 0


def _git_owners(root, args) -> int:
    if args == ["list"]:
        owners, hosts = baseline.load_owners(root)
        print("Allowlisted git owners (hosts: " + ", ".join(hosts) + "): " + ", ".join(owners))
        return 0
    if len(args) == 2 and args[0] in ("add", "remove") and re.fullmatch(r"[A-Za-z0-9-]+", args[1]):
        verb, owner = args
        owners, _hosts = baseline.load_owners(root)
        near, distance = baseline.nearest_owner(owner, [o for o in owners if o != owner] or owners)
        message = (f"\nYou are {'ADDING' if verb == 'add' else 'REMOVING'} the git owner {owner!r} "
                   f"{'to' if verb == 'add' else 'from'} the allowlist.\n"
                   + (f"Nearest other allowlisted name: {near!r}, {distance} edit(s) away.\n" if near else "")
                   + ("Baselines of repositories under this owner become possible, and its commits are accepted "
                      "inside them." if verb == "add" else "Approved baselines of this owner stop covering anything."))
        if verb == "add" and owner in owners or verb == "remove" and owner not in owners:
            print(f"Nothing to do: {owner!r} is {'already' if verb == 'add' else 'not'} in the allowlist.")
            return 0
        if not _confirm_human(f"{verb} {owner}", message):
            return 1
        baseline.save_owners(root, [*owners, owner] if verb == "add" else [o for o in owners if o != owner])
        print(f"Done. Allowlisted git owners: {', '.join(baseline.load_owners(root)[0])}")
        return 0
    print("usage: cli.py git-owners list | add <owner> | remove <owner>", file=sys.stderr)
    return 2



def _explicit_root(argv):
    """(argv without `--root <dir>`, root or None). `--root` is accepted only
    directly after the subcommand: the form the hook prints and recognises."""
    if len(argv) >= 3 and argv[1] == "--root":
        root = os.path.realpath(argv[2])
        if not os.path.isdir(root):
            raise store.StoreError(f"--root {argv[2]!r} is not a directory")
        if os.path.realpath(__file__) != os.path.realpath(os.path.join(root, store.CLI_SUFFIX)):
            # Not this project's own file install: a plugin copy, run without
            # CLAUDE_PLUGIN_ROOT. Print commands in the plugin form.
            store._PLUGIN_CLI = True
        return [argv[0]] + argv[3:], Path(root)
    if any(a == "--root" or a.startswith("--root=") for a in argv):
        raise store.StoreError("--root must come directly after the subcommand")
    return argv, None


def _bench_config_usage():
    return ("usage: cli.py bench-config apply [--bench <dir>] [--toolchain name==version]... [--no-symlinks] "
            "[--new-app <name>]... | "
            "cli.py bench-config check [--bench <dir>]")


def _bench_config(root, args) -> int:
    """`bench-config apply` writes the installer files that pin what bench's installs may fetch,
    from the approved baselines of the upstream apps in the bench; `check` says whether they hold."""
    import dataclasses
    if not args or args[0] not in ("apply", "check"):
        print(_bench_config_usage(), file=sys.stderr)
        return 2
    verb, rest = args[0], list(args[1:])
    bench_dir, toolchain, no_symlinks, new_apps, i = None, [], False, [], 0
    while i < len(rest):
        token = rest[i]
        if token == "--bench" and i + 1 < len(rest):
            bench_dir, i = rest[i + 1], i + 2
        elif token == "--toolchain" and verb == "apply" and i + 1 < len(rest):
            name, equals, version = rest[i + 1].partition("==")
            if not (equals and name and version):
                print(f"error: --toolchain takes name==version, not {rest[i + 1]!r}", file=sys.stderr)
                return 2
            toolchain.append(bench_config.Pin(name, version, "", "toolchain"))
            i += 2
        elif token == "--no-symlinks" and verb == "apply":
            no_symlinks, i = True, i + 1
        elif token == "--new-app" and verb == "apply" and i + 1 < len(rest):
            if not bench_config.NEW_APP_NAME.fullmatch(rest[i + 1]):
                print(f"error: --new-app takes the name of the app `bench new-app` will create (letters, digits, "
                      f"`_` and `-`), not {rest[i + 1]!r}", file=sys.stderr)
                return 2
            new_apps.append(bench_config._normalize(rest[i + 1]))
            i += 2
        else:
            print(f"error: {token!r} is not an option of `bench-config {verb}`\n{_bench_config_usage()}",
                  file=sys.stderr)
            return 2
    bench = bench_config.bench_root(bench_dir or os.getcwd())
    if bench is None:
        print("error: no Frappe bench (a directory with apps/ and sites/) holds "
              f"{bench_dir or os.getcwd()}; use --bench <dir>", file=sys.stderr)
        return 2
    try:
        config = bench_gate.config_input(root, bench)
        if toolchain:
            config = dataclasses.replace(config, toolchain=tuple(toolchain))
        if no_symlinks:
            config = dataclasses.replace(config, no_symlinks=True)
        if new_apps:
            config = dataclasses.replace(config, new_apps=tuple(sorted({*config.new_apps, *new_apps})))
        if verb == "check":
            problems = bench_config.verify(bench, root, config, home=Path.home())
            if not problems:
                print("The guard's installer files for this bench hold, and nothing overrides them.")
                return 0
            print("The installer files for this bench do not hold:")
            for problem in problems:
                print(f"- {problem}")
            return 1
        result = bench_config.apply(bench, root, config)
    except bench_config.BenchConfigError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for path in result.written:
        print(f"wrote {path}")
    for note in result.notes:
        print(f"note: {note}")
    for path in result.dropped:
        print(f"no longer recorded: {path} (its app is not in the bench any more; the file itself is left as it is)")
    if not result.written and not result.dropped:
        print("Nothing to change: the installer files are what the approved baselines call for.")
    return 0


def main(argv) -> int:
    try:
        argv, explicit = _explicit_root(argv)
    except store.StoreError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    project = (lambda: explicit) if explicit is not None else (lambda: store.project_root(__file__))
    if argv and argv[0] == "mode":
        try:
            return _mode(project(), argv[1:])
        except (store.StoreError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if argv and argv[0] == "bench-config":
        try:
            return _bench_config(project(), argv[1:])
        except (store.StoreError, baseline.BaselineError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if argv and argv[0] in ("baseline", "git-owners"):
        try:
            return (_baseline if argv[0] == "baseline" else _git_owners)(project(), argv[1:])
        except (store.StoreError, baseline.BaselineError, OSError) as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if argv and argv[0] in _NO_ARGUMENT_COMMANDS:
        run = {"reconcile": _reconcile, "audit": _audit}[argv[0]]
        try:
            return run(project())
        except store.StoreError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 1
    if len(argv) < 2 or argv[0] not in _COMMANDS:
        print(USAGE, file=sys.stderr)
        return 2
    command, review_ids = argv[0], _dedupe(argv[1:])
    try:
        root = project()
        reports = _load_all(root, review_ids)
        if command == "show":
            fresh = _refresh(reports)
            print("\n\n".join(_summary(r, root, fresh.get(r["review_id"])) for r in reports))
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
