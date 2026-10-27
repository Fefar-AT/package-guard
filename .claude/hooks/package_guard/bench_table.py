"""The `bench` verb table: what each verb of Frappe's bench does to the packages on disk.

Pure: `classify` reads the words after `bench` and answers with a `Verdict`, and the parser
turns that into its own result. Every row is read from bench's source (`bench/commands/*.py`,
the commands of `bench/commands/__init__.py`) and Frappe's own (`frappe/commands/*.py`,
versions 11 to 16); a verb that is in no list below is refused, because an unknown verb may be
an app's own command or a release's new one.

  inert    acquires nothing: it edits configuration, starts or stops processes, runs a Frappe
           command that is project code (`migrate`, `console`), or removes something
  scope    installs or runs project code under a gate the hook applies (`BenchScope`):
           `setup requirements`, `update --requirements`, `new-app`, and the runners
           (`build`, `update --patch --build`)
  refuse   pulls code whose commit cannot be named in advance, recreates the env without the
           guard's pip.conf, installs system packages, or is the person's alone

The refusal texts name the split a person can follow: a git step that pins a commit, a baseline
a human approves, `bench-config apply`, then `bench setup requirements <app>`.
"""
from __future__ import annotations

import re
from typing import NamedTuple

_APP_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]*\Z")


class Verdict(NamedTuple):
    action: str            # "inert" | "scope" | "refuse"
    verb: str = ""         # the scope's key, or the verb as shown in a refusal
    apps: tuple = ()       # the apps a scope names (empty: every app)
    node: bool = False     # setup requirements --node
    python: bool = False   # setup requirements --python
    dev: bool = False      # setup requirements --dev
    code: str = ""         # the denial code of a refusal
    reason: str = ""


# -- what bench itself offers, by what it does ------------------------------------------------

# Commands that change configuration, start or stop processes, or print.
INERT_BENCH = frozenset({
    "start", "restart", "set-nginx-port", "set-ssl-certificate", "set-ssl-certificate-key",
    "set-url-root", "set-mariadb-host", "set-redis-cache-host", "set-redis-queue-host",
    "set-redis-socketio-host", "download-translations", "backup-all-sites", "renew-lets-encrypt",
    "disable-production", "src", "find-benches", "app-cache", "drop", "exclude-app", "include-app",
    "validate-dependencies", "remote-set-url", "remote-reset-url", "remote-urls", "completions",
    "remove-app", "remove", "rm", "config", "socketio-status",
})
# `bench setup <x>` that generate files or run system tools already on the machine.
INERT_SETUP = frozenset({
    "sudoers", "nginx", "reload-nginx", "supervisor", "redis", "backups", "ssh-port",
    "lets-encrypt", "wildcard-ssl", "procfile", "config", "add-domain", "remove-domain",
    "sync-domains", "fail2ban", "systemd",
})
# Frappe's own commands (`bench <name>` hands them to frappe): project code, database work. The
# ones that fetch packages or code are in REFUSED_FRAPPE.
INERT_FRAPPE = frozenset({
    "add-system-manager", "add-to-email-queue", "add-to-hosts", "add-user", "backup", "browse",
    "build-message-files", "build-search-index", "bulk-rename", "bypass-patch", "clear-cache",
    "clear-log-table", "clear-website-cache", "console", "convert-sidebar-fixtures", "create-patch",
    "create-po-file", "data-import", "db-console", "destroy-all-sessions", "disable-scheduler",
    "disable-user", "drop-site", "enable-scheduler", "execute", "export-csv", "export-doc",
    "export-fixtures", "export-json", "generate-pot-file", "get-untranslated", "import-csv",
    "import-doc", "import-translations", "install-app", "list-apps", "list-sites", "make-app",
    "mariadb", "migrate", "migrate-csv-to-po", "migrate-to", "migrate-translations", "mysql",
    "new-language", "new-site", "partial-restore", "postgres", "publish-realtime", "purge-jobs",
    "ready-for-migration", "rebuild-global-search", "reinstall", "reload-doc", "reload-doctype",
    "remove-from-installed-apps", "request", "reset-perms", "restore", "run-parallel-tests",
    "run-patch", "run-tests", "schedule", "scheduler", "serve", "set-admin-password", "set-config",
    "set-last-active-for-user", "set-limit", "set-limits", "set-maintenance-mode", "set-password",
    "setup-global-help", "setup-help", "show-config", "show-pending-jobs", "sqlite", "start-recording",
    "stop-recording", "sync-desktop-icons", "trigger-scheduler-event", "trim-tables", "uninstall-app",
    "update-csv-from-po", "update-translations", "use", "version", "worker", "ngrok", "gettext",
    "extract-pot-file", "compile-po-to-mo", "update-po-files", "new-po-file", "sync-fixtures",
    "add-database-index", "clear-limits", "create-rq-users", "describe-database-table", "doctor",
    "transform-database", "trim-database", "worker-pool",
})
# Frappe commands that install packages or fetch code: `jupyter` runs `pip install jupyter`,
# `run-ui-tests` runs `yarn add` for the test runner, the docs ones clone repositories,
# `auto-deploy` pulls and runs `bench update`, `setup-chrome` downloads a browser.
REFUSED_FRAPPE = {
    "jupyter": "runs `pip install jupyter` in the env",
    "run-ui-tests": "runs `yarn add` for the test runner in apps/frappe",
    "run-setup-wizard-ui-test": "runs `yarn add` for the test runner in apps/frappe",
    "setup-chrome": "downloads a browser",
    "get-docs-app": "clones a repository",
    "get-all-docs-apps": "clones repositories",
    "auto-deploy": "pulls an app and runs `bench update`",
    "build-docs": "builds documentation with tools it may fetch",
}
# Commands that run project code from the repository (a build is a `yarn run` script).
RUNNERS = frozenset({"build", "watch"})

# -- what is refused, and why --------------------------------------------------------------------

_SPLIT = (
    "split it: (1) `git clone --origin upstream <url> apps/<app>` and `git -C apps/<app> checkout "
    "--detach <40-hex commit>` (a git step Claude may run); (2) the user approves a baseline for it "
    "(`cli.py baseline plan --app apps/<app>`, then the approval); (3) the user runs "
    "`cli.py bench-config apply`; (4) `bench setup requirements <app>`, then `bench build --app <app>`. "
    "After `checkout --detach` the app is on no branch and every later `bench update` fails on it, "
    "so installs go through `bench setup requirements <app>`")
_PULLS = {
    "get-app": "clones a branch tip, never a commit",
    "get": "clones a branch tip, never a commit",
    "switch-to-branch": "checks out a branch tip in every app",
    "switch-to-develop": "checks out a branch tip in every app",
    "retry-upgrade": "pulls every app",
    "update": "pulls every app to a commit Package Guard cannot know in advance",
}
_HUMAN = {
    "migrate-env": "recreates env/, which drops the guard's pip.conf, and installs every app into it",
    "setup env": "recreates the env with pip and wheel unpinned",
    "setup production": "installs ansible with sudo pip and system packages through roles",
    "setup role": "runs ansible playbooks under sudo",
    "setup manager": "runs `bench get-app bench_manager`",
    "setup socketio": "ran an unpinned `npm install` before bench 5.7",
    "setup firewall": "runs an ansible playbook under sudo to install and configure the firewall",
    "setup fonts": "clones a font repository and installs it system-wide",
    "install": "installs system packages through ansible",
}


def _refuse(verb, why, code="unsupported-form", pulls=False):
    if pulls:
        reason = f"`bench {verb}` {why}. For an app that is already checked out at an exact commit, {_SPLIT}."
    else:
        reason = (f"`bench {verb}` {why}; Package Guard does not run it. It is for the user to run in "
                  "their own terminal. Tell the user.")
    return Verdict("refuse", verb, code=code, reason=reason)


# -- reading the words ---------------------------------------------------------------------------

_GROUP_VALUE_FLAGS = ("--site", "--use-feature")
_GROUP_FLAGS = ("-v", "--verbose")


def _after_group_flags(texts) -> list:
    index = 0
    while index < len(texts) and texts[index].startswith("-"):
        if texts[index] in ("--version", "--help", "-h"):
            return [texts[index]]
        if texts[index] in _GROUP_VALUE_FLAGS:
            index += 2
        elif texts[index] in _GROUP_FLAGS or texts[index].startswith(("--site=", "--use-feature=")):
            index += 1
        else:
            return [texts[index]]  # an unknown group flag: refused by the caller
    return list(texts[index:])


def _split_flags(args, valued=(), flags=()):
    """(flags set, {flag: value}, positionals) or an error text. `--flag=value` and `--flag value`."""
    seen, values, positional, i = set(), {}, [], 0
    while i < len(args):
        arg = args[i]
        if arg.startswith("-") and len(arg) > 1:
            name, equals, value = arg.partition("=")
            if name in valued:
                if not equals:
                    if i + 1 >= len(args):
                        return f"{name} needs a value"
                    value, i = args[i + 1], i + 1
                values.setdefault(name, []).append(value)
            elif name in flags and not equals:
                seen.add(name)
            else:
                return f"{arg!r} is not a flag Package Guard knows for this verb"
        else:
            positional.append(arg)
        i += 1
    return seen, values, positional


def _apps(names) -> tuple | str:
    found = []
    for name in names:
        for part in str(name).split(","):
            part = part.strip()
            if not part:
                continue
            if not _APP_NAME.match(part):
                return f"{part!r} is not an app name"
            if part not in found:
                found.append(part)
    return tuple(found)


def classify(texts) -> Verdict:
    """The decision for the words after `bench`."""
    words = _after_group_flags(list(texts))
    if not words:
        return Verdict("inert")
    verb, args = words[0], words[1:]
    if verb.startswith("-"):
        if verb in ("--version", "--help", "-h"):
            return Verdict("inert")
        return Verdict("refuse", verb, code="unsupported-flag",
                       reason=f"{verb!r} is not an option of bench that Package Guard knows")
    if verb == "init":
        return Verdict("refuse", "init", code="foreign-manager", reason=(
            "`bench init` creates the env and installs Frappe and its packages; it is for the user to "
            "run in their own terminal. Tell the user."))
    if verb == "pip":
        return Verdict("inert", "pip")  # read as the pip command it runs, by the caller
    if verb == "setup":
        return _setup(args)
    if verb in ("update",):
        return _update(args)
    if verb == "new-app":
        return _new_app(args)
    if verb in _PULLS:
        return _refuse(verb, f"{_PULLS[verb]}", pulls=True)
    if verb in _HUMAN:
        return _refuse(verb, _HUMAN[verb])
    if verb in RUNNERS:
        return _runner(verb, args)
    if verb in REFUSED_FRAPPE:
        return _refuse(verb, REFUSED_FRAPPE[verb])
    if verb in INERT_BENCH or verb in INERT_FRAPPE:
        return Verdict("inert", verb)
    return Verdict("refuse", verb, code="unknown-verb", reason=(
        f"`bench {verb}` is not a command Package Guard knows: it may be an app's own command, or "
        "one of a release it has not seen, and either may install something. Tell the user."))


def _setup(args) -> Verdict:
    if not args:
        return Verdict("inert", "setup")
    sub, rest = args[0], args[1:]
    if sub == "requirements":
        parsed = _split_flags(rest, flags=("--node", "--python", "--dev"))
        if isinstance(parsed, str):
            return Verdict("refuse", "setup requirements", code="unsupported-flag", reason=parsed)
        flags, _values, positional = parsed
        apps = _apps(positional)
        if isinstance(apps, str):
            return Verdict("refuse", "setup requirements", code="unsupported-form", reason=apps)
        # bench's own dispatch (`bench/commands/setup.py`): with neither --node nor --python (and no --dev) it
        # runs `Bench.setup.requirements` -> `install_app`; with exactly one of them, that part only; with
        # --dev, or with --node AND --python together, it falls to the last branch and installs ONLY the
        # development dependencies. Both of those spellings are `dev`.
        return Verdict("scope", "setup-requirements", apps, node="--node" in flags,
                       python="--python" in flags, dev="--dev" in flags or ("--node" in flags and "--python" in flags))
    key = f"setup {sub}"
    if key in _HUMAN:
        return _refuse(key, _HUMAN[key])
    if sub in INERT_SETUP:
        return Verdict("inert", key)
    return Verdict("refuse", key, code="unknown-verb", reason=(
        f"`bench setup {sub}` is not a command Package Guard knows. Tell the user."))


_UPDATE_FLAGS = ("--pull", "--patch", "--build", "--requirements", "--restart-supervisor",
                 "--restart-systemd", "--no-backup", "--no-compile", "--force", "--reset")


def _update(args) -> Verdict:
    parsed = _split_flags(args, valued=("--apps",), flags=_UPDATE_FLAGS)
    if isinstance(parsed, str):
        return Verdict("refuse", "update", code="unsupported-flag", reason=parsed)
    flags, values, positional = parsed
    if positional:
        return Verdict("refuse", "update", code="unsupported-form",
                       reason=f"`bench update` takes no argument ({positional[0]!r})")
    pulling = flags & {"--pull", "--reset"} or "--apps" in values
    chosen = flags & {"--patch", "--build", "--requirements"}
    if pulling or not chosen:
        why = ("pulls every app to a commit Package Guard cannot know in advance" if pulling else
               "with no flag means pull, patch, build and requirements")
        return _refuse("update" + (" " + " ".join(sorted(flags)) if flags else ""), why, pulls=True)
    if "--requirements" in chosen:
        return Verdict("scope", "update-requirements")
    return Verdict("scope", "update-run")


def _new_app(args) -> Verdict:
    parsed = _split_flags(args, flags=("--no-git",))
    if isinstance(parsed, str):
        return Verdict("refuse", "new-app", code="unsupported-flag", reason=parsed)
    _flags, _values, positional = parsed
    if len(positional) != 1 or not _APP_NAME.match(positional[0]):
        return Verdict("refuse", "new-app", code="unsupported-form",
                       reason="`bench new-app` takes one app name (letters, digits, `_` and `-`)")
    return Verdict("scope", "new-app", ("frappe",))


def _runner(verb, args) -> Verdict:
    """`bench build` and `bench watch`: a `yarn run` (v11 to v15) or a node script in the app."""
    names = []
    i = 0
    while i < len(args):
        arg = args[i]
        name, equals, value = arg.partition("=")
        if name in ("--app", "--apps"):
            if not equals:
                if i + 1 >= len(args):
                    return Verdict("refuse", verb, code="unsupported-flag", reason=f"{name} needs a value")
                value, i = args[i + 1], i + 1
            names.append(value)
        i += 1
    apps = _apps(names)
    if isinstance(apps, str):
        return Verdict("refuse", verb, code="unsupported-form", reason=apps)
    return Verdict("scope", "build", tuple(dict.fromkeys(("frappe",) + apps)))
