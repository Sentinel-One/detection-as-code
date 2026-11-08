#!/usr/bin/env python3
"""Detection as Code — validate, diff and apply detection rules from a Git repository.

One run works with one console. A repository holds one or more consoles, each with its own
deployments.yaml file at consoles/<name>.yaml (default root; override with
--consoles-dir/$CONSOLES_DIR), drawing rule files from a shared root, default detections/
(override with --detections-dir/$DETECTIONS_DIR). The console's file is bundled under the fixed
name deployments.yaml regardless of what it's called on disk. The GitHub workflow runs this
script once per console.

Works in two modes:
  - GitHub Actions mode (auto-detected via GITHUB_ACTIONS env var):
    Posts PR comments, check runs, step summaries, and uses ::error:: annotations.
  - Manual/CLI mode:
    Prints all output to the console.

Usage:
  python detection-as-code.py validate
  python detection-as-code.py diff  --deployments-file consoles/us-prod.yaml
  python detection-as-code.py apply --deployments-file consoles/us-prod.yaml

Environment variables:
  Required for diff and apply:
    API_TOKEN              API token for the console named by the deployments file
    GITHUB_REPOSITORY      Repository name (owner/repo)
    GITHUB_REPOSITORY_ID   Numeric repository ID
    HEAD_SHA               SHA of the head commit

  Optional:
    MGMT_URI               Console URL; defaults to mgmtUri in the deployments file
    DEPLOYMENTS_FILE       Path to the console's deployments.yaml (required for diff and apply)
    DETECTIONS_DIR         Rule files root, used by every command (default: detections)
    CONSOLES_DIR           Root holding one <name>.yaml file per console, used by every command
                           (default: consoles)

  Auto-set in GitHub Actions:
    GITHUB_ACTIONS         Detects GitHub Actions mode
    GITHUB_TOKEN           Token for PR comments and check runs
    PULL_REQUEST           PR number (required in diff mode to post PR comments)
    GITHUB_STEP_SUMMARY    Path to step summary file
    GITHUB_SERVER_URL      GitHub server URL (for API URL resolution)
"""

from __future__ import annotations

import argparse
import io
import json
import os
import pathlib
import re
import sys
import zipfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from enum import Enum

import requests
import yaml

API_PATH = "/web/api/v2.1/cloud-detection/rules/parse-vcs"


class Command(Enum):
    validate = "validate"
    diff = "diff"
    apply = "apply"


_GH_HTTP_TIMEOUT = 30
_DAC_HTTP_TIMEOUT = 120
_SAFE_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_PR_COMMENT_MARKER_PREFIX = "<!-- detection-as-code:"
# The identity the default GITHUB_TOKEN posts comments as, on github.com and GHE alike.
_GITHUB_ACTIONS_BOT_LOGIN = "github-actions[bot]"

DEPLOYMENTS_FILE_NAME = "deployments.yaml"
RULE_FILE_SUFFIXES = (".yaml", ".yml")

_CHANGE_TYPES = [
    ("✅", "Created", "create", "creates", "total_creates"),
    ("✏️", "Updated", "update", "updates", "total_updates"),
    ("🗑️", "Deleted", "delete", "deletes", "total_deletes"),
    ("📥", "Imported", "import", "imports", "total_imports"),
    ("🔓", "Retained", "retain", "retains", "total_retains"),
]


@dataclass(frozen=True)
class SummaryStats:
    total_creates: int
    total_updates: int
    total_deletes: int
    total_imports: int
    total_changes: int
    total_retains: int

    @classmethod
    def from_response(cls, response_data: dict) -> SummaryStats:
        summary = response_data.get("summary", {})
        return cls(
            total_creates=summary.get("totalCreates", 0),
            total_updates=summary.get("totalUpdates", 0),
            total_deletes=summary.get("totalDeletes", 0),
            total_imports=summary.get("totalImports", 0),
            total_changes=summary.get("totalChanges", 0),
            total_retains=summary.get("totalRetains", 0),
        )

    @property
    def description(self) -> str:
        if self.total_changes == 0:
            return "No detection rule changes"
        return (
            f"{self.total_creates} create(s), {self.total_updates} update(s), "
            f"{self.total_deletes} delete(s), {self.total_imports} import(s), "
            f"{self.total_retains} retain(s)"
        )


@dataclass(frozen=True)
class Console:
    name: str
    deployments_file: pathlib.Path
    root: pathlib.Path
    config: dict

    @property
    def mgmt_uri(self) -> str:
        return self.config.get("mgmtUri") or ""

    @property
    def token_secret(self) -> str:
        return self.config.get("tokenSecret") or ""


@dataclass(frozen=True)
class Args:
    command: Command
    detections_dir: str
    consoles_dir: str
    deployments_file: str
    api_token: str
    github_repository: str
    head_sha: str
    github_repository_id: str
    mgmt_uri: str


class OutputHandler(ABC):
    """Strategy base class for output handling across different environments."""

    @abstractmethod
    def info(self, msg: str) -> None: ...

    @abstractmethod
    def error(self, msg: str) -> None: ...

    @abstractmethod
    def warning(self, msg: str) -> None: ...

    @abstractmethod
    def notice(self, msg: str) -> None: ...

    @abstractmethod
    def group(self, title: str, body: str) -> None: ...

    def report_errors(self, data: dict, command: Command, console_name: str = "") -> None:
        """Parse and report API error responses."""
        response_data = data.get("data", {})
        validation_errors = response_data.get("validationErrors", {})

        if not validation_errors:
            errors_list = data.get("errors") or response_data.get("errors")
            if errors_list:
                for err in errors_list:
                    detail = err.get("detail", "")
                    title = err.get("title", "")
                    code = err.get("code", "")
                    self.error(f"{title} ({code}): {detail}" if code else f"{title}: {detail}")
                return

            error_msg = (
                data.get("error") or data.get("message") or response_data.get("error") or response_data.get("message")
            )
            if error_msg:
                self.error(f"API Error: {error_msg}")
            elif response_data:
                self.error(f"Response: {response_data}")
            else:
                self.error(f"Response: {data}")
            return

        for err in validation_errors.get("global", []):
            self.error(f"Global: {err}")

        for rule_error in validation_errors.get("rules", []):
            external_id = rule_error.get("externalId", "unknown")
            file_path = rule_error.get("filePath", "unknown")
            for err in rule_error.get("errors", []):
                self.error(f"Rule '{external_id}' ({file_path}, {_scope_label(rule_error)}): {err}")

    def report_validation_errors(self, errors: list[str], command: Command, console_name: str = "") -> None:
        for err in errors:
            self.error(err)

    def clear_validation_comment(self) -> None:
        """Minimize a stale repository-validation-failure comment once validation passes again."""

    @abstractmethod
    def report_result(self, command: Command, console_name: str, response_data: dict) -> None: ...


class ConsoleOutput(OutputHandler):
    """Outputs everything as human-readable text to stdout/stderr."""

    def info(self, msg: str) -> None:
        print(msg)

    def error(self, msg: str) -> None:
        print(f"ERROR: {msg}", file=sys.stderr)

    def warning(self, msg: str) -> None:
        print(f"WARNING: {msg}", file=sys.stderr)

    def notice(self, msg: str) -> None:
        print(f"NOTICE: {msg}")

    def group(self, title: str, body: str) -> None:
        print(f"\n{'=' * 60}\n{title}\n{'=' * 60}\n{body}\n{'=' * 60}\n")

    def report_result(self, command: Command, console_name: str, response_data: dict) -> None:
        stats = SummaryStats.from_response(response_data)

        lines = [
            f"Console: {console_name}",
            f"Total Changes: {stats.total_changes}",
            f"  Creates: {stats.total_creates}",
            f"  Updates: {stats.total_updates}",
            f"  Deletes: {stats.total_deletes}",
            f"  Imports: {stats.total_imports}",
            f"  Retains: {stats.total_retains}",
        ]

        for _icon, label, _verb, key, _total_key in _CHANGE_TYPES:
            items = response_data.get(key, [])
            if items:
                lines.append(f"\n--- {label.upper()} RULES ---")
                for item in items:
                    ext_id = item.get("externalId", "N/A")
                    name = (item.get("ruleData") or {}).get("name", ext_id)
                    lines.append(f"  {name} (id: {ext_id}, {_scope_label(item)})")

        self.group("DEPLOYMENT SUMMARY", "\n".join(lines))


class GitHubActionsOutput(OutputHandler):
    """Uses GH Actions annotations, PR comments, check runs, and step summaries."""

    def __init__(self, repository: str, head_sha: str) -> None:
        self.repository = repository
        self.head_sha = head_sha

        self.github_token = os.environ.get("GITHUB_TOKEN", "")
        self.pull_request = os.environ.get("PULL_REQUEST", "")
        self.step_summary_path = os.environ.get("GITHUB_STEP_SUMMARY", "")
        server_url = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
        if server_url == "https://github.com":
            self.api_url = "https://api.github.com"
            self.graphql_url = "https://api.github.com/graphql"
        else:
            # GitHub Enterprise Server uses /api/v3 for REST and /api/graphql for GraphQL
            self.api_url = f"{server_url}/api/v3"
            self.graphql_url = f"{server_url}/api/graphql"

    def info(self, msg: str) -> None:
        print(msg)

    def error(self, msg: str) -> None:
        print(f"::error::{msg}")

    def warning(self, msg: str) -> None:
        print(f"::warning::{msg}")

    def notice(self, msg: str) -> None:
        print(f"::notice::{msg}")

    def group(self, title: str, body: str) -> None:
        print(f"::group::{title}\n{body}\n::endgroup::")

    def report_errors(self, data: dict, command: Command, console_name: str = "") -> None:
        super().report_errors(data, command, console_name)

        body = _build_markdown_errors(data, command, console_name)
        if body:
            self._write_step_summary(body)
            if command == Command.diff:
                self._post_pr_comment(console_name, body)

    def report_validation_errors(self, errors: list[str], command: Command, console_name: str = "") -> None:
        super().report_validation_errors(errors, command, console_name)

        body = _build_markdown_validation_errors(errors, console_name)
        self._write_step_summary(body)
        if command in (Command.diff, Command.validate):
            self._post_pr_comment(console_name, body)

    def report_result(self, command: Command, console_name: str, response_data: dict) -> None:
        stats = SummaryStats.from_response(response_data)

        title = "🔍 Detection as Code — Diff Summary" if command == Command.diff else "🚀 Detection as Code — Apply Summary"
        body = _build_markdown_summary(title, console_name, response_data)

        self._write_step_summary(body)
        self._post_check_run(console_name, self.head_sha, command.value, stats, body)
        if command == Command.diff:
            self._post_pr_comment(console_name, body)

        self.info(f"\n{title} ({console_name}): {stats.total_changes} change(s) — {stats.description}")

    def _write_step_summary(self, content: str) -> None:
        if self.step_summary_path:
            with open(self.step_summary_path, "a") as f:
                f.write(content + "\n")

    def _post_check_run(
        self, console_name: str, sha: str, context_prefix: str, stats: SummaryStats, summary: str
    ) -> None:
        if not (self.github_token and self.repository and sha):
            return

        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        resp = requests.post(
            f"{self.api_url}/repos/{self.repository}/check-runs",
            headers=headers,
            json={
                "name": f"Detection as Code / {context_prefix} ({console_name})",
                "head_sha": sha,
                "status": "completed",
                "conclusion": "success",
                "output": {
                    "title": stats.description,
                    "summary": summary,
                },
            },
            timeout=_GH_HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        self.info(f"Check run posted for {sha}")

    def clear_validation_comment(self) -> None:
        self._minimize_matching_comments("")

    def _post_pr_comment(self, console_name: str, body: str) -> None:
        if not (self.github_token and self.repository and self.pull_request):
            self.warning("Skipping PR comment — missing GITHUB_TOKEN, REPOSITORY, or PULL_REQUEST")
            return

        self._minimize_matching_comments(console_name)

        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        resp = requests.post(
            f"{self.api_url}/repos/{self.repository}/issues/{self.pull_request}/comments",
            headers=headers,
            json={"body": body},
            timeout=_GH_HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        self.info("PR comment posted")

    def _minimize_matching_comments(self, console_name: str) -> None:
        """Minimize every existing comment carrying this console's marker, if any."""
        if not (self.github_token and self.repository and self.pull_request):
            return

        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        api = f"{self.api_url}/repos/{self.repository}"
        marker = _pr_comment_marker(console_name)

        resp = requests.get(
            f"{api}/issues/{self.pull_request}/comments",
            headers=headers,
            params={"per_page": 100},
            timeout=_GH_HTTP_TIMEOUT,
        )
        resp.raise_for_status()

        for comment in resp.json():
            is_ours = comment.get("user", {}).get("login") == _GITHUB_ACTIONS_BOT_LOGIN
            if is_ours and marker in comment.get("body", ""):
                self._minimize_comment(comment["node_id"])

    def _minimize_comment(self, node_id: str) -> None:
        """Collapse a previous run's comment instead of leaving it dangling once superseded."""
        query = """
            mutation($id: ID!) {
              minimizeComment(input: { subjectId: $id, classifier: OUTDATED }) {
                minimizedComment { isMinimized }
              }
            }
        """
        resp = requests.post(
            self.graphql_url,
            headers={"Authorization": f"Bearer {self.github_token}"},
            json={"query": query, "variables": {"id": node_id}},
            timeout=_GH_HTTP_TIMEOUT,
        )
        resp.raise_for_status()
        errors = resp.json().get("errors")
        if errors:
            # stderr, not self.warning(): validate's stdout is captured as JSON for the workflow's matrix.
            print(f"::warning::Could not minimize previous PR comment: {errors}", file=sys.stderr)


def _pr_comment_marker(console_name: str) -> str:
    return f"{_PR_COMMENT_MARKER_PREFIX}{console_name} -->"


def _scope_label(item: dict) -> str:
    """'site 123', 'account 456' or 'global' for a change or error item; 'all scopes' for an unscoped error."""
    scope_level = item.get("scopeLevel")
    if scope_level is None:
        return "all scopes"
    if scope_level in ("tenant", "global"):
        return "global"
    return f"{scope_level} {item.get('scopeId')}"


def _build_markdown_errors(data: dict, command: Command, console_name: str) -> str:
    """Build a markdown error summary from an API error response. Returns empty string if nothing to report."""
    title = "❌ Detection as Code — Diff Failed" if command == Command.diff else "❌ Detection as Code — Apply Failed"
    label = f" ({console_name})" if console_name else ""
    lines = [_pr_comment_marker(console_name), f"## {title}{label}", ""]

    response_data = data.get("data", {})
    validation_errors = response_data.get("validationErrors", {})
    errors_list = data.get("errors") or response_data.get("errors")

    if validation_errors:
        global_errors = validation_errors.get("global", [])
        if global_errors:
            lines.append("### Global Errors")
            for err in global_errors:
                lines.append(f"- {err}")
            lines.append("")

        rule_errors = validation_errors.get("rules", [])
        if rule_errors:
            lines.append("### Rule Errors")
            lines.append("")
            lines.append("| Rule | Scope | File | Error |")
            lines.append("|------|-------|------|-------|")
            for rule_error in rule_errors:
                external_id = rule_error.get("externalId", "unknown")
                file_path = rule_error.get("filePath", "unknown")
                for err in rule_error.get("errors", []):
                    lines.append(f"| `{external_id}` | {_scope_label(rule_error)} | `{file_path}` | {err} |")

    elif errors_list:
        lines.append("| Code | Title | Detail |")
        lines.append("|------|-------|--------|")
        for err in errors_list:
            code = err.get("code", "")
            err_title = err.get("title", "")
            detail = err.get("detail", "")
            lines.append(f"| `{code}` | {err_title} | {detail} |")

    return "\n".join(lines)


def _build_markdown_validation_errors(errors: list[str], console_name: str) -> str:
    label = f" ({console_name})" if console_name else ""
    lines = [_pr_comment_marker(console_name), f"## ❌ Detection as Code — Repository Validation Failed{label}", ""]
    lines.extend(f"- {err}" for err in errors)
    return "\n".join(lines)


def _build_markdown_summary(title: str, console_name: str, response_data: dict) -> str:
    stats = SummaryStats.from_response(response_data)

    lines = [
        _pr_comment_marker(console_name),
        f"## {title} ({console_name})",
        "",
        "| Change | Count |",
        "|--------|------:|",
    ]
    for icon, label, _verb, key, total_key in _CHANGE_TYPES:
        lines.append(f"| {icon} {label} | {getattr(stats, total_key)} |")
    lines.append(f"| **Total** | **{stats.total_changes}** |")

    for icon, _label, verb, key, _total_key in _CHANGE_TYPES:
        external_ids_by_scope: dict[str, list[str]] = {}
        for item in response_data.get(key, []):
            external_ids_by_scope.setdefault(_scope_label(item), []).append(item.get("externalId", ""))
        if external_ids_by_scope:
            lines.extend(["", f"### {icon} Rules to {verb}"])
            for scope, external_ids in external_ids_by_scope.items():
                lines.append(f"- {scope}: " + ", ".join(f"`{n}`" for n in external_ids))

    return "\n".join(lines)


# =============================================================================
# Repository layout
# =============================================================================


def _load_yaml_mapping(path: pathlib.Path) -> tuple[dict | None, str]:
    """Return (mapping, error). A file that is not a YAML mapping is an error; "" means no error."""
    try:
        with open(path, encoding="utf-8") as f:
            data = yaml.safe_load(f)
    except (OSError, yaml.YAMLError) as e:
        return None, f"{path.as_posix()}: cannot read YAML: {e}"
    if not isinstance(data, dict):
        return None, f"{path.as_posix()}: expected a YAML mapping (key: value pairs)"
    return data, ""


def discover_consoles(consoles_dir: pathlib.Path, detections_root: pathlib.Path) -> tuple[list[Console], list[str]]:
    """Find every console file under consoles_dir: <consoles_dir>/<name>.yaml."""
    errors: list[str] = []
    if not consoles_dir.is_dir():
        errors.append(f"No {consoles_dir.as_posix()}/ found: expected {consoles_dir.as_posix()}/<console>.yaml")
        return [], errors

    candidates = sorted(p for p in consoles_dir.iterdir() if p.is_file() and p.suffix in RULE_FILE_SUFFIXES)
    if not candidates:
        errors.append(f"No console files found in {consoles_dir.as_posix()}/")
        return [], errors

    consoles: list[Console] = []
    for path in candidates:
        config, error = _load_yaml_mapping(path)
        if error:
            errors.append(error)
            continue
        consoles.append(Console(name=path.stem, deployments_file=path, root=detections_root, config=config or {}))
    return consoles, errors


def load_console(deployments_file: pathlib.Path, detections_root: pathlib.Path) -> tuple[Console | None, list[str]]:
    if not deployments_file.exists():
        return None, [f"'{deployments_file.as_posix()}' not found"]
    config, error = _load_yaml_mapping(deployments_file)
    if error:
        return None, [error]
    return Console(
        name=deployments_file.stem, deployments_file=deployments_file, root=detections_root, config=config or {}
    ), []


# =============================================================================
# Validation
# =============================================================================


def _validate_console_config(console: Console, errors: list[str]) -> None:
    file_label = console.deployments_file.as_posix()
    if not _SAFE_NAME.match(console.name):
        errors.append(f"{file_label}: console name {console.name!r} may only use letters, digits, '.', '_' and '-'")

    config = console.config
    if not isinstance(config.get("mgmtUri"), str) or not config["mgmtUri"].strip():
        errors.append(f"{file_label}: 'mgmtUri' is required and must be the console URL")
    if not isinstance(config.get("tokenSecret"), str) or not _SAFE_NAME.match(config["tokenSecret"]):
        errors.append(f"{file_label}: 'tokenSecret' is required and must be a secret name")

    targets = config.get("targets")
    if not isinstance(targets, dict) or not targets:
        errors.append(f"{file_label}: 'targets' must be a non-empty mapping")
        targets = {}
    deploy = config.get("deploy")
    if not isinstance(deploy, dict) or not deploy:
        errors.append(f"{file_label}: 'deploy' must be a non-empty mapping of target name to glob list")
        deploy = {}

    for target_name, patterns in deploy.items():
        if target_name not in targets:
            errors.append(f"{file_label}: deploy target {target_name!r} is not defined under 'targets'")
        if not isinstance(patterns, list) or not all(isinstance(p, str) for p in patterns):
            errors.append(f"{file_label}: deploy patterns for {target_name!r} must be a list of strings")


def _list_rule_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Every rule file under root, in a stable order -- the set both validated and bundled."""
    return sorted(p for p in root.rglob("*") if p.is_file() and p.suffix in RULE_FILE_SUFFIXES)


def _validate_rule_files(root: pathlib.Path, errors: list[str]) -> None:
    paths_by_id: dict[str, list[str]] = {}
    for path in _list_rule_files(root):
        rel_path = path.relative_to(root).as_posix()
        rule, error = _load_yaml_mapping(path)
        if error:
            errors.append(error)
            continue
        rule_id = (rule or {}).get("id")
        if not isinstance(rule_id, str) or not rule_id.strip():
            errors.append(f"{rel_path}: rule must have a string 'id'")
            continue
        paths_by_id.setdefault(rule_id, []).append(rel_path)

    for rule_id, paths in sorted(paths_by_id.items()):
        if len(paths) > 1:
            errors.append(f"Duplicate rule id {rule_id!r} in {len(paths)} files: {', '.join(paths)}")


def validate_repository(consoles_dir: pathlib.Path, detections_root: pathlib.Path) -> tuple[list[Console], list[str]]:
    """Check every console under consoles_dir and every rule file under detections_root."""
    consoles, errors = discover_consoles(consoles_dir, detections_root)

    seen_uris: dict[str, str] = {}
    for console in consoles:
        _validate_console_config(console, errors)
        uri = console.mgmt_uri
        if uri.strip():
            key = uri.strip().rstrip("/").lower()
            if key in seen_uris:
                errors.append(
                    f"Consoles {seen_uris[key]!r} and {console.name!r} point at the same console {uri}; "
                    f"two files for one console would delete each other's rules"
                )
            seen_uris[key] = console.name

    _validate_rule_files(detections_root, errors)
    return consoles, errors


# =============================================================================
# Bundle
# =============================================================================


def build_bundle(console: Console) -> tuple[bytes, list[str]]:
    """Zip the console's deployments.yaml plus every rule file; the backend applies the deploy globs."""
    included: list[str] = []
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.write(console.deployments_file, DEPLOYMENTS_FILE_NAME)
        for path in _list_rule_files(console.root):
            rel_path = path.relative_to(console.root).as_posix()
            archive.write(path, rel_path)
            included.append(rel_path)
    return buffer.getvalue(), included


def send_bundle(
    out: OutputHandler,
    bundle: bytes,
    url: str,
    api_token: str,
    extra_data: dict[str, str],
) -> tuple[dict, bool]:
    """POST the bundle zip to the API. Returns (response_data, ok)."""
    out.info(f"Sending bundle to {url}")

    resp = requests.post(
        url,
        headers={"Authorization": f"Bearer {api_token}"},
        files={"file": ("detections.zip", bundle, "application/zip")},
        data=extra_data,
        timeout=_DAC_HTTP_TIMEOUT,
    )

    try:
        response_json = resp.json()
    except json.JSONDecodeError:
        out.error(f"HTTP {resp.status_code} — invalid JSON response: {resp.text}")
        sys.exit(1)

    if not resp.ok:
        out.error(f"HTTP {resp.status_code}")
        return response_json, False

    out.info(f"Success: HTTP {resp.status_code}")
    return response_json.get("data", response_json), True


# =============================================================================
# Commands
# =============================================================================


def _make_output(github_repository: str, head_sha: str) -> OutputHandler:
    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        return GitHubActionsOutput(github_repository, head_sha)
    return ConsoleOutput()


def run_validate(detections_dir: str, consoles_dir: str, github_repository: str, head_sha: str) -> None:
    """Validate the repository, then print its consoles as JSON for the workflow's matrix."""
    out = _make_output(github_repository, head_sha)
    detections_root = pathlib.Path(detections_dir)
    consoles_root = pathlib.Path(consoles_dir)
    consoles, errors = validate_repository(consoles_root, detections_root)
    if errors:
        out.report_validation_errors(errors, Command.validate)
        sys.exit(1)
    out.clear_validation_comment()
    entries = [
        {
            "name": console.name,
            "mgmtUri": console.mgmt_uri,
            "tokenSecret": console.token_secret,
            "deploymentsFile": pathlib.Path(os.path.relpath(console.deployments_file)).as_posix(),
        }
        for console in consoles
    ]
    print(json.dumps(entries, separators=(",", ":")))


def run_sync(args: Args) -> None:
    out = _make_output(args.github_repository, args.head_sha)
    command = args.command

    if not args.deployments_file:
        out.report_validation_errors(
            ["--deployments-file (or $DEPLOYMENTS_FILE) is required for diff and apply"], command
        )
        sys.exit(1)
    deployments_file = pathlib.Path(args.deployments_file)
    detections_root = pathlib.Path(args.detections_dir)
    console, errors = load_console(deployments_file, detections_root)
    if console is None:
        out.report_validation_errors(errors, command)
        sys.exit(1)

    mgmt_uri = args.mgmt_uri or console.mgmt_uri
    required = {
        "API_TOKEN": args.api_token,
        "MGMT_URI": mgmt_uri,
        "GITHUB_REPOSITORY_ID": args.github_repository_id,
        "GITHUB_REPOSITORY": args.github_repository,
        "HEAD_SHA": args.head_sha,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        out.error(
            f"Missing required values: {', '.join(missing)} "
            f"(set via CLI arguments, environment variables, or mgmtUri in {deployments_file.as_posix()})"
        )
        sys.exit(1)

    bundle, included = build_bundle(console)
    targets = console.config.get("targets") or {}
    target_lines = [
        f"  {name}: scopeLevel={cfg.get('scopeLevel', 'N/A')} scopeId={cfg.get('scopeId', 'N/A')}"
        for name, cfg in targets.items()
        if isinstance(cfg, dict)
    ]
    out.group(
        f"Console: {console.name}",
        "\n".join(
            [
                f"  mgmtUri:     {mgmt_uri}",
                f"  deployments: {deployments_file.as_posix()}",
                "  targets:",
                *target_lines,
                f"  rule files:  {len(included)}",
                *(f"    {path}" for path in included),
            ]
        ),
    )

    url = f"{mgmt_uri.rstrip('/')}{API_PATH}?mode={command.value}"
    extra_data: dict[str, str] = {
        "vcsRepoId": args.github_repository_id,
        "vcsRepoName": args.github_repository,
        "vcsCommitId": args.head_sha,
    }

    response_data, ok = send_bundle(out, bundle, url, args.api_token, extra_data)
    if not ok:
        out.report_errors(response_data, command, console.name)
        sys.exit(1)

    out.report_result(command, console.name, response_data)


def main() -> None:
    parser = argparse.ArgumentParser(description="Detection as Code — validate, diff or apply detection rules")
    parser.add_argument(
        "command",
        type=Command,
        choices=list(Command),
        metavar="{validate,diff,apply}",
        help="Operation to perform",
    )
    parser.add_argument(
        "--detections-dir",
        default=os.environ.get("DETECTIONS_DIR", "detections"),
        help="Rule files root, used by every command (default: $DETECTIONS_DIR or 'detections')",
    )
    parser.add_argument(
        "--consoles-dir",
        default=os.environ.get("CONSOLES_DIR", "consoles"),
        help="Root directory holding one <name>.yaml file per console (default: $CONSOLES_DIR or 'consoles')",
    )
    parser.add_argument(
        "--deployments-file",
        default=os.environ.get("DEPLOYMENTS_FILE", ""),
        help="The console's deployments.yaml for diff and apply, e.g. consoles/us-prod.yaml "
        "(default: $DEPLOYMENTS_FILE)",
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("API_TOKEN", ""),
        help="API token (default: $API_TOKEN)",
    )
    parser.add_argument(
        "--github-repository",
        default=os.environ.get("GITHUB_REPOSITORY", ""),
        help="Repository name (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--head-sha",
        default=os.environ.get("HEAD_SHA", ""),
        help="Head commit hash (default: $HEAD_SHA)",
    )
    parser.add_argument(
        "--github-repository-id",
        default=os.environ.get("GITHUB_REPOSITORY_ID", ""),
        help="ID of the GitHub repo (default: $GITHUB_REPOSITORY_ID)",
    )
    parser.add_argument(
        "--mgmt-uri",
        default=os.environ.get("MGMT_URI", ""),
        help="Management console URI (default: $MGMT_URI, then mgmtUri from the deployments file)",
    )
    args = Args(**vars(parser.parse_args()))

    if args.command == Command.validate:
        run_validate(args.detections_dir, args.consoles_dir, args.github_repository, args.head_sha)
    else:
        run_sync(args)


if __name__ == "__main__":
    main()
