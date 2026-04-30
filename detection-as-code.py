#!/usr/bin/env python3
"""Detections as Code — unified script for diff and apply operations.

Works in two modes:
  - GitHub Actions mode (auto-detected via GITHUB_ACTIONS env var):
    Posts PR comments, commit statuses, step summaries, and uses ::error:: annotations.
  - Manual/CLI mode:
    Prints all output to the console.

Usage:
  python detection-as-code.py diff
  python detection-as-code.py apply

Environment variables:
  Required when running from CLI and in GitHub Actions to be able to call DaC API:
    API_TOKEN              API token for the management endpoint
    MGMT_URI               Management console URI (e.g., https://user-console.sentinelone.net)
    GITHUB_REPOSITORY      Repository name (owner/repo)
    GITHUB_REPOSITORY_ID   Numeric repository ID
    HEAD_SHA               SHA of the head commit

  Auto-set in GitHub Actions:
    GITHUB_ACTIONS         Detects GitHub Actions mode
    GITHUB_TOKEN           Token for PR comments and commit statuses
    PULL_REQUEST           PR number (required in diff mode to post PR comments)
    GITHUB_STEP_SUMMARY    Path to step summary file
    GITHUB_SERVER_URL      GitHub server URL (for API URL resolution)

  Optional:
    DEPLOYMENTS_FILE       Path to the deployments.yaml file (default: detections/deployments.yaml)
"""

from __future__ import annotations

import argparse
import json
import os
import pathlib
import re
import shutil
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass

import requests
import yaml

API_PATH = "/web/api/v2.1/cloud-detection/rules/parse-vcs"

_GH_HTTP_TIMEOUT = 30
_DAC_HTTP_TIMEOUT = 120
_SAFE_TARGET_NAME = re.compile(r"^[A-Za-z0-9._-]+$")
_PR_COMMENT_MARKER = "<!-- detections-as-code -->"

@dataclass(frozen=True)
class SummaryStats:
    total_creates: int
    total_updates: int
    total_deletes: int
    total_changes: int

    @classmethod
    def from_response(cls, response_data: dict) -> SummaryStats:
        summary = response_data.get("summary", {})
        return cls(
            total_creates=summary.get("totalCreates", 0),
            total_updates=summary.get("totalUpdates", 0),
            total_deletes=summary.get("totalDeletes", 0),
            total_changes=summary.get("totalChanges", 0),
        )

    @property
    def description(self) -> str:
        if self.total_changes == 0:
            return "No detection rule changes"
        return f"{self.total_creates} create(s), {self.total_updates} update(s), {self.total_deletes} delete(s)"


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

    def report_errors(self, data: dict, command: str = "", target_name: str = "") -> None:
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
                self.error(f"Rule '{external_id}' ({file_path}): {err}")

    @abstractmethod
    def report_result(self, command: str, target_name: str, response_data: dict) -> None: ...


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

    def report_result(self, command: str, target_name: str, response_data: dict) -> None:
        stats = SummaryStats.from_response(response_data)

        lines = [
            f"Total Changes: {stats.total_changes}",
            f"  Creates: {stats.total_creates}",
            f"  Updates: {stats.total_updates}",
            f"  Deletes: {stats.total_deletes}",
        ]

        for label, key in [("CREATED", "creates"), ("UPDATED", "updates"), ("DELETED", "deletes")]:
            items = response_data.get(key, [])
            if items:
                lines.append(f"\n--- {label} RULES ---")
                for item in items:
                    ext_id = item.get("externalId", "N/A")
                    name = item.get("ruleData", {}).get("name", ext_id)
                    lines.append(f"  {name} (id: {ext_id})")

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
        else:
            # GitHub Enterprise Server uses /api/v3 path
            self.api_url = f"{server_url}/api/v3"

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

    def report_errors(self, data: dict, command: str = "", target_name: str = "") -> None:
        super().report_errors(data, command, target_name)

        body = _build_markdown_errors(data, command, target_name)
        if body:
            self._write_step_summary(body)
            if command == "diff":
                self._post_or_update_pr_comment(body)

    def report_result(self, command: str, target_name: str, response_data: dict) -> None:
        stats = SummaryStats.from_response(response_data)

        title = "🔍 Detections as Code — Diff Summary" if command == "diff" else "🚀 Detections as Code — Apply Summary"
        body = _build_markdown_summary(title, target_name, response_data)

        self._write_step_summary(body)
        self._post_check_run(target_name, self.head_sha, command, stats, body)
        if command == "diff":
            self._post_or_update_pr_comment(body)

        self.info(f"\n{title} ({target_name}): {stats.total_changes} change(s) — {stats.description}")

    def _write_step_summary(self, content: str) -> None:
        if self.step_summary_path:
            with open(self.step_summary_path, "a") as f:
                f.write(content + "\n")

    def _post_check_run(self, target_name: str, sha: str, context_prefix: str, stats: SummaryStats, summary: str) -> None:
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
                "name": f"Detections as Code / {context_prefix} ({target_name})",
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

    def _post_or_update_pr_comment(self, body: str) -> None:
        if not (self.github_token and self.repository and self.pull_request):
            self.warning("Skipping PR comment — missing GITHUB_TOKEN, REPOSITORY, or PULL_REQUEST")
            return

        headers = {
            "Authorization": f"token {self.github_token}",
            "Accept": "application/vnd.github+json",
        }
        api = f"{self.api_url}/repos/{self.repository}"

        resp = requests.get(f"{api}/issues/{self.pull_request}/comments", headers=headers, timeout=_GH_HTTP_TIMEOUT)
        resp.raise_for_status()

        existing_id = None
        for comment in resp.json():
            if _PR_COMMENT_MARKER in comment.get("body", ""):
                existing_id = comment["id"]
                break

        if existing_id:
            resp = requests.patch(
                f"{api}/issues/comments/{existing_id}",
                headers=headers,
                json={"body": body},
                timeout=_GH_HTTP_TIMEOUT,
            )
        else:
            resp = requests.post(
                f"{api}/issues/{self.pull_request}/comments",
                headers=headers,
                json={"body": body},
                timeout=_GH_HTTP_TIMEOUT,
            )
        resp.raise_for_status()
        self.info("PR comment posted")


def _build_markdown_errors(data: dict, command: str, target_name: str) -> str:
    """Build a markdown error summary from an API error response. Returns empty string if nothing to report."""
    title = "❌ Detections as Code — Diff Failed" if command == "diff" else "❌ Detections as Code — Apply Failed"
    label = f" ({target_name})" if target_name else ""
    lines = [_PR_COMMENT_MARKER, f"## {title}{label}", ""]

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
            lines.append("| Rule | File | Error |")
            lines.append("|------|------|-------|")
            for rule_error in rule_errors:
                external_id = rule_error.get("externalId", "unknown")
                file_path = rule_error.get("filePath", "unknown")
                for err in rule_error.get("errors", []):
                    lines.append(f"| `{external_id}` | `{file_path}` | {err} |")

    elif errors_list:
        lines.append("| Code | Title | Detail |")
        lines.append("|------|-------|--------|")
        for err in errors_list:
            code = err.get("code", "")
            err_title = err.get("title", "")
            detail = err.get("detail", "")
            lines.append(f"| `{code}` | {err_title} | {detail} |")

    return "\n".join(lines)


def _build_markdown_summary(title: str, target_name: str, response_data: dict) -> str:
    stats = SummaryStats.from_response(response_data)

    creates = [c.get("externalId", "") for c in response_data.get("creates", [])]
    updates = [u.get("externalId", "") for u in response_data.get("updates", [])]
    deletes = [d.get("externalId", "") for d in response_data.get("deletes", [])]

    lines = [
        _PR_COMMENT_MARKER,
        f"## {title} ({target_name})",
        "",
        "| Change | Count |",
        "|--------|------:|",
        f"| ✅ Created | {stats.total_creates} |",
        f"| ✏️ Updated | {stats.total_updates} |",
        f"| 🗑️ Deleted | {stats.total_deletes} |",
        f"| **Total** | **{stats.total_changes}** |",
    ]

    for label, items in [
        ("✅ Rules to create", creates),
        ("✏️ Rules to update", updates),
        ("🗑️ Rules to delete", deletes),
    ]:
        if items:
            rule_list = ", ".join(f"`{n}`" for n in items)
            lines.extend(["", f"### {label}", rule_list])

    return "\n".join(lines)


def load_config(out: OutputHandler, config_path: pathlib.Path) -> tuple[str, dict]:
    """Load and validate deployments.yaml, returning (target_name, target_config)."""
    if not config_path.exists():
        out.error(f"'{config_path}' not found")
        sys.exit(1)

    with open(config_path, encoding="utf-8") as f:
        config = yaml.safe_load(f) or {}

    targets = config.get("targets", {})
    if not targets:
        out.error(f"No targets defined in {config_path.name}")
        sys.exit(1)

    target_name = next(iter(targets))
    target_config = targets[target_name]
    if not _SAFE_TARGET_NAME.match(target_name):
        out.error(
            f"Target name {target_name!r} contains unsafe characters; "
            f"allowed: letters, digits, '.', '_', '-'."
        )
        sys.exit(1)

    return target_name, target_config


def send_bundle(
    out: OutputHandler,
    bundle_path: pathlib.Path,
    url: str,
    api_token: str,
    extra_data: dict[str, str],
) -> tuple[dict, bool]:
    """POST the bundle zip to the API. Returns (response_data, ok)."""
    out.info(f"Sending bundle to {url}")

    with open(bundle_path, "rb") as f:
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {api_token}"},
            files={"file": f},
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


def main() -> None:
    parser = argparse.ArgumentParser(description="Detections as Code — diff or apply detection rules")
    parser.add_argument("command", choices=["diff", "apply"], help="Operation to perform")
    parser.add_argument(
        "--deployments-file",
        default=os.environ.get("DEPLOYMENTS_FILE", "detections/deployments.yaml"),
        help="Path to deployments.yaml file (default: $DEPLOYMENTS_FILE or 'detections/deployments.yaml')",
    )
    parser.add_argument(
        "--api-token",
        default=os.environ.get("API_TOKEN"),
        help="API token (default: $API_TOKEN)",
    )
    parser.add_argument(
        "--github-repository",
        default=os.environ.get("GITHUB_REPOSITORY"),
        help="Repository name (default: $GITHUB_REPOSITORY)",
    )
    parser.add_argument(
        "--head-sha",
        default=os.environ.get("HEAD_SHA"),
        help="Head commit hash (default: $HEAD_SHA)",
    )
    parser.add_argument(
        "--github-repository-id",
        default=os.environ.get("GITHUB_REPOSITORY_ID"),
        help="ID of the GitHub repo (default: $GITHUB_REPOSITORY_ID)",
    )
    parser.add_argument(
        "--mgmt-uri",
        default=os.environ.get("MGMT_URI"),
        help="Management console URI (default: $MGMT_URI)",
    )
    args = parser.parse_args()

    if os.environ.get("GITHUB_ACTIONS", "").lower() == "true":
        out = GitHubActionsOutput(args.github_repository, args.head_sha)
    else:
        out = ConsoleOutput()

    required = {
        "API_TOKEN": args.api_token,
        "MGMT_URI": args.mgmt_uri,
        "GITHUB_REPOSITORY_ID": args.github_repository_id,
        "GITHUB_REPOSITORY": args.github_repository,
        "HEAD_SHA": args.head_sha,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        out.error(f"Missing required values: {', '.join(missing)} (set via CLI arguments or environment variables)")
        sys.exit(1)

    deployments_file = pathlib.Path(args.deployments_file)
    target_name, target_config = load_config(out, deployments_file)
    base_path = deployments_file.parent
    mgmt_uri = args.mgmt_uri
    out.group(
        f"Target: {target_name}",
        f"  mgmtUri:    {mgmt_uri}\n"
        f"  scopeLevel: {target_config.get('scopeLevel', 'N/A')}\n"
        f"  scopeId:    {target_config.get('scopeId', 'N/A')}",
    )

    bundle_name = f"detections-as-code-{target_name}"
    bundle_path = pathlib.Path(f"{bundle_name}.zip")
    shutil.make_archive(bundle_name, "zip", base_path)

    url = f"{mgmt_uri.rstrip('/')}{API_PATH}?mode={args.command}"
    extra_data: dict[str, str] = {
        "vcsRepoId": args.github_repository_id,
        "vcsRepoName": args.github_repository,
        "vcsCommitId": args.head_sha,
    }

    response_data, ok = send_bundle(out, bundle_path, url, args.api_token, extra_data)
    if not ok:
        out.report_errors(response_data, args.command, target_name)
        sys.exit(1)

    out.report_result(args.command, target_name, response_data)


if __name__ == "__main__":
    main()
