"""Restricted host runner for OpenCode v2 using a separately authorized ChatGPT plan."""

import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from evaluate.agents.base import AgentResult, RunContext
from evaluate.agents.opencode import OpenCodeAgent

MODEL = "gpt-6.2-sol"
POLICY = {
    "$schema": "https://opencode.ai/config.json",
    "permissions": [
        {"action": action, "resource": "*", "effect": "deny"}
        for action in (
            "external_directory",
            "shell",
            "edit",
            "execute",
            "subagent",
            "websearch",
            "webfetch",
            "question",
        )
    ]
    + [{"action": "shell", "resource": "shasum -a 256 *", "effect": "allow"}],
}


def _ignore_links(directory: str, names: list[str]) -> list[str]:
    return [name for name in names if name == ".git" or (Path(directory) / name).is_symlink()]


def _runtime() -> tuple[Path, dict[str, str]]:
    value = os.environ.get("VEX_OPENCODE_HOME")
    if not value:
        raise RuntimeError("Set VEX_OPENCODE_HOME to the private OpenCode v2 installation")
    root = Path(value).resolve()
    binary = root / "node_modules/.bin/opencode"
    database = root / "data/opencode/opencode.db"
    if not binary.is_file():
        raise RuntimeError(f"OpenCode v2 CLI not found: {binary}")
    if not database.is_file():
        raise RuntimeError("OpenCode authentication is missing; sign in before running cases")
    policy_file = root / "config/opencode/opencode.json"
    if policy_file.exists():
        if json.loads(policy_file.read_text(encoding="utf-8")) != POLICY:
            raise RuntimeError(f"Unexpected OpenCode policy; refusing host run: {policy_file}")
    else:
        policy_file.parent.mkdir(parents=True, exist_ok=True)
        policy_file.write_text(json.dumps(POLICY, indent=2) + "\n", encoding="utf-8")
    env = os.environ.copy()
    env.update(
        XDG_DATA_HOME=str(root / "data"),
        XDG_CONFIG_HOME=str(root / "config"),
        XDG_CACHE_HOME=str(root / "cache"),
    )
    return binary, env


def _failure_detail(stdout: str, stderr: str) -> str:
    if stderr.strip():
        return stderr.strip()[-2000:]
    for line in reversed(stdout.splitlines()):
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "error":
            error = event.get("error", {})
            return f"{error.get('type', 'unknown')}: {error.get('message', 'no detail')}"[:2000]
    return "process exited without an error message"


class OpenCodeHostAgent(OpenCodeAgent):
    """Run OpenCode in a disposable source copy with dangerous tools denied."""

    def __init__(self, model: str):
        if model != MODEL:
            raise ValueError(f"Host ChatGPT runner supports only {MODEL!r}")
        self.model_name = f"openai/{model}"

    def run(self, prompt: str, ctx: RunContext) -> AgentResult:
        binary, env = _runtime()
        with tempfile.TemporaryDirectory(prefix="vex-opencode-host-") as tmp:
            source = Path(tmp) / "source"
            shutil.copytree(ctx.cwd, source, ignore=_ignore_links)
            env["PWD"] = str(source)
            try:
                result = subprocess.run(
                    [
                        str(binary),
                        "run",
                        "--standalone",
                        "--auto",
                        "--agent",
                        "explore",
                        "--model",
                        self.model_name,
                        "--format",
                        "json",
                        "--archived",
                        prompt,
                    ],
                    cwd=source,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=ctx.timeout,
                )
            except subprocess.TimeoutExpired as exc:
                raise RuntimeError(f"OpenCode host run timed out after {ctx.timeout}s") from exc
            if ctx.artifacts_dir:
                ctx.artifacts_dir.mkdir(parents=True, exist_ok=True)
                (ctx.artifacts_dir / "host-stdout.jsonl").write_text(
                    result.stdout, encoding="utf-8"
                )
                (ctx.artifacts_dir / "host-stderr.log").write_text(result.stderr, encoding="utf-8")
            if result.returncode:
                raise RuntimeError(
                    f"OpenCode host run failed: {_failure_detail(result.stdout, result.stderr)}"
                )
            return AgentResult(raw_output=result.stdout)

    def result_filename(self) -> str:
        return "result.jsonl"
