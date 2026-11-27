from collections.abc import Callable

from evaluate.agents.base import Agent, AgentResult, ParsedResult, RunContext, RunStats
from evaluate.agents.claude import ClaudeAgent
from evaluate.agents.codex import CodexAgent
from evaluate.agents.opencode import OpenCodeAgent
from evaluate.agents.opencode_host import OpenCodeHostAgent

# Each entry is a factory: ``(model) -> Agent``.
AGENTS: dict[str, Callable[..., Agent]] = {
    "codex": CodexAgent,
    "claude": ClaudeAgent,
    "opencode": OpenCodeAgent,
    "opencode_host": OpenCodeHostAgent,
}

__all__ = ["AGENTS", "Agent", "AgentResult", "ParsedResult", "RunContext", "RunStats"]
