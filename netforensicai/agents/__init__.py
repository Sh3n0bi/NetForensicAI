"""The investigation-team agents (see docs/design/agent-team.md).

Each agent is one role - a mission, a scoped subset of the read-only case
tools, and a step budget - run over the same grounded loop the chat assistant
uses. Every finding must cite a tool result or it is dropped, so no role can
invent a finding.
"""

from netforensicai.agents.base import AgentError, AgentFinding, Role, RoleResult, run_role

__all__ = ["AgentError", "AgentFinding", "Role", "RoleResult", "run_role"]
