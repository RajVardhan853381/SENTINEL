# src/sentinels/agents/workers/dependency_auditor.py
from agent_framework import Agent
from sentinels.agents.workers.base_worker import BaseWorkerAgent
from sentinels.prompts.worker_prompts import DEPENDENCY_AUDITOR_PROMPT

def create_dependency_auditor() -> Agent:
    """
    Factory function to create the Software Composition Analysis (SCA) Worker Agent.
    Specializes in scanning third-party dependencies for known CVEs and generating
    upgrade patches.
    """
    return BaseWorkerAgent.create(
        prompt=DEPENDENCY_AUDITOR_PROMPT,
        agent_name="DependencyAuditorAgent"
    )
