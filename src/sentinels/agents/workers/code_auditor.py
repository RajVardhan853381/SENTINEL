# src/sentinels/agents/workers/code_auditor.py
from agent_framework import Agent
from sentinels.agents.workers.base_worker import BaseWorkerAgent
from sentinels.prompts.worker_prompts import CODE_AUDITOR_PROMPT

def create_code_auditor() -> Agent:
    """
    Factory function to create and configure the Code Auditor Worker Agent.
    This agent specializes in application logic (Python, JS, Go, etc.).
    """
    return BaseWorkerAgent.create(
        prompt=CODE_AUDITOR_PROMPT,
        agent_name="CodeAuditorAgent"
    )