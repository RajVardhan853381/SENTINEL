# src/sentinels/agents/workers/iac_auditor.py
from agent_framework import Agent
from sentinels.agents.workers.base_worker import BaseWorkerAgent
from sentinels.prompts.worker_prompts import IAC_AUDITOR_PROMPT

def create_iac_auditor() -> Agent:
    """
    Factory function to create and configure the IaC Auditor Worker Agent.
    This agent specializes in infrastructure-as-code (Terraform, Bicep, CloudFormation).
    """
    return BaseWorkerAgent.create(
        prompt=IAC_AUDITOR_PROMPT,
        agent_name="IaCAuditorAgent"
    )
