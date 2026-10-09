# src/sentinels/agents/manager.py
import asyncio
from typing import List
from agent_framework import create_harness_agent, tool

from sentinels.config import get_chat_client
from sentinels.prompts.manager_prompts import MANAGER_SYSTEM_PROMPT
from sentinels.agents.workers.code_auditor import create_code_auditor
from sentinels.agents.workers.iac_auditor import create_iac_auditor
from sentinels.agents.workers.dependency_auditor import create_dependency_auditor

def create_manager_agent():
    """
    Factory function to create the Manager (Harness) Agent.
    It delegates work to Worker Agents via function tools, with support
    for parallel multi-directory audits and SCA dependency scanning.
    """
    chat_client = get_chat_client()

    # 1. Instantiate the Worker Agents
    code_auditor_agent = create_code_auditor()
    iac_auditor_agent = create_iac_auditor()
    dependency_auditor_agent = create_dependency_auditor()

    # 2. Wrap each Worker Agent as a Function Tool so the Manager can call it
    @tool(
        description="Delegate application code auditing (Python, JS, Go, Rust) to the Code Auditor Agent. Pass the specific directory path to audit."
    )
    async def audit_code_tool(target_directory: str) -> str:
        """Invokes the Code Auditor Agent on a single directory."""
        result = await code_auditor_agent.run(f"Audit the following directory: {target_directory}")
        return result.text

    @tool(
        description="Delegate infrastructure-as-code auditing (Terraform, Bicep, CloudFormation) to the IaC Auditor Agent. Pass the specific directory path to audit."
    )
    async def audit_iac_tool(target_directory: str) -> str:
        """Invokes the IaC Auditor Agent on an infrastructure directory."""
        result = await iac_auditor_agent.run(f"Audit the following directory: {target_directory}")
        return result.text

    @tool(
        description="Delegate Software Composition Analysis (SCA) dependency auditing (requirements.txt, package.json, go.mod) to detect known CVEs and upgrade paths."
    )
    async def audit_dependencies_tool(target_directory: str = ".") -> str:
        """Invokes the Dependency Auditor Agent to check packages for known CVEs."""
        result = await dependency_auditor_agent.run(
            f"Perform an SCA dependency audit for known CVEs in: {target_directory}"
        )
        return result.text

    @tool(
        description="Concurrently audit multiple directories in parallel using an async worker pool. Provide a list of directory paths (e.g., ['src/api', 'src/auth', 'infra'])."
    )
    async def audit_batch_directories_tool(directories: List[str]) -> str:
        """Concurrently audits multiple directories in parallel via asyncio.gather."""
        if not directories:
            return "No directories specified."

        semaphore = asyncio.Semaphore(4)  # Limit concurrency to 4 simultaneous workers

        async def _audit_single_dir(target_dir: str):
            async with semaphore:
                is_infra = any(k in target_dir.lower() for k in ["infra", "terraform", "deploy", "bicep"])
                # Instantiate a dedicated worker agent per task to prevent stdio race conditions on parallel execution
                agent = create_iac_auditor() if is_infra else create_code_auditor()
                try:
                    res = await agent.run(f"Audit the following directory: {target_dir}")
                    return f"=== Audit Results for {target_dir} ===\n{res.text}"
                except Exception as e:
                    return f"=== Audit Error for {target_dir} ===\nFailed: {str(e)}"

        tasks = [_audit_single_dir(d) for d in directories]
        batch_results = await asyncio.gather(*tasks)
        return "\n\n".join(batch_results)

    # 3. Create the Manager Harness Agent
    manager_agent = create_harness_agent(
        client=chat_client,
        agent_instructions=MANAGER_SYSTEM_PROMPT,
        name="ManagerAgent",
        tools=[
            audit_code_tool,
            audit_iac_tool,
            audit_dependencies_tool,
            audit_batch_directories_tool
        ],
        disable_tool_auto_approval=True,
        disable_mode=True,
        disable_file_memory=True,
        disable_todo=True,
        disable_web_search=True,
    )

    return manager_agent