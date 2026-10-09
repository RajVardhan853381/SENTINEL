# src/sentinels/agents/workers/base_worker.py
import sys
from pathlib import Path

from agent_framework import Agent
from agent_framework import MCPStdioTool
from sentinels.config import get_chat_client

# src/sentinels/mcp_server/server.py, resolved from this file's location so it
# works regardless of the process's current working directory.
_SERVER_SCRIPT = Path(__file__).resolve().parents[2] / "mcp_server" / "server.py"

class BaseWorkerAgent:
    """
    Base factory for creating specialized MAF Worker Agents.
    Handles MCP tool binding and Agent instantiation.
    """
    
    @staticmethod
    def create(prompt: str, agent_name: str) -> Agent:
        """
        Creates a configured MAF Agent connected to the local MCP server.
        """
        # 1. Get the configured Chat Client (Ollama, Azure, or OpenAI)
        chat_client = get_chat_client()
        
        # 2. Configure the MCP Tool
        # This tells MAF to launch our FastMCP server as a subprocess.
        # It automatically discovers the @mcp.tool() functions we wrote!
        mcp_tool = MCPStdioTool(
            name="SentinelRepoTools",
            command=sys.executable,
            args=[str(_SERVER_SCRIPT)]
        )
        
        # 3. Create the MAF Agent
        agent = Agent(
            client=chat_client,
            instructions=prompt,
            name=agent_name,
            tools=[mcp_tool] # Bind the MCP tools to the agent
        )
        
        return agent