# src/sentinels/mcp_server/server.py
from mcp.server.fastmcp import FastMCP

# Import the deterministic tool functions we wrote earlier
from sentinels.mcp_server.tools.repo import clone_repo, list_files, read_file
from sentinels.mcp_server.tools.scanner import run_semgrep, run_secret_scan
from sentinels.mcp_server.tools.dependency_scanner import run_dependency_scan

# Initialize a single, unified FastMCP server instance
mcp = FastMCP("SentinelSecurityTools")

# Register the tools with the server.
# FastMCP will automatically expose these to the MAF Agent as callable tools.
mcp.add_tool(clone_repo)
mcp.add_tool(list_files)
mcp.add_tool(read_file)
mcp.add_tool(run_semgrep)
mcp.add_tool(run_secret_scan)
mcp.add_tool(run_dependency_scan)

if __name__ == "__main__":
    # Run the server using the stdio transport.
    # This allows the MAF MCPStdioTool to communicate with it via standard input/output.
    mcp.run(transport="stdio")