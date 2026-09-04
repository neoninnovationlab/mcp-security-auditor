import os
import sys
import shutil
import tempfile
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional

from mcp.server.mcpserver import MCPServer
from mcp_scanner.scanner import MCPScanner, generate_markdown_report

server = MCPServer(
    name="mcp-security-auditor",
    title="MCP Security & Vulnerability Auditor",
    version="1.0.0",
    description="Zero-execution static AST security scanner for Model Context Protocol servers.",
)

scanner = MCPScanner()

@server.tool(
    name="audit_mcp_repository",
    description="Performs a static AST security audit on a public MCP Git repository without executing untrusted code. Checks for Command Injection (CWE-78), Path Traversal (CWE-22), Hardcoded Secrets (CWE-798), and Unauthenticated Transports (CWE-306). Returns a Trust Score (0-100), letter grade, and findings."
)
def audit_mcp_repository(repository_url: str, sub_directory: str = "") -> Dict[str, Any]:
    temp_dir = tempfile.mkdtemp(prefix="mcp_audit_")
    try:
        # Clone shallowly without executing git hooks
        res = subprocess.run(
            ["git", "clone", "--depth", "1", repository_url, temp_dir],
            capture_output=True,
            text=True,
            timeout=120
        )
        if res.returncode != 0:
            return {
                "status": "error",
                "message": f"Failed to clone repository: {res.stderr}"
            }

        target_path = Path(temp_dir)
        if sub_directory:
            target_path = target_path / sub_directory
            if not target_path.exists():
                return {
                    "status": "error",
                    "message": f"Subdirectory '{sub_directory}' not found in repository."
                }

        scan_result = scanner.scan_directory(target_path)
        scan_result.target_name = f"{Path(repository_url).stem}" + (f":{sub_directory}" if sub_directory else "")
        markdown_report = generate_markdown_report(scan_result)

        data = scan_result.to_dict()
        data["markdown_report"] = markdown_report
        data["status"] = "success"
        return data
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)

@server.tool(
    name="audit_local_directory",
    description="Audits a local directory containing MCP server source code for security vulnerabilities using static AST analysis."
)
def audit_local_directory(directory_path: str) -> Dict[str, Any]:
    target = Path(directory_path)
    if not target.exists():
        return {
            "status": "error",
            "message": f"Directory path '{directory_path}' does not exist."
        }

    try:
        scan_result = scanner.scan_directory(target)
        markdown_report = generate_markdown_report(scan_result)
        data = scan_result.to_dict()
        data["markdown_report"] = markdown_report
        data["status"] = "success"
        return data
    except Exception as e:
        return {
            "status": "error",
            "message": str(e)
        }

if __name__ == "__main__":
    # Runs the standard stdio transport for MCP clients (Claude Desktop, Cursor, Glama)
    server.run()
