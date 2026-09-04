import ast
import re
from typing import List
from .base import BaseRule
from ..models import Finding, Severity

class TransportAuthRule(BaseRule):
    rule_id: str = "MCP-SEC-004"
    title: str = "Unauthenticated Remote Transport (SSE / HTTP)"
    severity: Severity = Severity.HIGH
    cwe_id: str = "CWE-306"

    def scan_python_ast(self, file_path: str, tree: ast.AST, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        # Check for fastmcp or uvicorn run binding to 0.0.0.0
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = ""
                if isinstance(node.func, ast.Attribute):
                    call_name = node.func.attr
                elif isinstance(node.func, ast.Name):
                    call_name = node.func.id

                # Check if running SSE transport
                is_sse = False
                is_public_host = False

                for kw in node.keywords:
                    if kw.arg == "transport":
                        if isinstance(kw.value, ast.Constant) and kw.value.value == "sse":
                            is_sse = True
                    if kw.arg == "host":
                        if isinstance(kw.value, ast.Constant) and kw.value.value in ("0.0.0.0", "::"):
                            is_public_host = True

                # FastMCP run with transport="sse" and host="0.0.0.0"
                if is_sse and is_public_host:
                    # Check if there is any auth token check in the code
                    has_auth = any(token in content.lower() for token in ("bearer", "authorization", "api_key", "auth_token", "authenticate"))
                    if not has_auth:
                        line_no = node.lineno
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title="Public Unauthenticated SSE Transport (0.0.0.0)",
                                severity=Severity.CRITICAL,
                                cwe_id=self.cwe_id,
                                file_path=file_path,
                                line_number=line_no,
                                snippet=snippet,
                                description="The MCP server binds an SSE transport to 0.0.0.0 with no detected authentication middleware. Any client on the network or internet can execute server tools without credentials.",
                                remediation="Enforce Bearer token or API key authentication on the SSE endpoint, or bind exclusively to 127.0.0.1 for local usage.",
                                confidence="HIGH"
                            )
                        )

        return findings

    def scan_text(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        if not (file_path.endswith(".ts") or file_path.endswith(".js")):
            return findings

        lines = content.splitlines()
        # Look for SSEServerTransport
        if "SSEServerTransport" in content:
            has_auth_middleware = any(term in content.lower() for term in ("req.headers.authorization", "bearer", "api_key", "jwt", "authenticate"))
            if not has_auth_middleware:
                for i, line in enumerate(lines, 1):
                    if "SSEServerTransport" in line:
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title="Unauthenticated SSEServerTransport Exposed",
                                severity=Severity.HIGH,
                                cwe_id=self.cwe_id,
                                file_path=file_path,
                                line_number=i,
                                snippet=line.strip(),
                                description="SSEServerTransport is instantiated without explicit authentication middleware verifying incoming requests.",
                                remediation="Add an authentication handler before establishing the SSE connection (e.g., verify Bearer token from authorization header).",
                                confidence="MEDIUM"
                            )
                        )
                        break

        return findings
