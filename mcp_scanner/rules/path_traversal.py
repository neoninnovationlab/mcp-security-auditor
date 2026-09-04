import ast
import re
from typing import List
from .base import BaseRule
from ..models import Finding, Severity

class PathTraversalRule(BaseRule):
    rule_id: str = "MCP-SEC-002"
    title: str = "Arbitrary File Access & Path Traversal"
    severity: Severity = Severity.HIGH
    cwe_id: str = "CWE-22"

    def scan_python_ast(self, file_path: str, tree: ast.AST, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef) or isinstance(node, ast.AsyncFunctionDef):
                # Check if this function is an MCP tool
                is_tool = False
                for dec in node.decorator_list:
                    dec_name = ""
                    if isinstance(dec, ast.Name):
                        dec_name = dec.id
                    elif isinstance(dec, ast.Attribute):
                        dec_name = dec.attr
                    elif isinstance(dec, ast.Call):
                        if isinstance(dec.func, ast.Name):
                            dec_name = dec.func.id
                        elif isinstance(dec.func, ast.Attribute):
                            dec_name = dec.func.attr
                    if "tool" in dec_name.lower():
                        is_tool = True

                # If it's a tool, look for file operations
                has_containment_check = False
                file_calls = []

                for child in ast.walk(node):
                    # Check for containment patterns
                    if isinstance(child, ast.Call):
                        call_name = ""
                        if isinstance(child.func, ast.Attribute):
                            call_name = child.func.attr
                        elif isinstance(child.func, ast.Name):
                            call_name = child.func.id

                        if call_name in ("commonpath", "is_relative_to", "startswith", "resolve"):
                            has_containment_check = True

                        if call_name in ("open", "read_text", "write_text", "rmtree", "unlink", "remove"):
                            file_calls.append((child.lineno, call_name))

                        # Unsafe archive extraction
                        if call_name in ("extractall", "extract"):
                            has_filter = False
                            for kw in child.keywords:
                                if kw.arg == "filter":
                                    has_filter = True
                            if not has_filter:
                                line_no = child.lineno
                                snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                                findings.append(
                                    Finding(
                                        rule_id=self.rule_id,
                                        title="Unsafe Archive Extraction (ZipSlip/TarSlip)",
                                        severity=Severity.HIGH,
                                        cwe_id=self.cwe_id,
                                        file_path=file_path,
                                        line_number=line_no,
                                        snippet=snippet,
                                        description="Archive extraction without path filter or validation allows archive members to write outside the destination directory.",
                                        remediation="Use filter='data' in Python 3.12+ or validate every member filename before extracting.",
                                        confidence="HIGH"
                                    )
                                )

                if is_tool and file_calls and not has_containment_check:
                    for line_no, call_name in file_calls:
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"MCP Tool '{node.name}' performs file operation without root path boundary check",
                                severity=Severity.HIGH,
                                cwe_id=self.cwe_id,
                                file_path=file_path,
                                line_number=line_no,
                                snippet=snippet,
                                description=f"Tool '{node.name}' calls {call_name}() but no boundary validation (such as Path.resolve() + is_relative_to() or os.path.commonpath()) was detected. Attackers can pass '../../etc/passwd' to escape intended boundaries.",
                                remediation="Resolve target path and verify: Path(target).resolve().is_relative_to(allowed_root).",
                                confidence="MEDIUM"
                            )
                        )

        return findings

    def scan_text(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        if not (file_path.endswith(".ts") or file_path.endswith(".js")):
            return findings

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            if "fs.readFile" in line or "fs.readFileSync" in line or "fs.writeFile" in line:
                if "path.join" in line and not any(k in content for k in ("startsWith", "relative", "normalize", "realpath")):
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title="Unvalidated File Operation via fs",
                            severity=Severity.HIGH,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=i,
                            snippet=line.strip(),
                            description="File operation with path.join without boundary checking allows directory traversal using '../'.",
                            remediation="Ensure resolved path is verified with: path.resolve(userPath).startsWith(allowedDirectory).",
                            confidence="MEDIUM"
                        )
                    )
        return findings
