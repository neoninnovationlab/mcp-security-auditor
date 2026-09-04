import ast
import re
from typing import List
from .base import BaseRule
from ..models import Finding, Severity

class CommandInjectionRule(BaseRule):
    rule_id: str = "MCP-SEC-001"
    title: str = "Command Injection (Shell Execution)"
    severity: Severity = Severity.CRITICAL
    cwe_id: str = "CWE-78"

    def scan_python_ast(self, file_path: str, tree: ast.AST, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                func_name = ""
                if isinstance(node.func, ast.Name):
                    func_name = node.func.id
                elif isinstance(node.func, ast.Attribute):
                    func_name = node.func.attr
                    # Check for os.system or os.popen
                    if isinstance(node.func.value, ast.Name) and node.func.value.id == "os":
                        if func_name in ("system", "popen"):
                            line_no = node.lineno
                            snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                            findings.append(
                                Finding(
                                    rule_id=self.rule_id,
                                    title=f"Unsafe os.{func_name}() execution",
                                    severity=Severity.CRITICAL,
                                    cwe_id=self.cwe_id,
                                    file_path=file_path,
                                    line_number=line_no,
                                    snippet=snippet,
                                    description=f"Use of os.{func_name}() directly invokes a system shell, exposing the MCP tool to remote command injection.",
                                    remediation="Use subprocess.run(['binary', 'arg1'], shell=False) with parameterized arguments.",
                                    confidence="HIGH"
                                )
                            )

                # Check for subprocess calls with shell=True
                if func_name in ("run", "Popen", "call", "check_output", "check_call"):
                    is_shell = False
                    for kw in node.keywords:
                        if kw.arg == "shell":
                            if isinstance(kw.value, ast.Constant) and bool(kw.value.value) is True:
                                is_shell = True
                            elif not isinstance(kw.value, ast.Constant):
                                # Dynamic shell flag
                                is_shell = True

                    if is_shell:
                        line_no = node.lineno
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title=f"subprocess.{func_name}() with shell=True",
                                severity=Severity.CRITICAL,
                                cwe_id=self.cwe_id,
                                file_path=file_path,
                                line_number=line_no,
                                snippet=snippet,
                                description="Executing commands through the shell (shell=True) allows arguments with shell metacharacters (; | & ` $()) to execute arbitrary commands.",
                                remediation="Set shell=False and pass arguments as a list of strings: subprocess.run([cmd, arg1, arg2], shell=False).",
                                confidence="HIGH"
                            )
                        )

                # Check for dangerous builtins eval/exec
                if func_name in ("eval", "exec"):
                    line_no = node.lineno
                    snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Dangerous dynamic code execution via {func_name}()",
                            severity=Severity.HIGH,
                            cwe_id="CWE-95",
                            file_path=file_path,
                            line_number=line_no,
                            snippet=snippet,
                            description=f"Dynamic evaluation using {func_name}() can allow callers to execute arbitrary code if arguments are controlled by an LLM prompt.",
                            remediation="Avoid dynamic code evaluation. Use ast.literal_eval for parsing data structures or use structured parser libraries.",
                            confidence="HIGH"
                        )
                    )

        return findings

    def scan_text(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        if not (file_path.endswith(".ts") or file_path.endswith(".js") or file_path.endswith(".mjs") or file_path.endswith(".cjs")):
            return findings

        lines = content.splitlines()

        # Check for child_process exec/execSync with string templates or concatenation
        exec_pattern = re.compile(r'(?:exec|execSync)\s*\(\s*([`\'"].*?|\w+)')
        shell_true_pattern = re.compile(r'shell\s*:\s*true')

        for i, line in enumerate(lines, 1):
            if "exec(" in line or "execSync(" in line:
                if "`" in line or "+" in line or "${" in line:
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title="Unsafe child_process.exec() with interpolated command",
                            severity=Severity.CRITICAL,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=i,
                            snippet=line.strip(),
                            description="child_process.exec() passes strings directly to /bin/sh. Dynamic parameters can escape into arbitrary shell execution.",
                            remediation="Use child_process.execFile() or spawn() without a shell, passing arguments in an array.",
                            confidence="HIGH"
                        )
                    )
            elif shell_true_pattern.search(line):
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        title="child_process spawn() configured with shell: true",
                        severity=Severity.HIGH,
                        cwe_id=self.cwe_id,
                        file_path=file_path,
                        line_number=i,
                        snippet=line.strip(),
                        description="Spawning a process with shell: true invokes a system shell, exposing parameters to command injection.",
                        remediation="Remove shell: true and pass arguments as an explicit string array.",
                        confidence="HIGH"
                    )
                )

        return findings
