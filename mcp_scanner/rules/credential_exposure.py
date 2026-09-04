import ast
import re
from typing import List
from .base import BaseRule
from ..models import Finding, Severity

SECRET_PATTERNS = [
    (re.compile(r'sk-[a-zA-Z0-9]{32,}'), "OpenAI Legacy API Key", Severity.CRITICAL),
    (re.compile(r'sk-proj-[a-zA-Z0-9_\-]{40,}'), "OpenAI Project API Key", Severity.CRITICAL),
    (re.compile(r'sk-ant-api03-[a-zA-Z0-9_\-]{80,}'), "Anthropic API Key", Severity.CRITICAL),
    (re.compile(r'ghp_[a-zA-Z0-9]{36}'), "GitHub Personal Access Token", Severity.CRITICAL),
    (re.compile(r'github_pat_[a-zA-Z0-9_]{82}'), "GitHub Fine-Grained Personal Access Token", Severity.CRITICAL),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key ID", Severity.HIGH),
    (re.compile(r'xox[baprs]-[0-9a-zA-Z\-]{24,}'), "Slack Token", Severity.HIGH),
    (re.compile(r'-----BEGIN (?:RSA|OPENSSH|EC|PRIVATE) KEY-----'), "Private Key Header", Severity.CRITICAL),
]

class CredentialExposureRule(BaseRule):
    rule_id: str = "MCP-SEC-003"
    title: str = "Credential & Secret Exposure"
    severity: Severity = Severity.CRITICAL
    cwe_id: str = "CWE-798"

    def scan_python_ast(self, file_path: str, tree: ast.AST, content: str) -> List[Finding]:
        findings = []
        lines = content.splitlines()

        # Check for passing raw os.environ in MCP tool return
        for node in ast.walk(tree):
            if isinstance(node, ast.Return):
                if isinstance(node.value, ast.Attribute):
                    if isinstance(node.value.value, ast.Name) and node.value.value.id == "os" and node.value.attr == "environ":
                        line_no = node.lineno
                        snippet = lines[line_no - 1].strip() if line_no <= len(lines) else ""
                        findings.append(
                            Finding(
                                rule_id=self.rule_id,
                                title="Returning Full os.environ in MCP Tool",
                                severity=Severity.CRITICAL,
                                cwe_id="CWE-200",
                                file_path=file_path,
                                line_number=line_no,
                                snippet=snippet,
                                description="Returning os.environ directly from a tool exposes all server environment variables and secrets to the connected LLM / user.",
                                remediation="Only return explicitly sanitized, safe configuration values; never return raw environment maps.",
                                confidence="HIGH"
                            )
                        )

        return findings

    def scan_text(self, file_path: str, content: str) -> List[Finding]:
        findings = []
        # Skip lockfiles and compiled files
        if any(skip in file_path for skip in ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "poetry.lock")):
            return findings

        lines = content.splitlines()
        for i, line in enumerate(lines, 1):
            # Ignore comments stating examples or placeholders
            lower = line.lower()
            if "your_api_key" in lower or "placeholder" in lower or "example" in lower or "xxx" in lower:
                continue

            for pattern, name, severity in SECRET_PATTERNS:
                match = pattern.search(line)
                if match:
                    # Redact the secret in the finding
                    raw_val = match.group(0)
                    redacted = raw_val[:6] + "..." + raw_val[-4:] if len(raw_val) > 10 else "[REDACTED]"
                    clean_snippet = line.replace(raw_val, redacted).strip()

                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            title=f"Hardcoded {name} Detected",
                            severity=severity,
                            cwe_id=self.cwe_id,
                            file_path=file_path,
                            line_number=i,
                            snippet=clean_snippet,
                            description=f"A hardcoded credential ({name}) was found in the source code. Anyone with access to the repo or container can extract this token.",
                            remediation="Extract credentials to environment variables or secret vaults and read them at runtime.",
                            confidence="HIGH"
                        )
                    )

        return findings
