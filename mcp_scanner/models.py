from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import List, Optional, Dict, Any

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

@dataclass
class Finding:
    rule_id: str
    title: str
    severity: Severity
    cwe_id: str
    file_path: str
    line_number: int
    snippet: str
    description: str
    remediation: str
    confidence: str = "HIGH"

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity.value
        return data

@dataclass
class ScanResult:
    target_path: str
    target_name: str
    total_files_scanned: int
    trust_score: int
    grade: str
    findings: List[Finding] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "target_path": self.target_path,
            "target_name": self.target_name,
            "total_files_scanned": self.total_files_scanned,
            "trust_score": self.trust_score,
            "grade": self.grade,
            "summary": {
                "critical": len([f for f in self.findings if f.severity == Severity.CRITICAL]),
                "high": len([f for f in self.findings if f.severity == Severity.HIGH]),
                "medium": len([f for f in self.findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in self.findings if f.severity == Severity.LOW]),
                "info": len([f for f in self.findings if f.severity == Severity.INFO]),
                "total_findings": len(self.findings),
            },
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }
