import os
import sys
import json
import subprocess
import shutil
from pathlib import Path
from typing import List, Dict, Any

from mcp_scanner.scanner import MCPScanner, generate_markdown_report
from mcp_scanner.models import ScanResult, Severity

BENCHMARK_DIR = Path("scratch/benchmarks")

REPOSITORIES = [
    {
        "name": "mcp-reference-servers",
        "url": "https://github.com/modelcontextprotocol/servers.git",
        "subdirs": [
            "src/everything",
            "src/fetch",
            "src/filesystem",
            "src/git",
            "src/memory",
            "src/sequentialthinking",
            "src/time",
        ]
    },
    {
        "name": "mcp-archived-servers",
        "url": "https://github.com/modelcontextprotocol/servers-archived.git",
        "subdirs": [
            "src/sqlite",
            "src/postgres",
            "src/slack",
            "src/puppeteer",
            "src/brave-search",
            "src/gdrive",
            "src/github",
            "src/gitlab",
            "src/google-maps",
            "src/redis",
            "src/sentry",
            "src/everart",
            "src/aws-kb-retrieval-server",
        ]
    },
    {
        "name": "fastmcp",
        "url": "https://github.com/jlowin/fastmcp.git",
        "subdirs": None
    },
    {
        "name": "slack-mcp-server",
        "url": "https://github.com/zencoderai/slack-mcp-server.git",
        "subdirs": None
    },
    {
        "name": "brave-search-mcp",
        "url": "https://github.com/brave/brave-search-mcp-server.git",
        "subdirs": None
    },
    {
        "name": "docker-mcp",
        "url": "https://github.com/k-doering-ch/mcp-server-docker.git",
        "subdirs": None
    },
    {
        "name": "mcp-shell",
        "url": "https://github.com/michaellatman/mcp-shell.git",
        "subdirs": None
    }
]

def clone_repo(url: str, dest: Path) -> bool:
    if dest.exists():
        print(f"[*] Destination {dest} already exists, skipping clone.")
        return True
    print(f"[*] Shallow cloning {url} -> {dest}...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dest)],
            check=True,
            capture_output=True,
            text=True
        )
        return True
    except subprocess.CalledProcessError as e:
        print(f"[-] Failed to clone {url}: {e.stderr}", file=sys.stderr)
        return False

def run_benchmark():
    BENCHMARK_DIR.mkdir(parents=True, exist_ok=True)
    scanner = MCPScanner()
    all_results: List[ScanResult] = []

    # Clone repos
    for repo_info in REPOSITORIES:
        repo_dest = BENCHMARK_DIR / repo_info["name"]
        success = clone_repo(repo_info["url"], repo_dest)
        if not success:
            continue

        if repo_info.get("subdirs"):
            for sub in repo_info["subdirs"]:
                target_dir = repo_dest / sub
                if target_dir.exists():
                    server_name = f"{repo_info['name']}:{Path(sub).name}"
                    print(f"[*] Scanning {server_name}...")
                    result = scanner.scan_directory(target_dir)
                    result.target_name = server_name
                    all_results.append(result)
                else:
                    print(f"[-] Subdir {target_dir} not found, skipping.")
        else:
            print(f"[*] Scanning {repo_info['name']}...")
            result = scanner.scan_directory(repo_dest)
            all_results.append(result)

    # Compile Benchmark Report
    print(f"\n[+] Benchmark completed. Scanned {len(all_results)} distinct MCP servers.")

    md = []
    md.append("# State of MCP Security: Empirical Benchmark Report (September 2026)")
    md.append(f"**Total MCP Servers Audited:** `{len(all_results)}`\n")
    md.append("This empirical security audit evaluated popular reference and community Model Context Protocol (MCP) servers using pure static AST and pattern analysis (zero remote execution risk).\n")

    md.append("## Executive Benchmark Table\n")
    md.append("| # | Server Target | Files Scanned | Trust Score | Grade | Critical | High | Med | Low | Total Flaws |")
    md.append("| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |")

    total_crit = 0
    total_high = 0
    total_med = 0
    total_low = 0

    for idx, r in enumerate(all_results, 1):
        crit = len([f for f in r.findings if f.severity == Severity.CRITICAL])
        high = len([f for f in r.findings if f.severity == Severity.HIGH])
        med = len([f for f in r.findings if f.severity == Severity.MEDIUM])
        low = len([f for f in r.findings if f.severity == Severity.LOW])
        total_flaws = len(r.findings)

        total_crit += crit
        total_high += high
        total_med += med
        total_low += low

        md.append(f"| {idx} | **`{r.target_name}`** | {r.total_files_scanned} | `{r.trust_score}/100` | **`{r.grade}`** | {crit} | {high} | {med} | {low} | {total_flaws} |")

    md.append("\n## Macro Vulnerability Metrics\n")
    md.append(f"- **Total Vulnerability Findings Across Fleet:** {total_crit + total_high + total_med + total_low}")
    md.append(f"  - **Critical Severity (CWE-78 Command Injection, CWE-798 Secrets):** {total_crit}")
    md.append(f"  - **High Severity (CWE-22 Path Traversal, CWE-306 Unauthenticated Transport):** {total_high}")
    md.append(f"  - **Medium Severity:** {total_med}")
    md.append(f"  - **Low Severity:** {total_low}\n")

    md.append("## Detailed Server Breakdowns\n")
    for r in all_results:
        if r.findings:
            md.append(f"### `{r.target_name}` (Score: {r.trust_score}/100, Grade: {r.grade})\n")
            for f in r.findings:
                md.append(f"- **[{f.severity.value}]** `{f.cwe_id}`: {f.title} (`{f.file_path}:{f.line_number}`)")
                md.append(f"  - *Remediation*: {f.remediation}")
            md.append("")

    report_content = "\n".join(md)
    output_path = BENCHMARK_DIR / "mcp_security_benchmark_report.md"
    output_path.write_text(report_content, encoding="utf-8")
    print(f"[+] Full benchmark report saved to: {output_path}")

    # Also save raw JSON
    json_path = BENCHMARK_DIR / "mcp_security_benchmark_results.json"
    json_path.write_text(json.dumps([r.to_dict() for r in all_results], indent=2), encoding="utf-8")
    print(f"[+] Raw JSON results saved to: {json_path}")

if __name__ == "__main__":
    run_benchmark()
