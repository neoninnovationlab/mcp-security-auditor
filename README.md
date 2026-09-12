# MCP Security & Vulnerability Auditor

[![Glama Server](https://glama.ai/mcp/servers/neoninnovationlab/mcp-security-auditor/badges/score.svg)](https://glama.ai/mcp/servers/neoninnovationlab/mcp-security-auditor)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A zero-execution static AST security scanner and vulnerability auditor for **Model Context Protocol (MCP)** servers.

Detect critical remote code execution (RCE), arbitrary file access, leaked API keys, unauthenticated transports, and tool poisoning before connecting any untrusted MCP server to your AI agents, Claude Desktop, or Cursor environments.

---

## 🌟 Tools Exposed to AI Agents

This server exposes two specialized security tools to connected MCP clients:

1. **`audit_mcp_repository`**
   - **Arguments:**
     - `repository_url` (string, required): Public Git URL of the MCP repository to audit.
     - `sub_directory` (string, optional): Subdirectory path if auditing a specific tool inside a monorepo.
   - **Action:** Clones the repository shallowly without executing hooks, performs AST syntax analysis, and returns a Trust Score (0–100), letter grade (A+ to F), and formatted markdown report.

2. **`audit_local_directory`**
   - **Arguments:**
     - `directory_path` (string, required): Absolute path to a local directory containing MCP server code.
   - **Action:** Audits local source code without executing it.

---

## 🛡️ Vulnerability Rule Set

| Rule ID | Severity | CWE | Threat Category |
| :--- | :--- | :--- | :--- |
| **MCP-SEC-001** | CRITICAL | **CWE-78** | **Command Injection**: Detects `subprocess.run(shell=True)`, `os.system()`, and dynamic string formatting in shell commands. |
| **MCP-SEC-002** | HIGH | **CWE-22** | **Path Traversal & ZipSlip**: Detects filesystem tools lacking root boundary checks (`Path.is_relative_to()`) and unvalidated archive extractions. |
| **MCP-SEC-003** | CRITICAL | **CWE-798** | **Credential & Secret Exposure**: Detects hardcoded OpenAI, Anthropic, GitHub, AWS, and Slack tokens, and blocks returning raw `os.environ`. |
| **MCP-SEC-004** | HIGH | **CWE-306** | **Unauthenticated Remote Transport**: Flags SSE / HTTP endpoints bound to `0.0.0.0` with no authentication middleware. |
| **MCP-SEC-005** | HIGH | **CWE-1384** | **Tool Poisoning**: Detects prompt injection directives and zero-width homoglyph obfuscation in tool docstrings. |

---

## 🚀 Quick Start & Installation

### With Claude Desktop
Add to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "mcp-security-auditor": {
      "command": "python3",
      "args": ["/path/to/mcp-security-auditor/server.py"]
    }
  }
}
```

### With Docker
```bash
docker build -t mcp-security-auditor .
docker run -i --rm mcp-security-auditor
```

---

## 📊 Empirical Benchmark (23 Public Servers)

We audited 23 prominent reference and community MCP servers:

| Category | Repositories Tested | Average Trust Score | Grade | Notes |
| :--- | :--- | :--- | :--- | :--- |
| **Anthropic Reference Servers** | `filesystem`, `git`, `fetch`, `sqlite`, `postgres`, `memory`, `time` | **100/100** | **A+** | Clean path containment, zero dynamic shell invocations. |
| **Reference SSE Server** | `everything` | **85/100** | **A** | Caught unauthenticated SSE transport in test handler. |
| **Community Servers** | `fastmcp` | **25/100** | **F** | Caught ZipSlip in telemetry extraction and unconstrained `read_file` tools. |

---

## 📄 License
MIT License. Maintained by [Neon Innovation Lab](https://github.com/neoninnovationlab).
