# Cybersecurity Vulnerability Intelligence MCP

[![CI](https://github.com/EMRD95/cybersecurity-vuln-mcp/actions/workflows/ci.yml/badge.svg)](https://github.com/EMRD95/cybersecurity-vuln-mcp/actions/workflows/ci.yml)
[![Docker Publish](https://github.com/EMRD95/cybersecurity-vuln-mcp/actions/workflows/docker-publish.yml/badge.svg)](https://github.com/EMRD95/cybersecurity-vuln-mcp/actions/workflows/docker-publish.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

An enterprise-grade **Model Context Protocol (MCP)** server and Hermes skillset that detects, enriches, and reports cybersecurity vulnerabilities from natural language infrastructure descriptions. It aggregates data from NVD, CISA KEV, EPSS, MITRE ATT\&CK, and MITRE CWE into a unified intelligence pipeline.

![System Workflow](docs/images/workflow_diagram.png)

## Features

- **Enriched CVE Lookups** — One-call retrieval of CVSS, EPSS, KEV status, ATT\&CK techniques, and CWE mitigations.
- **Bulk Analysis** — Analyze entire software stacks or SBOMs in parallel.
- **CISA KEV Tracking** — Identify actively exploited vulnerabilities and upcoming remediation deadlines.
- **MITRE CWE Intelligence** — Query weakness taxonomies, detection methods, and mitigation strategies.
- **Vendor Risk Assessments** — Cross-reference vendor/product CVEs with known exploited catalogs.
- **Automated Reporting** — Generate JSON and HTML vulnerability reports via Hermes agent orchestration.
- **Docker-ready** — Multi-stage Dockerfile for reproducible MCP server deployments.

## Prerequisites

- [Docker Engine](https://docs.docker.com/engine/install/debian/) (Debian/Ubuntu instructions)
- [Hermes Agent](https://hermes-agent.nousresearch.com/docs/getting-started/installation)
- Node.js >= 18 (only if building the MCP server from source)

### Add your user to the Docker group

```bash
sudo usermod -aG docker $USER
newgrp docker
```

## Installation & Setup

### 1. Clone the repository

```bash
git clone https://github.com/EMRD95/cybersecurity-vuln-mcp.git
cd cybersecurity-vuln-mcp
```

### 2. Build the Docker image

The MCP server is containerized under `vuln-scanner-mcp/`.

```bash
docker build -t cybersecurity-vuln-mcp ./vuln-scanner-mcp
```

### 3. Install the Hermes skill

```bash
hermes skills install ./vuln-scanner
```

> The skill will be installed to `~/.hermes/skills/vuln-scanner/`. You can edit it later with:
> ```bash
> nano ~/.hermes/skills/vuln-scanner/SKILL.md
> ```

### 4. Configure the MCP server in Hermes

Add the following block to your Hermes `config.yaml` (usually at `~/.hermes/config.yaml`):

```yaml
mcp_servers:
  vuln_intel:
    command: "docker"
    args:
      - "run"
      - "-i"
      - "--rm"
      - "-e"
      - "NVD_API_KEY"
      - "cybersecurity-vuln-mcp"
    env:
      NVD_API_KEY: "${NVD_API_KEY}"
    timeout: 120
    connect_timeout: 60
```

After saving, reload MCP servers inside Hermes:

```bash
hermes
/reload-mcp
```

### 5. Configure API keys

Create or edit your Hermes environment file at `~/.hermes/.env` and add the required secrets:

```bash
# NVD API Key (optional but recommended)
# Get one free at: https://nvd.nist.gov/developers/request-an-api-key
NVD_API_KEY=your_nvd_api_key_here

# Add other provider keys here as needed (web search, sudo, etc.)
```

> **Security Note:** Never commit `.env` files to version control. The repository provides `vuln-scanner-mcp/.env.example` as a template.

## Usage

### Run the automated vulnerability mapper

The `cve_mapper.sh` script orchestrates the full workflow: it reads `infrastructure.txt`, launches the Hermes agent with the installed skill, runs MCP tools natively, and writes JSON/HTML reports.

```bash
./cve_mapper.sh
```

Reports are saved to `./generated_reports/`.

### Hermes Docker backend configuration (used by the script)

The orchestration script temporarily switches Hermes into Docker backend mode to sandbox file writes:

```bash
hermes config set terminal.backend docker
hermes config set terminal.docker_mount_cwd_to_workspace true
hermes config set terminal.docker_run_as_host_user true
```

To revert to normal local terminal execution afterward:

```bash
hermes config set terminal.backend local
hermes config set terminal.docker_mount_cwd_to_workspace false
hermes config set terminal.docker_run_as_host_user false
```

## Project Structure

```text
.
├── .github/                 # CI/CD workflows (GitHub Actions)
│   ├── workflows/
│   │   ├── ci.yml              # Lint, build, type-check, Docker smoke test
│   │   ├── docker-publish.yml # GHCR image publication on main/releases
│   │   └── branch-protection.yml # Direct-push guard
│   ├── PULL_REQUEST_TEMPLATE.md
│   └── ISSUE_TEMPLATE/
├── cve_mapper.sh            # Orchestration script (Hermes + Docker)
├── infrastructure.txt       # Sample target architecture description
├── vuln-scanner/            # Hermes skill
│   └── SKILL.md
├── vuln-scanner-mcp/        # MCP server source & Docker assets
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── package.json
│   ├── tsconfig.json
│   ├── .env.example
│   ├── .actor/
│   ├── src/
│   │   ├── main.ts          # StreamableHTTP / Apify Actor transport
│   │   ├── stdio.ts         # Stdio MCP transport (default Docker mode)
│   │   └── lib/             # NVD, KEV, EPSS, CWE, ATT&CK, cache clients
│   └── dist/              # Compiled output (generated via `npm run build`)
├── docs/
│   └── images/
│       └── workflow_diagram.png
├── CONTRIBUTING.md          # Branching strategy & contribution guidelines
├── CODEOWNERS             # Code review ownership
├── LICENSE
└── README.md
```

## CI/CD & Branch Strategy

This repository enforces an enterprise **GitFlow** model:

| Branch      | Purpose                                                            | Direct Push |
|-------------|---------------------------------------------------------------------|-------------|
| `main`      | Production-ready, stable artifacts; tagged releases               | Prohibited  |
| `development` | Integration branch for validated features and bugfixes            | Prohibited  |
| `feature/*` | Short-lived branches for individual work units                    | Allowed     |
| `hotfix/*`  | Emergency patches branched from `main`                            | Allowed     |

### Workflow Summary

1. Branch from `development` into `feature/your-feature`.
2. Commit and push your feature branch.
3. Open a **Pull Request** targeting `development`.
4. All PRs must pass:
   - TypeScript compilation (`npm run build`)
   - Type checking (`tsc --noEmit`)
   - Docker image smoke build
   - Shell script syntax validation
5. After approval, squash-merge into `development`.
6. Release merges from `development` to `main` trigger automated GHCR image publication.

## Security

- **No secrets in source:** API keys, tokens, and environment variables are excluded via `.gitignore`. Use `.env` files locally.
- **No native API scripting in agent workflows:** The skill enforces use of native MCP tools (`vuln_lookup_cve`, `vuln_search`, `cwe_get`) rather than external scripts.
- **Docker sandboxing:** `cve_mapper.sh` optionally isolates agent file writes inside a Docker volume mounted to `/output`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for commit conventions, branch naming, and quality gate requirements.

## License

This project is licensed under the MIT License. See [LICENSE](LICENSE) for details.
