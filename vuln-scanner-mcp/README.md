# Cybersecurity Vulnerability Intelligence MCP Server

Unified vulnerability intelligence from 5 government/open data sources in a single MCP server. Get enriched CVE lookups with CVSS scores, active exploitation status, exploitation probability, ATT&CK techniques, and MITRE CWE weakness classifications — all in one call.

## Data Sources

| Source | What It Provides | Update Frequency |
|--------|-----------------|-----------------|
| **NIST NVD 2.0** | CVE details, CVSS scores, descriptions, references, CWE classifications | Continuous |
| **CISA KEV** | Actively exploited vulnerabilities catalog, remediation deadlines | Daily |
| **FIRST.org EPSS** | Exploitation probability scores (0-1) predicting likelihood of exploitation in next 30 days | Daily |
| **MITRE ATT&CK** | Adversary techniques mapped to CVEs | Quarterly |
| **MITRE CWE** | Software/hardware weakness taxonomy, relationships, consequences, mitigations, detection methods, CAPEC attack patterns | Quarterly |

## Quick Start

### npm (Recommended for Development)

```bash
cd /home/kali/Desktop/TP3Pentest/vuln-mcp
npm install
npm run build
npm run stdio
```

### Docker

```bash
# Build image
docker build -t cybersecurity-vuln-mcp .

# Run
# IMPORTANT: -i (interactive) is required for stdio MCP
docker run -i --rm cybersecurity-vuln-mcp
```

### Docker Compose

```bash
docker compose up --build
```

The compose file uses `stdin_open: true` and `tty: true` so stdio works correctly.

## Nous Hermes Agent Integration

Add to `~/.hermes/config.yaml`:

### Local Node.js

```yaml
mcp_servers:
  vuln_intel:
    command: "node"
    args: ["/home/kali/Desktop/TP3Pentest/vuln-mcp/dist/stdio.js"]
    timeout: 120
    connect_timeout: 60
```

### Docker

```yaml
mcp_servers:
  vuln_intel:
    command: "docker"
    args: ["run", "-i", "--rm", "cybersecurity-vuln-mcp"]
    timeout: 120
    connect_timeout: 60
```

After saving config, run `/reload-mcp` in your Hermes session or restart the agent.

## Vulnerability Tools

### `vuln_lookup_cve` — Enriched CVE Lookup (Recommended Start)

Look up any CVE and get intelligence from all sources in a single call.

**Parameters:**
- `cveId` (required): CVE identifier (e.g., `CVE-2021-44228`)
- `enrichCwe` (optional): If `true`, fetch full CWE details for weakness references found in the CVE — description, consequences, mitigations, detection methods, CAPEC patterns (default: `false`)

**Example enriched result:**
- Log4Shell (CVE-2021-44228): CVSS 10.0, confirmed in CISA KEV, EPSS 0.97 (97th percentile), mapped to ATT&CK T1190, with CWE-917 (Expression Language Injection) decomposition including all mitigations and detection methods.

---

The rest of the vulnerability tools remain as before:

- `vuln_search` — Search CVEs by keyword, severity, date range
- `vuln_kev_latest` — Recently added CISA KEV entries
- `vuln_kev_due_soon` — Upcoming remediation deadlines
- `vuln_epss_top` — Highest EPSS exploitation probability
- `vuln_trending` — Newly published critical/high CVEs
- `vuln_by_vendor` — Vendor vulnerability assessment with KEV cross-reference

## CWE Tools (MITRE REST API)

### `cwe_version` — Catalog Version Info

Get CWE content release version, date, and counts (weaknesses, categories, views).

### `cwe_get` — Get CWE Details

Full details of one or more CWEs by numeric ID. Supports bulk via comma-separated values.

**Parameters:**
- `ids` (required): Comma-separated IDs without "CWE-" prefix (e.g., `'79,89,22'`)
- `type` (optional): `auto` (default), `weakness`, `category`, `view`

**Returns for weaknesses:** Name, abstraction, status, description, extended description, likelihood of exploit, related weaknesses, common consequences, detection methods, potential mitigations, demonstrative examples, related CAPEC attack patterns, references, taxonomy mappings.

### `cwe_parents` — Get Parent Hierarchy

Get direct parent entities of a CWE in the hierarchy. E.g., CWE-79 parents include CWE-1003 (Weaknesses in Software Development).

### `cwe_children` — Get Child Hierarchy

Get direct child entities of a CWE. E.g., children of CWE-20 (Improper Input Validation) include many specific weakness variants.

### `cwe_ancestors` — Full Ancestor Tree

Recursively get all ancestors up to root. Option to filter by view (e.g., view `1000` for Research Concepts).

### `cwe_descendants` — Full Descendant Tree

Recursively get all descendants down to leaf nodes. E.g., all weakness variants under CWE-20. Option to filter by view.

### `cwe_list_all` — List Full Catalog

List all weaknesses, categories, or views from the complete catalog. Large response — use sparingly.

### `cwe_search_name` — Search by Name/Keyword

Find CWE IDs by searching names and descriptions. Case-insensitive substring match. Good for finding CWEs when you only know the concept.

**Example:** Search keyword `"sql injection"` returns CWE-89, CWE-564, and related entries.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `NVD_API_KEY` | Optional NVD API key for increased rate limits (50 req/30s vs 5 req/30s without) |

## Attribution

- This product uses data from the NVD API but is not endorsed or certified by the NVD.
- EPSS data provided by FIRST.org (https://www.first.org/epss/).
- ATT&CK is a registered trademark of The MITRE Corporation. Licensed under Apache 2.0.
- CISA Known Exploited Vulnerabilities Catalog — US Government public domain.
- CWE is a community-developed list of common software and hardware weakness types. © The MITRE Corporation.
