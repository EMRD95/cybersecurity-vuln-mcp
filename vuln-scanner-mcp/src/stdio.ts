import "dotenv/config";

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

import { getCveById, getCvesByIdBulk, searchCves, getTrendingCves, getCvesByVendor, type NvdCveItem } from "./lib/nvd.js";
import { lookupCve, getLatestKevEntries, getDueSoonEntries, getKevByVendor, type KevEntry } from "./lib/kev.js";
import { getEpssByCve, getTopEpss, type EpssScore } from "./lib/epss.js";
import { getAttackTechniques } from "./lib/attack-map.js";
import {
  getCweVersion,
  getCweWeaknesses,
  getCweCategories,
  getCweViews,
  getCweParents,
  getCweChildren,
  getCweAncestors,
  getCweDescendants,
  resolveCweWeaknesses,
  getAllWeaknesses,
  getAllCategories,
  getAllViews,
  countTreeNodes,
  trimTreeByDepth,
  type CweWeakness,
  type CweCategory,
  type CweView,
  type CweTreeNode,
} from "./lib/cwe.js";

const ATTRIBUTION = {
  nvd: "This product uses data from the NVD API but is not endorsed or certified by the NVD.",
  epss: "EPSS data provided by FIRST.org (https://www.first.org/epss/).",
  attack: "ATT&CK is a registered trademark of The MITRE Corporation. Licensed under Apache 2.0.",
  kev: "CISA Known Exploited Vulnerabilities Catalog — US Government public domain.",
  cwe: "CWE is a community-developed list of common software and hardware weakness types. (c) The MITRE Corporation.",
};

// ---------------------------------------------------------------------------
// Formatters
// ---------------------------------------------------------------------------

function formatCveSummary(cve: NvdCveItem) {
  const description = cve.descriptions?.find((d) => d.lang === "en")?.value ?? "";
  const cvss31 = cve.metrics?.cvssMetricV31?.[0]?.cvssData;
  const cvss2 = cve.metrics?.cvssMetricV2?.[0]?.cvssData;

  return {
    id: cve.id,
    published: cve.published ?? null,
    lastModified: cve.lastModified ?? null,
    vulnStatus: cve.vulnStatus ?? null,
    description,
    cvss: cvss31
      ? {
          version: "3.1",
          baseScore: cvss31.baseScore ?? null,
          severity: cvss31.baseSeverity ?? null,
          vector: cvss31.vectorString ?? null,
          attackVector: cvss31.attackVector ?? null,
          attackComplexity: cvss31.attackComplexity ?? null,
          privilegesRequired: cvss31.privilegesRequired ?? null,
          userInteraction: cvss31.userInteraction ?? null,
        }
      : cvss2
        ? {
            version: "2.0",
            baseScore: cvss2.baseScore ?? null,
            severity: null,
            vector: cvss2.vectorString ?? null,
          }
        : null,
    weaknesses:
      cve.weaknesses
        ?.flatMap((w) => w.description?.filter((d) => d.lang === "en").map((d) => d.value) ?? [])
        ?? [],
    references: (cve.references ?? []).slice(0, 10).map((r) => ({
      url: r.url,
      source: r.source ?? null,
      tags: r.tags ?? [],
    })),
  };
}

function formatKevStatus(kev: KevEntry | null) {
  if (!kev) return { inKev: false };
  return {
    inKev: true,
    vendorProject: kev.vendorProject,
    product: kev.product,
    vulnerabilityName: kev.vulnerabilityName,
    dateAdded: kev.dateAdded,
    dueDate: kev.dueDate,
    requiredAction: kev.requiredAction,
    knownRansomwareCampaignUse: kev.knownRansomwareCampaignUse,
    shortDescription: kev.shortDescription,
  };
}

function formatEpss(epss: EpssScore | null) {
  if (!epss) return null;
  return { score: epss.epss, percentile: epss.percentile, date: epss.date };
}

function formatCweWeakness(w: CweWeakness) {
  return {
    id: w.ID,
    name: w.Name,
    abstraction: w.Abstraction,
    structure: w.Structure,
    status: w.Status,
    description: w.Description,
    extendedDescription: w.ExtendedDescription ?? null,
    likelihoodOfExploit: w.LikelihoodOfExploit ?? null,
    relatedWeaknesses: w.RelatedWeaknesses?.map((r) => ({
      nature: r.Nature,
      cweId: r.CWE_ID,
      viewId: r.ViewID,
      chainId: r.ChainID ?? null,
    })) ?? [],
    commonConsequences: w.CommonConsequences?.map((c) => ({
      scope: Array.isArray(c.Scope) ? c.Scope : [c.Scope],
      impact: Array.isArray(c.Impact) ? c.Impact : [c.Impact],
      likelihood: c.Likelihood ?? null,
      note: c.Note ?? null,
    })) ?? [],
    detectionMethods: w.DetectionMethods?.map((d) => ({
      method: d.Method,
      description: d.Description,
      effectiveness: d.Effectiveness ?? null,
      effectivenessNotes: d.EffectivenessNotes ?? null,
    })) ?? [],
    potentialMitigations: w.PotentialMitigations?.map((m) => ({
      phase: Array.isArray(m.Phase) ? m.Phase : [m.Phase],
      description: m.Description,
      effectiveness: m.Effectiveness ?? null,
      effectivenessNotes: m.EffectivenessNotes ?? null,
    })) ?? [],
    relatedAttackPatterns: w.RelatedAttackPatterns?.map((a) => a.CAPEC_ID) ?? [],
    references: w.References?.map((r) => ({
      id: r.Reference_ID,
      authors: r.Author,
      title: r.Title,
      url: r.URL ?? null,
    })) ?? [],
  };
}

function formatCweCategory(c: CweCategory) {
  return {
    id: c.ID,
    name: c.Name,
    status: c.Status,
    summary: c.Summary,
    relationships: c.Relationships?.map((r) => ({
      nature: r.Nature,
      cweId: r.CWE_ID,
      viewId: r.ViewID,
    })) ?? [],
  };
}

function formatCweView(v: CweView) {
  return {
    id: v.ID,
    name: v.Name,
    type: v.Type,
    status: v.Status,
    objective: v.Objective ?? null,
    membersCount: v.Members?.length ?? 0,
    audience: v.Audience?.map((a) => ({
      type: a.Type,
      description: a.Description,
    })) ?? [],
  };
}

// ---------------------------------------------------------------------------
// MCP Server
// ---------------------------------------------------------------------------

const mcpServer = new McpServer({
  name: "cybersecurity-vuln-mcp",
  version: "1.1.0",
});

// ========================================================================
// VULN TOOLS (existing)
// ========================================================================

mcpServer.tool(
  "vuln_lookup_cve",
  "Look up a CVE by ID and get enriched intelligence: NVD details (CVSS score, description, references), CISA KEV active exploitation status, EPSS exploitation probability score, and MITRE ATT&CK techniques. Optionally includes full CWE weakness details when enrichCwe=true.",
  {
    cveId: z
      .string()
      .regex(/^CVE-\d{4}-\d{4,}$/i)
      .describe("CVE identifier (e.g., CVE-2021-44228)"),
    enrichCwe: z.boolean().default(false).describe("If true, fetch full CWE details for weakness references found in the CVE. Enriches each CWE entry with description, consequences, mitigations, and detection methods.")
  },
  async ({ cveId, enrichCwe }) => {
    const normalizedId = cveId.toUpperCase();

    const [nvdResult, kevResult, epssResult] = await Promise.allSettled([
      getCveById(normalizedId),
      lookupCve(normalizedId),
      getEpssByCve(normalizedId),
    ]);

    const nvd = nvdResult.status === "fulfilled" ? nvdResult.value : null;
    const kev = kevResult.status === "fulfilled" ? kevResult.value : null;
    const epss = epssResult.status === "fulfilled" ? epssResult.value : null;

    if (!nvd) {
      const nvdError = nvdResult.status === "rejected" ? String(nvdResult.reason) : "";
      return {
        content: [
          {
            type: "text" as const,
            text: `CVE ${normalizedId} not found in NVD.${nvdError ? ` Error: ${nvdError}` : ""}`,
          },
        ],
        isError: true,
      };
    }

    const attackTechniques = getAttackTechniques(normalizedId);

    // Optional CWE enrichment
    let cweDetails: unknown = null;
    if (enrichCwe) {
      const cwes = nvd.weaknesses
        ?.flatMap((w) => w.description?.filter((d) => d.lang === "en").map((d) => d.value) ?? [])
        ?? [];

      const cweIds = cwes
        .map((c) => {
          const match = c.match(/^CWE-(\d+)$/i);
          return match?.[1] ?? null;
        })
        .filter((x): x is string => x !== null);

      if (cweIds.length > 0) {
        try {
          const weaknesses = await resolveCweWeaknesses(cweIds.join(","));
          cweDetails = weaknesses.map(formatCweWeakness);
        } catch {
          cweDetails = { error: "Failed to fetch CWE details" };
        }
      }
    }

    const enriched = {
      ...formatCveSummary(nvd),
      cweDetails,
      kevStatus: formatKevStatus(kev),
      epss: formatEpss(epss),
      attackTechniques: attackTechniques.length > 0 ? attackTechniques : null,
      dataSources: {
        nvd: nvdResult.status === "fulfilled",
        kev: kevResult.status === "fulfilled",
        epss: epssResult.status === "fulfilled",
        attack: attackTechniques.length > 0,
        cwe: cweDetails !== null && !((typeof cweDetails === "object" && cweDetails !== null && "error" in cweDetails)),
      },
      attribution: ATTRIBUTION,
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(enriched, null, 2) }],
      isError: false,
    };
  },
);

mcpServer.tool(
  "vuln_lookup_cves",
  "Bulk lookup multiple CVEs in a single call. Massive performance boost for analyzing software stacks, SBOMs, or vulnerability lists. Each CVE gets the same enrichment as vuln_lookup_cve: NVD details, CISA KEV status, EPSS score, ATT&CK techniques, and optional CWE details.",
  {
    cveIds: z
      .string()
      .regex(/^CVE-\d{4}-\d{4,}(,CVE-\d{4}-\d{4,})*$/i)
      .describe("Comma-separated CVE identifiers (e.g., 'CVE-2021-44228,CVE-2023-38408,CVE-2019-19781')"),
    enrichCwe: z.boolean().default(false).describe("If true, fetch full CWE details for weakness references found across all CVEs."),
  },
  async ({ cveIds, enrichCwe }) => {
    const ids = cveIds.split(",").map((id) => id.trim().toUpperCase());

    const { found: nvdResults, notFound } = await getCvesByIdBulk(ids);

    // Bulk KEV + EPSS lookups in parallel
    const kevSettled = await Promise.allSettled(ids.map((id) => lookupCve(id)));
    const epssSettled = await Promise.allSettled(ids.map((id) => getEpssByCve(id)));

    const results = [];
    for (let i = 0; i < nvdResults.length; i++) {
      const nvd = nvdResults[i];
      const kevResult = kevSettled[i];
      const epssResult = epssSettled[i];
      const kev = kevResult.status === "fulfilled" ? kevResult.value : null;
      const epss = epssResult.status === "fulfilled" ? epssResult.value : null;
      const attackTechniques = getAttackTechniques(nvd.id);

      let cweDetails: unknown = null;
      if (enrichCwe) {
        const cwes = nvd.weaknesses
          ?.flatMap((w) => w.description?.filter((d) => d.lang === "en").map((d) => d.value) ?? [])
          ?? [];
        const cweIds = cwes
          .map((c) => { const m = c.match(/^CWE-(\d+)$/i); return m?.[1] ?? null; })
          .filter((x): x is string => x !== null);
        if (cweIds.length > 0) {
          try {
            const weaknesses = await resolveCweWeaknesses(cweIds.join(","));
            cweDetails = weaknesses.map(formatCweWeakness);
          } catch { cweDetails = { error: "Failed to fetch CWE details" }; }
        }
      }

      results.push({
        ...formatCveSummary(nvd),
        cweDetails,
        kevStatus: formatKevStatus(kev),
        epss: formatEpss(epss),
        attackTechniques: attackTechniques.length > 0 ? attackTechniques : null,
      });
    }

    const response = {
      totalRequested: ids.length,
      found: results.length,
      notFound,
      cves: results,
      dataSources: {
        nvd: true,
        kev: true,
        epss: true,
        attack: true,
        cwe: enrichCwe,
      },
      attribution: ATTRIBUTION,
    };

    return {
      content: [{ type: "text" as const, text: JSON.stringify(response, null, 2) }],
      isError: false,
    };
  },
);

mcpServer.tool(
  "vuln_search",
  "Search the NIST NVD for CVEs by keyword, severity, and date range.",
  {
    keyword: z.string().optional().describe("Search keyword (e.g., 'apache log4j')"),
    severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).optional().describe("CVSS v3.1 severity"),
    pubStartDate: z.string().optional().describe("Start date ISO format"),
    pubEndDate: z.string().optional().describe("End date ISO format"),
    hasKev: z.boolean().optional().describe("Only show actively exploited CVEs"),
    limit: z.number().int().min(1).max(50).default(20),
  },
  async ({ keyword, severity, pubStartDate, pubEndDate, hasKev, limit }) => {
    try {
      const result = await searchCves({ keyword, severity, pubStartDate, pubEndDate, limit });
      let cves = result.cves.map(formatCveSummary);
      if (hasKev) {
        const kevChecks = await Promise.allSettled(cves.map((c) => lookupCve(c.id)));
        cves = cves.filter((_, i) => kevChecks[i].status === "fulfilled" && kevChecks[i].value !== null);
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ totalResults: hasKev ? cves.length : result.totalResults, returnedCount: cves.length, cves, attribution: { nvd: ATTRIBUTION.nvd } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error searching CVEs: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "vuln_kev_latest",
  "Get recently added CISA KEV entries (actively exploited vulnerabilities).",
  { days: z.number().int().min(1).max(365).default(7).describe("Look back N days"), limit: z.number().int().min(1).max(100).default(20) },
  async ({ days, limit }) => {
    try {
      const entries = await getLatestKevEntries(days, limit);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ period: `Last ${days} days`, count: entries.length, entries: entries.map((e) => ({ cveId: e.cveID, vendor: e.vendorProject, product: e.product, name: e.vulnerabilityName, dateAdded: e.dateAdded, dueDate: e.dueDate, requiredAction: e.requiredAction, ransomwareUse: e.knownRansomwareCampaignUse, description: e.shortDescription })), attribution: { kev: ATTRIBUTION.kev } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching KEV entries: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "vuln_kev_due_soon",
  "Get CISA KEV vulnerabilities with upcoming remediation deadlines.",
  { days: z.number().int().min(1).max(90).default(14).describe("Deadline within next N days"), limit: z.number().int().min(1).max(100).default(20) },
  async ({ days, limit }) => {
    try {
      const entries = await getDueSoonEntries(days, limit);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ deadline: `Within ${days} days`, count: entries.length, entries: entries.map((e) => ({ cveId: e.cveID, vendor: e.vendorProject, product: e.product, name: e.vulnerabilityName, dateAdded: e.dateAdded, dueDate: e.dueDate, requiredAction: e.requiredAction, ransomwareUse: e.knownRansomwareCampaignUse, description: e.shortDescription })), attribution: { kev: ATTRIBUTION.kev } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "vuln_epss_top",
  "Get CVEs with highest EPSS exploitation probability scores.",
  { threshold: z.number().min(0).max(1).default(0.7).describe("Minimum EPSS score (0-1)"), limit: z.number().int().min(1).max(100).default(20) },
  async ({ threshold, limit }) => {
    try {
      const scores = await getTopEpss(threshold, limit);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ threshold, count: scores.length, scores: scores.map((s) => ({ cveId: s.cve, epssScore: s.epss, percentile: s.percentile, date: s.date })), attribution: { epss: ATTRIBUTION.epss } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "vuln_trending",
  "Get recently published critical/high severity CVEs from the NVD.",
  { days: z.number().int().min(1).max(30).default(3).describe("Published within last N days"), severity: z.enum(["LOW", "MEDIUM", "HIGH", "CRITICAL"]).default("CRITICAL"), limit: z.number().int().min(1).max(50).default(20) },
  async ({ days, severity, limit }) => {
    try {
      const result = await getTrendingCves({ days, severity, limit });
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ period: `Last ${days} days`, severity, totalResults: result.totalResults, returnedCount: result.cves.length, cves: result.cves.map(formatCveSummary), attribution: { nvd: ATTRIBUTION.nvd } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "vuln_by_vendor",
  "Search CVEs for a specific vendor/product, cross-referenced with CISA KEV.",
  { vendor: z.string().describe("Vendor name (e.g., 'microsoft', 'apache')"), product: z.string().optional().describe("Product name (e.g., 'windows', 'log4j')"), limit: z.number().int().min(1).max(50).default(20) },
  async ({ vendor, product, limit }) => {
    try {
      const [nvdResult, kevEntries] = await Promise.allSettled([
        getCvesByVendor({ vendor, product, limit }),
        getKevByVendor(vendor, 500),
      ]);
      const cves = nvdResult.status === "fulfilled" ? nvdResult.value.cves.map(formatCveSummary) : [];
      const kevSet = new Set(kevEntries.status === "fulfilled" ? kevEntries.value.map((e) => e.cveID) : []);
      const enrichedCves = cves.map((c) => ({ ...c, inKev: kevSet.has(c.id) }));
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ vendor, product: product ?? null, totalResults: nvdResult.status === "fulfilled" ? nvdResult.value.totalResults : 0, returnedCount: enrichedCves.length, kevCount: enrichedCves.filter((c) => c.inKev).length, cves: enrichedCves, attribution: { nvd: ATTRIBUTION.nvd, kev: ATTRIBUTION.kev } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error: ${msg}` }], isError: true };
    }
  },
);

// ========================================================================
// CWE TOOLS (new)
// ========================================================================

mcpServer.tool(
  "cwe_version",
  "Get MITRE CWE catalog version info: content release date, version number, total counts of weaknesses, categories, and views. Use this to verify freshness and see API availability.",
  {},
  async () => {
    try {
      const version = await getCweVersion();
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ ...version, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching CWE version: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_get",
  "Get full details of one or more CWE weaknesses, categories, or views by their numeric IDs. Returns comprehensive weakness data including description, consequences, detection methods, mitigations, related Attack Patterns (CAPEC), and references. Supports comma-separated IDs for bulk retrieval.",
  {
    ids: z.string()
      .regex(/^\d+(,\d+)*$/)
      .describe("Comma-separated CWE IDs (e.g., '79' or '79,89,22'). Do not include 'CWE-' prefix."),
    type: z.enum(["auto", "weakness", "category", "view"]).default("auto").describe("Entity type. Use 'auto' to let the API infer. Explicitly use 'weakness' for software weaknesses, 'category' for categories, 'view' for views.")
  },
  async ({ ids, type }) => {
    try {
      let data: unknown;
      switch (type) {
        case "weakness": {
          const result = await getCweWeaknesses(ids);
          data = { weaknesses: (result.Weaknesses ?? []).map(formatCweWeakness) };
          break;
        }
        case "category": {
          const result = await getCweCategories(ids);
          data = { categories: (result.Categories ?? []).map(formatCweCategory) };
          break;
        }
        case "view": {
          const result = await getCweViews(ids);
          data = { views: (result.Views ?? []).map(formatCweView) };
          break;
        }
        default: {
          // Auto mode: try weakness first, fall back to other types on 404
          try {
            const result = await getCweWeaknesses(ids);
            data = { weaknesses: (result.Weaknesses ?? []).map(formatCweWeakness) };
          } catch (weakErr) {
            const errMsg = String(weakErr);
            if (errMsg.includes("not found") || errMsg.includes("404")) {
              try {
                const result = await getCweCategories(ids);
                data = { categories: (result.Categories ?? []).map(formatCweCategory) };
              } catch (catErr) {
                const errMsg2 = String(catErr);
                if (errMsg2.includes("not found") || errMsg2.includes("404")) {
                  const result = await getCweViews(ids);
                  data = { views: (result.Views ?? []).map(formatCweView) };
                } else {
                  throw catErr;
                }
              }
            } else {
              throw weakErr;
            }
          }
        }
      }

      return {
        content: [{ type: "text" as const, text: JSON.stringify({ ...data as Record<string, unknown>, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching CWE data: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_parents",
  "Get parent entities of a CWE entry in the hierarchy. Useful for understanding how a weakness is classified (e.g., CWE-79 XSS is a child of CWE-1003 'Weaknesses in Software Development'). Optionally filter by view ID.",
  {
    id: z.string().regex(/^\d+$/).describe("CWE numeric ID (e.g., '79'). Do not include 'CWE-' prefix."),
    viewId: z.string().optional().describe("Optional view ID to scope the hierarchy (e.g., '1000' for Research Concepts, '1003' for Software Development)."),
  },
  async ({ id, viewId }) => {
    try {
      const parents = await getCweParents(id, viewId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ id, viewId: viewId ?? null, parents, count: parents.length, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching CWE parents: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_children",
  "Get child entities of a CWE entry in the hierarchy. Useful for finding specific weakness variants under a higher-level CWE class. Optionally filter by view ID.",
  {
    id: z.string().regex(/^\d+$/).describe("CWE numeric ID (e.g., '79')."),
    viewId: z.string().optional().describe("Optional view ID to scope the hierarchy (e.g., '1000')."),
  },
  async ({ id, viewId }) => {
    try {
      const children = await getCweChildren(id, viewId);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ id, viewId: viewId ?? null, children, count: children.length, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching CWE children: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_ancestors",
  "Get the ancestor tree of a CWE entry. Returns direct parents up to root. Use maxDepth to control tree depth and prevent huge responses.",
  {
    id: z.string().regex(/^\d+$/).describe("CWE numeric ID (e.g., '79')."),
    viewId: z.string().optional().describe("Optional view ID (e.g., '1000' for Research Concepts)."),
    primary: z.boolean().default(false).describe("If true, include only primary parent relationships (excludes secondary/related mappings)."),
    maxDepth: z.number().int().min(1).max(10).default(3).describe("Maximum recursion depth. Default 3 prevents massive context overflow while still showing meaningful hierarchy."),
  },
  async ({ id, viewId, primary, maxDepth }) => {
    try {
      const tree = await getCweAncestors(id, viewId, primary);
      const totalNodes = countTreeNodes(tree);
      let trimmed = tree;
      if (totalNodes > 200) {
        trimmed = trimTreeByDepth(tree, maxDepth);
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ id, viewId: viewId ?? null, primary, maxDepth, totalNodes, nodesReturned: countTreeNodes(trimmed), trimmed: totalNodes > 200, tree: trimmed, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching CWE ancestors: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_descendants",
  "Get the descendant tree of a CWE entry. Use maxDepth to control tree depth and prevent context overflow. For example, descendants of CWE-20 at depth 2 show major subcategories, while depth 1 shows only direct children.",
  {
    id: z.string().regex(/^\d+$/).describe("CWE numeric ID (e.g., '20')."),
    viewId: z.string().optional().describe("Optional view ID (e.g., '1000')."),
    maxDepth: z.number().int().min(1).max(10).default(2).describe("Maximum recursion depth. Default 2 prevents massive context overflow while still showing useful sub-variants."),
  },
  async ({ id, viewId, maxDepth }) => {
    try {
      const tree = await getCweDescendants(id, viewId);
      const totalNodes = countTreeNodes(tree);
      let trimmed = tree;
      if (totalNodes > 200) {
        trimmed = trimTreeByDepth(tree, maxDepth);
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ id, viewId: viewId ?? null, maxDepth, totalNodes, nodesReturned: countTreeNodes(trimmed), trimmed: totalNodes > 200, tree: trimmed, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error fetching CWE descendants: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_list_all",
  "List the MITRE CWE catalog with pagination. Supports limit/offset to prevent context overflow. The full catalog is ~1000 weaknesses; use small pages for LLM consumption.",
  {
    entity: z.enum(["weaknesses", "categories", "views"]).default("weaknesses").describe("Which entity type to list."),
    limit: z.number().int().min(1).max(200).default(50).describe("Max items to return per page. Default 50 stays within typical token budgets."),
    offset: z.number().int().min(0).default(0).describe("Skip first N items. Combine with limit for pagination."),
  },
  async ({ entity, limit, offset }) => {
    try {
      let data: unknown;
      switch (entity) {
        case "weaknesses": {
          const result = await getAllWeaknesses(limit, offset);
          data = { weaknesses: result.map(formatCweWeakness), page: { limit, offset, totalHint: 969 } };
          break;
        }
        case "categories": {
          const result = await getAllCategories(limit, offset);
          data = { categories: result.map(formatCweCategory), page: { limit, offset, totalHint: 350 } };
          break;
        }
        case "views": {
          const result = await getAllViews(limit, offset);
          data = { views: result.map(formatCweView), page: { limit, offset, totalHint: 45 } };
          break;
        }
      }
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ ...data as Record<string, unknown>, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error listing CWE entities: ${msg}` }], isError: true };
    }
  },
);

mcpServer.tool(
  "cwe_search_name",
  "Search the full CWE catalog by name or keyword. Returns matching weaknesses, categories, and views filtered by a keyword (case-insensitive substring match). Useful for finding CWE IDs without knowing the exact number.",
  {
    keyword: z.string().min(1).describe("Search term (e.g., 'sql injection', 'buffer overflow', 'input validation')."),
    type: z.enum(["weakness", "category", "view", "all"]).default("all").describe("Limit search scope to a specific entity type."),
    limit: z.number().int().min(1).max(1000).default(50).describe("Maximum results to return."),
  },
  async ({ keyword, type, limit }) => {
    try {
      const results: Array<{ id: string; name: string; type: string; status: string; description?: string }> = [];

      if (type === "all" || type === "weakness") {
        const w = await getAllWeaknesses();
        results.push(
          ...w
            .filter((x) => x.Name.toLowerCase().includes(keyword.toLowerCase()) || x.Description.toLowerCase().includes(keyword.toLowerCase()))
            .map((x) => ({ id: x.ID, name: x.Name, type: "weakness", status: x.Status, description: x.Description }))
        );
      }
      if (type === "all" || type === "category") {
        const c = await getAllCategories();
        results.push(
          ...c
            .filter((x) => x.Name.toLowerCase().includes(keyword.toLowerCase()) || x.Summary.toLowerCase().includes(keyword.toLowerCase()))
            .map((x) => ({ id: x.ID, name: x.Name, type: "category", status: x.Status, description: x.Summary }))
        );
      }
      if (type === "all" || type === "view") {
        const v = await getAllViews();
        results.push(
          ...v
            .filter((x) => x.Name.toLowerCase().includes(keyword.toLowerCase()))
            .map((x) => ({ id: x.ID, name: x.Name, type: "view", status: x.Status, description: x.Objective ?? "" }))
        );
      }

      const sliced = results.slice(0, limit);
      return {
        content: [{ type: "text" as const, text: JSON.stringify({ query: keyword, totalMatches: results.length, returned: sliced.length, results: sliced, attribution: { cwe: ATTRIBUTION.cwe } }, null, 2) }],
        isError: false,
      };
    } catch (error) {
      const msg = error instanceof Error ? error.message : String(error);
      return { content: [{ type: "text" as const, text: `Error searching CWE: ${msg}` }], isError: true };
    }
  },
);

// ---------------------------------------------------------------------------
// Transport
// ---------------------------------------------------------------------------

const transport = new StdioServerTransport();
await mcpServer.connect(transport);
