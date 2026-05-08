/**
 * MITRE CWE REST API Client
 * Base URL: https://cwe-api.mitre.org/api/v1
 * Docs: https://github.com/CWE-CAPEC/REST-API-wg/blob/main/Quick%20Start.md
 *
 * No authentication required. Content changes infrequently (a few times/year).
 */

import { TtlCache } from "./cache.js";

const CWE_BASE = "https://cwe-api.mitre.org/api/v1";

// CWE data changes infrequently — cache for 7 days by default
const DEFAULT_CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

const cweCache = new TtlCache<unknown>(DEFAULT_CACHE_TTL_MS);

// ---- Rate limit guard ----
const THROTTLE_MS = 300;
let lastRequestTime = 0;

async function throttle(): Promise<void> {
  const now = Date.now();
  const elapsed = now - lastRequestTime;
  if (elapsed < THROTTLE_MS) {
    await new Promise((r) => setTimeout(r, THROTTLE_MS - elapsed));
  }
  lastRequestTime = Date.now();
}

async function cweFetch<T>(path: string): Promise<T> {
  const cacheKey = path;
  const cached = cweCache.get(cacheKey);
  if (cached !== undefined) return cached as T;

  await throttle();

  const url = `${CWE_BASE}${path}`;
  const response = await fetch(url, {
    headers: { Accept: "application/json" },
  });

  if (response.status === 404) {
    throw new Error(`CWE resource not found: ${path}`);
  }
  if (!response.ok) {
    const body = await response.text().catch(() => "");
    throw new Error(`CWE API returned ${response.status}: ${body.slice(0, 300)}`);
  }

  const data = (await response.json()) as T;
  cweCache.set(cacheKey, data);
  return data;
}

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface CweVersion {
  ContentVersion: string;
  ContentDate: string;
  TotalWeaknesses: number;
  TotalCategories: number;
  TotalViews: number;
}

export interface CweSummaryItem {
  ID: string;
  type: string;
}

export interface CweWeakness {
  ID: string;
  Name: string;
  Abstraction: string;
  Structure: string;
  Status: string;
  Diagram?: string;
  Description: string;
  ExtendedDescription?: string;
  LikelihoodOfExploit?: string;
  RelatedWeaknesses?: Array<{
    Nature: string;
    CWE_ID: string;
    ViewID: string;
    ChainID?: string;
  }>;
  WeaknessOrdinalities?: Array<{
    Ordinality: string;
    Description: string;
  }>;
  ApplicablePlatforms?: Array<unknown>;
  BackgroundDetails?: Array<string>;
  AlternateTerms?: Array<{
    Term: string;
    Description?: string;
  }>;
  ModesOfIntroduction?: Array<{
    Phase: string;
    Description: string;
  }>;
  CommonConsequences?: Array<{
    Scope: string | string[];
    Impact: string | string[];
    Likelihood?: string;
    Note?: string;
  }>;
  DetectionMethods?: Array<{
    Method: string;
    Description: string;
    Effectiveness?: string;
    EffectivenessNotes?: string;
  }>;
  PotentialMitigations?: Array<{
    Phase: string | string[];
    Description: string;
    Effectiveness?: string;
    EffectivenessNotes?: string;
  }>;
  DemonstrativeExamples?: Array<unknown>;
  ObservedExamples?: Array<{
    Reference: string;
    Description: string;
    Link?: string;
  }>;
  FunctionalAreas?: Array<string>;
  AffectedResources?: Array<string>;
  TaxonomyMappings?: Array<{
    TaxonomyName: string;
    EntryID: string;
    EntryName?: string;
    MappingFit?: string;
  }>;
  RelatedAttackPatterns?: Array<{
    CAPEC_ID: string;
  }>;
  References?: Array<{
    Reference_ID: string;
    Author: string[];
    Title: string;
    URL?: string;
  }>;
  MappingNotes?: {
    Usage?: string;
    Rationale?: string;
    Comments?: string;
    Reasons?: string;
  };
  Notes?: Array<{
    Type: string;
    Note: string;
  }>;
  ContentHistory?: {
    Submission?: {
      Submission_Name: string;
      Submission_Organization: string;
      Submission_Date: string;
      Submission_Comment?: string;
    };
    Modifications?: Array<{
      Modification_Name: string;
      Modification_Organization?: string;
      Modification_Date: string;
      Modification_Comment: string;
    }>;
  };
}

export interface CweCategory {
  ID: string;
  Name: string;
  Status: string;
  Summary: string;
  Taxonomy_Mappings?: Array<unknown>;
  Relationships?: Array<{
    Nature: string;
    CWE_ID: string;
    ViewID: string;
  }>;
  References?: Array<{
    Reference_ID: string;
    Author: string[];
    Title: string;
    URL?: string;
  }>;
  Notes?: Array<{
    Type: string;
    Note: string;
  }>;
  Content_History?: {
    Submission?: {
      Submission_Name: string;
      Submission_Organization: string;
      Submission_Date: string;
      Submission_Comment?: string;
    };
    Modifications?: Array<{
      Modification_Name: string;
      Modification_Organization?: string;
      Modification_Date: string;
      Modification_Comment: string;
    }>;
  };
}

export interface CweView {
  ID: string;
    Name: string;
  Type: string;
  Status: string;
  Objective?: string;
  Audience?: Array<{
    Type: string;
    Description: string;
  }>;
  Members?: Array<{
    Type: string;
    CWE_ID: string;
  }>;
  References?: Array<{
    Reference_ID: string;
    Author: string[];
    Title: string;
    URL?: string;
  }>;
  Notes?: Array<{
    Type: string;
    Note: string;
  }>;
  Content_History?: {
    Submission?: {
      Submission_Name: string;
      Submission_Organization: string;
      Submission_Date: string;
      Submission_Comment?: string;
    };
    Modifications?: Array<{
      Modification_Name: string;
      Modification_Organization?: string;
      Modification_Date: string;
      Modification_Comment: string;
    }>;
  };
}

export interface CweRelationship {
  Type: string;
  ID: string;
  ViewID: string;
  Primary_Parent?: boolean;
}

export interface CweTreeNode {
  Data: {
    Type: string;
    ID: string;
    ViewID: string;
  };
  Parents?: CweTreeNode[];
  Children?: CweTreeNode[];
}

// ---------------------------------------------------------------------------
// API Functions
// ---------------------------------------------------------------------------

export async function getCweVersion(): Promise<CweVersion> {
  return cweFetch<CweVersion>("/cwe/version");
}

export async function getCweSummaries(ids: string): Promise<CweSummaryItem[]> {
  return cweFetch<CweSummaryItem[]>(`/cwe/${ids}`);
}

export async function getCweWeaknesses(ids: string): Promise<{ Weaknesses: CweWeakness[] }> {
  return cweFetch<{ Weaknesses: CweWeakness[] }>(`/cwe/weakness/${ids}`);
}

export async function getCweCategories(ids: string): Promise<{ Categories: CweCategory[] }> {
  return cweFetch<{ Categories: CweCategory[] }>(`/cwe/category/${ids}`);
}

export async function getCweViews(ids: string): Promise<{ Views: CweView[] }> {
  return cweFetch<{ Views: CweView[] }>(`/cwe/view/${ids}`);
}

export async function getCweParents(id: string, viewId?: string): Promise<CweRelationship[]> {
  let path = `/cwe/${id}/parents`;
  if (viewId) path += `?view=${viewId}`;
  return cweFetch<CweRelationship[]>(path);
}

export async function getCweChildren(id: string, viewId?: string): Promise<CweRelationship[]> {
  let path = `/cwe/${id}/children`;
  if (viewId) path += `?view=${viewId}`;
  return cweFetch<CweRelationship[]>(path);
}

export async function getCweAncestors(
  id: string,
  viewId?: string,
  primary?: boolean,
): Promise<CweTreeNode> {
  let path = `/cwe/${id}/ancestors`;
  const params = new URLSearchParams();
  if (viewId) params.set("view", viewId);
  if (primary) params.set("primary", "true");
  if (params.toString()) path += `?${params.toString()}`;
  return cweFetch<CweTreeNode>(path);
}

export async function getCweDescendants(
  id: string,
  viewId?: string,
): Promise<CweTreeNode> {
  let path = `/cwe/${id}/descendants`;
  if (viewId) path += `?view=${viewId}`;
  return cweFetch<CweTreeNode>(path);
}

// ---------------------------------------------------------------------------
// Helper: resolve CWE summaries into full weakness data
// ---------------------------------------------------------------------------

export async function resolveCweWeaknesses(ids: string): Promise<CweWeakness[]> {
  const data = await getCweWeaknesses(ids);
  return data.Weaknesses ?? [];
}

export async function getAllWeaknesses(limit?: number, offset?: number): Promise<CweWeakness[]> {
  const data = await getCweWeaknesses("all");
  let items = data.Weaknesses ?? [];
  if (offset) items = items.slice(offset);
  if (limit) items = items.slice(0, limit);
  return items;
}

export async function getAllCategories(limit?: number, offset?: number): Promise<CweCategory[]> {
  const data = await getCweCategories("all");
  let items = data.Categories ?? [];
  if (offset) items = items.slice(offset);
  if (limit) items = items.slice(0, limit);
  return items;
}

export async function getAllViews(limit?: number, offset?: number): Promise<CweView[]> {
  const data = await getCweViews("all");
  let items = data.Views ?? [];
  if (offset) items = items.slice(offset);
  if (limit) items = items.slice(0, limit);
  return items;
}

// ---------------------------------------------------------------------------
// Tree helpers: count and trim to prevent context overflow
// ---------------------------------------------------------------------------

function countTreeNodes(node: CweTreeNode): number {
  let count = 1;
  if (node.Children) for (const c of node.Children) count += countTreeNodes(c);
  if (node.Parents) for (const p of node.Parents) count += countTreeNodes(p);
  return count;
}

function trimTreeByDepth(node: CweTreeNode, maxDepth: number): CweTreeNode {
  if (maxDepth <= 0) {
    return { Data: node.Data };
  }
  const trimmed: CweTreeNode = { Data: node.Data };
  if (node.Children && node.Children.length > 0) {
    trimmed.Children = node.Children.map((c) => trimTreeByDepth(c, maxDepth - 1));
  }
  if (node.Parents && node.Parents.length > 0) {
    trimmed.Parents = node.Parents.map((p) => trimTreeByDepth(p, maxDepth - 1));
  }
  return trimmed;
}

export { countTreeNodes, trimTreeByDepth };
