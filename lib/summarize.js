// Compact, model-friendly summaries of the engine reports, shared by the CLI
// and the MCP server. The full reports stay available from the library.

const pickIssues = (issues = [], n = 10) =>
  issues.slice(0, n).map((i) => ({
    area: i.area,
    impact: i.impact,
    issue: i.text,
    ...(i.fix ? { fix: i.fix } : {}),
  }));

const areas = (cats) =>
  Array.isArray(cats)
    ? cats.map((c) => ({ area: c.name, score: c.score }))
    : Object.entries(cats || {}).map(([area, v]) => ({ area, score: v && typeof v === "object" ? v.score : v }));

function summarizeAiShopping(r) {
  return {
    url: r.finalUrl || r.url,
    isProductPage: r.isProductPage,
    score: r.overall,
    areas: areas(r.categories),
    chatgptFeed: r.feed
      ? {
          requiredFound: r.feed.required.found.length,
          requiredMissing: r.feed.required.missing,
          optionalMissing: r.feed.optional.missing,
        }
      : undefined,
    topIssues: pickIssues(r.issues),
  };
}

function summarizeMerchantCenter(r) {
  const problems = (r.findings || []).filter((f) => f.status && f.status !== "pass");
  return {
    url: r.finalUrl || r.url,
    isProductPage: r.isProductPage,
    score: r.score,
    riskLevel: r.riskLevel,
    areas: areas(r.categories),
    problems: problems.slice(0, 15).map((f) => ({ check: f.label, status: f.status, severity: f.severity, detail: f.detail })),
    cantCheck: r.cantCheck,
    scope: r.scope,
  };
}

function summarizeCheckout(r) {
  return {
    url: r.finalUrl || r.url,
    isShopify: r.isShopify,
    score: r.overall,
    verdict: r.verdict,
    areas: areas(r.categories),
    topIssues: pickIssues(r.issues),
    adminChecklist: (r.adminChecklist || []).map((c) => c.label),
    deadlines: r.deadlines,
  };
}

function summarizeAudit(r) {
  return {
    url: r.finalUrl || r.url,
    isShopify: r.isShopify,
    score: r.overall,
    areas: areas(r.categories),
    coreWebVitals: r.coreWebVitals || "not available (Google PageSpeed Insights did not answer)",
    topIssues: pickIssues(r.issues),
  };
}

module.exports = { summarizeAiShopping, summarizeMerchantCenter, summarizeCheckout, summarizeAudit };
