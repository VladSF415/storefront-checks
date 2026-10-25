#!/usr/bin/env node
// storefront-checks CLI: run one check on a URL and print a summary (or JSON).
const lib = require("..");
const S = require("../lib/summarize");

const COMMANDS = {
  ai: { run: lib.checkAiShopping, sum: S.summarizeAiShopping, help: "AI shopping readiness of a product page" },
  gmc: { run: lib.checkMerchantCenter, sum: S.summarizeMerchantCenter, help: "Google Merchant Center compliance of a product page" },
  checkout: { run: lib.checkShopifyCheckout, sum: S.summarizeCheckout, help: "Shopify checkout deadline exposure of a store" },
  audit: { run: lib.auditStore, sum: S.summarizeAudit, help: "SEO, links and speed audit of a page" },
};

const USAGE = `Usage: storefront-checks <command> <url> [--json] [--full]

Commands:
${Object.entries(COMMANDS).map(([k, v]) => `  ${k.padEnd(9)} ${v.help}`).join("\n")}

Options:
  --json    print JSON instead of text
  --full    with --json, print the engine's full report

Examples:
  storefront-checks ai https://example-store.com/products/blue-mug
  storefront-checks gmc https://example-store.com/products/blue-mug --json`;

function printText(s) {
  const lines = [];
  if (s.url) lines.push(`URL: ${s.url}`);
  if (s.score !== undefined) lines.push(`Score: ${s.score}${s.riskLevel ? ` (risk: ${s.riskLevel})` : ""}`);
  if (s.verdict) lines.push(`Verdict: ${s.verdict}`);
  if (s.areas) lines.push("", "Areas:", ...s.areas.map((a) => `  ${String(a.score).padStart(3)}  ${a.area}`));
  if (s.chatgptFeed) lines.push("", `ChatGPT feed: ${s.chatgptFeed.requiredFound} required fields found${s.chatgptFeed.requiredMissing.length ? `, missing: ${s.chatgptFeed.requiredMissing.join(", ")}` : ""}`);
  if (s.problems && s.problems.length) lines.push("", "Problems:", ...s.problems.map((p) => `  [${p.severity || p.status}] ${p.check}${p.detail ? `: ${p.detail}` : ""}`));
  if (s.topIssues && s.topIssues.length) {
    lines.push("", "Top issues:");
    s.topIssues.forEach((i, n) => {
      lines.push(`  ${n + 1}. [${i.impact || "info"}] ${i.issue}`);
      if (i.fix) lines.push(`     Fix: ${i.fix}`);
    });
  }
  if (s.adminChecklist && s.adminChecklist.length) lines.push("", "Check in your Shopify admin:", ...s.adminChecklist.map((c) => `  - ${c}`));
  console.log(lines.join("\n"));
}

async function main(argv) {
  const args = argv.filter((a) => !a.startsWith("--"));
  const flags = new Set(argv.filter((a) => a.startsWith("--")));
  const [cmd, url] = args;
  if (!cmd || flags.has("--help") || !COMMANDS[cmd] || !url) {
    console.log(USAGE);
    return cmd && !flags.has("--help") ? 1 : 0;
  }
  const c = COMMANDS[cmd];
  try {
    const report = await c.run(url);
    if (flags.has("--json")) console.log(JSON.stringify(flags.has("--full") ? report : c.sum(report), null, 2));
    else printText(c.sum(report));
    return 0;
  } catch (e) {
    console.error(`Error: ${e.message}`);
    return 1;
  }
}

main(process.argv.slice(2)).then((code) => process.exit(code));
