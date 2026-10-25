#!/usr/bin/env node
// storefront-checks MCP server (stdio). Each tool fetches public pages and
// applies rules; no AI model is called and nothing is stored.
import { createRequire } from "node:module";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

const require = createRequire(import.meta.url);
const lib = require("../index.js");
const S = require("../lib/summarize.js");
const { version } = require("../package.json");

const server = new McpServer({ name: "storefront-checks", version });

const url = z.string().describe("A public page URL, e.g. https://store.com/products/blue-mug");

function tool(name, description, run, summarize) {
  server.registerTool(
    name,
    { description, inputSchema: { url }, annotations: { readOnlyHint: true, openWorldHint: true } },
    async ({ url: target }) => {
      try {
        const report = await run(target);
        return { content: [{ type: "text", text: JSON.stringify(summarize(report), null, 2) }] };
      } catch (e) {
        return { isError: true, content: [{ type: "text", text: `Could not check ${target}: ${e.message}` }] };
      }
    }
  );
}

tool(
  "check_ai_shopping_readiness",
  "Grade one product page on the signals AI shopping tools (ChatGPT, Google AI Mode, Perplexity, Copilot) use: Product structured data, price and stock, GTINs, reviews in markup, return and shipping terms, buyer-question coverage and AI crawler access. Returns a 0-100 score per area and the top issues with fixes.",
  lib.checkAiShopping,
  S.summarizeAiShopping
);
tool(
  "check_merchant_center",
  "Check one product page for Google Merchant Center problems: price and availability in the markup vs the visible page, duplicate or conflicting Product blocks, missing identifiers. Page-level only; it does not log in to Merchant Center.",
  lib.checkMerchantCenter,
  S.summarizeMerchantCenter
);
tool(
  "check_shopify_checkout",
  "Check a Shopify store's exposure to the 2026 checkout extensibility deadlines from its public pages (legacy checkout scripts and tracking), plus a checklist for what only the admin shows.",
  lib.checkShopifyCheckout,
  S.summarizeCheckout
);
tool(
  "audit_store",
  "Audit one store page for SEO basics, structured data, images, broken links, trust signals and speed. Core Web Vitals come from the Google PageSpeed Insights API when it answers, which can take up to about 40 seconds.",
  lib.auditStore,
  S.summarizeAudit
);

await server.connect(new StdioServerTransport());
