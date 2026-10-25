# storefront-checks

Free, rules-based checks for e-commerce product pages, as a Node library, a CLI and an MCP server.

- **AI shopping readiness:** does a product page give ChatGPT, Google AI Mode, Perplexity and Copilot what they use to recommend it? Product structured data, price and stock, GTINs (with check digits), reviews in the markup, return and shipping terms, answers to buyer questions, and whether AI crawlers are allowed in.
- **Google Merchant Center compliance:** price and availability in the markup against the visible page, duplicate or conflicting Product blocks, and product identifiers.
- **Store audit:** SEO basics, structured data, images, broken links, trust signals and speed.
- **Shopify checkout deadlines:** signs of legacy checkout scripts and tracking ahead of Shopify's 2026 checkout extensibility deadlines, plus a checklist for what only the admin shows.

No AI model is called and nothing is stored. Each check fetches public pages and applies rules. These are the same engines behind the [free web tools on Extensions Market](https://extensionsmarket.com/free-tools).

## Quick start

```sh
npx -y github:VladSF415/storefront-checks ai https://store.example/products/blue-mug
```

Commands: `ai`, `gmc`, `checkout`, `audit`. Add `--json` for JSON output, or `--json --full` for the engine's whole report.

Example output from a real product page:

```text
Score: 76

Areas:
   94  Product identity & data
   20  Reviews & authority
   67  Merchant trust signals
   70  Buyer-question coverage
   91  Price, stock & variants
   91  Commercial data hygiene
  100  AI crawler access & indexing
   75  Agent buying path

ChatGPT feed: 9 required fields found

Top issues:
  1. [high] AggregateRating schema (star ratings): not detected
     Fix: Use a reviews app (Judge.me, Loox, Yotpo) that renders visible stars and outputs AggregateRating schema.
  2. [medium] Return policy in the markup (hasMerchantReturnPolicy): not detected
     Fix: Add a MerchantReturnPolicy (applicableCountry, returnPolicyCategory, merchantReturnDays) to your Organization markup or to the Offer.
```

## Use it from an AI assistant (MCP)

Four tools, each taking `{ "url": "..." }`:

| Tool | What it checks |
|---|---|
| `check_ai_shopping_readiness` | One product page against the signals AI shopping tools use |
| `check_merchant_center` | One product page for Merchant Center price, stock and markup problems |
| `check_shopify_checkout` | A Shopify store's exposure to the 2026 checkout deadlines |
| `audit_store` | SEO, structured data, images, links, trust signals and speed of one page |

**Claude Code:**

```sh
claude mcp add storefront-checks -- npx -y -p github:VladSF415/storefront-checks storefront-checks-mcp
```

**Claude Desktop, Cursor and other MCP clients:**

```json
{
  "mcpServers": {
    "storefront-checks": {
      "command": "npx",
      "args": ["-y", "-p", "github:VladSF415/storefront-checks", "storefront-checks-mcp"]
    }
  }
}
```

Then ask something like "Check https://store.example/products/blue-mug for AI shopping readiness and tell me what to fix first."

## Use it as a library

```sh
npm install github:VladSF415/storefront-checks
```

```js
const { checkAiShopping, checkMerchantCenter, auditStore, checkShopifyCheckout, gtinValid } = require("storefront-checks");

const report = await checkAiShopping("https://store.example/products/blue-mug");
console.log(report.overall, report.issues.slice(0, 3));

gtinValid("6291041500213"); // true: the check digit matches
```

Every function takes a URL and returns the engine's full report. `compareAiShopping(url, [competitorUrl1, competitorUrl2])` runs the AI shopping check on your page and up to two competitor pages.

## Limits

- It sees what a public page shows. Merchant Center account status, Shopify admin data and the feeds you send to shopping channels aren't visible to it.
- It checks one page per call. The store audit also requests the page's links, so keep volume reasonable.
- Core Web Vitals come from the Google PageSpeed Insights API when it answers. Set `GOOGLE_PAGESPEED_API_KEY` for a higher quota.
- Localhost and private network addresses are refused.

## Web versions

The same checks, free in the browser with no signup:

- [AI Shopping Readiness Checker](https://extensionsmarket.com/free-ai-shopping-checker)
- [Google Merchant Center Checker](https://extensionsmarket.com/free-merchant-center-checker)
- [Shopify Store Audit](https://extensionsmarket.com/free-shopify-store-audit)
- [Shopify Checkout Deadline Checker](https://extensionsmarket.com/free-checkout-checker)

## License

MIT. Made by [Extensions Market](https://extensionsmarket.com), which also builds [EZstock](https://ezstock.app), a Shopify app for reorder planning, purchase orders and receiving.
