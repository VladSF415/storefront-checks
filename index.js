// storefront-checks: free, rules-based checks for e-commerce pages.
// The engines in lib/ are the same ones behind the free tools on
// extensionsmarket.com. They fetch public pages and apply rules; no AI model
// is called and nothing is stored.
const ai = require("./lib/ai-shopping-engine");
const gmc = require("./lib/gmc-engine");
const checkout = require("./lib/checkout-engine");
const audit = require("./lib/audit-engine");

const SITE = "https://extensionsmarket.com";
const norm = (u) => (/^https?:\/\//i.test(u) ? u : "https://" + u);

// The engines link suggestions site-relative (they were written for
// extensionsmarket.com); make those links absolute for library users.
function absolute(report) {
  if (report && Array.isArray(report.recommendedApps)) {
    report.recommendedApps = report.recommendedApps.map((a) => ({
      ...a,
      url: a.url && a.url.startsWith("/") ? SITE + a.url : a.url,
      icon: a.icon && a.icon.startsWith("/") ? SITE + a.icon : a.icon,
    }));
  }
  return report;
}

/** AI shopping readiness of one product page (structured data, reviews, policies, GTINs, crawler access). */
async function checkAiShopping(url) {
  return absolute(await ai.checkProduct(norm(url)));
}

/** Your product page against up to two competitor product pages, on the same AI shopping checks. */
async function compareAiShopping(url, competitors = []) {
  return absolute(await ai.checkCompare(norm(url), competitors.slice(0, 2).map(norm)));
}

/** Google Merchant Center compliance of one product page (price and stock vs markup, duplicate Product blocks, identifiers). */
async function checkMerchantCenter(url) {
  return gmc.checkProduct(norm(url));
}

/** A Shopify store's exposure to the 2026 checkout extensibility deadlines, from its public pages. */
async function checkShopifyCheckout(url) {
  return checkout.checkCheckout(norm(url));
}

/** SEO, broken links and speed audit of a store page (speed via the Google PageSpeed Insights API). */
async function auditStore(url) {
  return audit.auditUrl(norm(url));
}

module.exports = {
  checkAiShopping,
  compareAiShopping,
  checkMerchantCenter,
  checkShopifyCheckout,
  auditStore,
  gtinValid: ai.gtinValid,
  validateUrl: audit.validateUrl,
};
