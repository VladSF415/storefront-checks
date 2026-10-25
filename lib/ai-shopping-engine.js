// Free "AI Shopping Readiness" checker engine. Grades a single PRODUCT-page URL
// against the on-page signals that AI shopping agents (ChatGPT Shopping, Google
// AI Mode / Shopping Graph, Perplexity, Gemini) use to decide which products to
// RECOMMEND. Pure fetch + Cheerio + rules — ZERO LLM / Anthropic tokens, no model
// calls anywhere, nothing stored. Works on ANY ecommerce product URL (Shopify,
// WooCommerce, custom), not just Shopify.
//
// Reuses the store-auditor's SSRF-guarded validateUrl + fetchPage (same repo).
// Exports: validateUrl (re-export), checkProduct(url) -> { ok, ...report }.

const cheerio = require("cheerio");
const { validateUrl, fetchPage } = require("./audit-engine");
// The Merchant Center checker's careful readers of the price and stock a shopper sees.
const { visiblePrice, visibleStock, normAvail } = require("./gmc-engine");

const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));
const num = (v) => {
  if (v == null) return null;
  const n = parseFloat(String(v).replace(/[^0-9.]/g, ""));
  return isNaN(n) ? null : n;
};
const cents = (n) => Math.round(n * 100);
const money = (n) => n.toFixed(2);

// ── JSON-LD walk: collect @types + the first Product-ish node's fields ────────
// Returns a flat picture of what structured data the page exposes to AI shopping
// engines: which schema types are present, and the Product/Offer/Review/Brand
// signals nested anywhere in the graph.
function readJsonLd($) {
  const types = new Set();
  const sig = {
    hasProduct: false, hasOffer: false, hasPrice: false, hasCurrency: false,
    hasAvailability: false, hasBrand: false, hasIdentifier: false,
    hasAggregateRating: false, reviewCount: null, ratingValue: null, hasReview: false,
    hasOrganization: false, hasBreadcrumb: false, hasFaqSchema: false,
    hasShipping: false, hasReturnPolicy: false,
  };
  $('script[type="application/ld+json"]').each((_, el) => {
    let data;
    try { data = JSON.parse($(el).contents().text()); } catch { return; }
    const walk = (o) => {
      if (!o || typeof o !== "object") return;
      if (Array.isArray(o)) return o.forEach(walk);
      const t = o["@type"];
      if (t) [].concat(t).forEach((x) => types.add(String(x)));
      const tl = t ? [].concat(t).map((x) => String(x).toLowerCase()) : [];
      if (tl.includes("product") || tl.includes("productgroup")) sig.hasProduct = true;
      if (tl.includes("organization") || tl.includes("onlinestore") || tl.includes("store") || tl.includes("localbusiness")) sig.hasOrganization = true;
      if (tl.includes("website") && o.name) sig.hasOrganization = true; // the store name, as Shopify's scanner counts it
      if (tl.includes("breadcrumblist")) sig.hasBreadcrumb = true;
      if (tl.includes("faqpage")) sig.hasFaqSchema = true;
      if (tl.includes("review")) sig.hasReview = true;
      // Offer(s) — may be nested under a Product's `offers`
      const off = o.offers;
      if (off) [].concat(off).forEach((of) => {
        if (of && typeof of === "object") {
          sig.hasOffer = true;
          if (of.price != null || of.lowPrice != null || of.highPrice != null) sig.hasPrice = true;
          if (of.priceCurrency != null) sig.hasCurrency = true;
          if (of.availability != null) sig.hasAvailability = true;
          if (of.shippingDetails != null) sig.hasShipping = true;
          if (of.hasMerchantReturnPolicy != null) sig.hasReturnPolicy = true;
        }
      });
      // Brand
      if (o.brand != null) sig.hasBrand = true;
      // Product identifiers
      if (o.gtin != null || o.gtin13 != null || o.gtin12 != null || o.gtin8 != null || o.gtin14 != null || o.mpn != null || o.sku != null || o.productID != null) sig.hasIdentifier = true;
      // Ratings
      if (o.aggregateRating != null) {
        sig.hasAggregateRating = true;
        const ar = o.aggregateRating;
        const rc = ar && (ar.reviewCount != null ? ar.reviewCount : ar.ratingCount);
        if (rc != null) { const n = parseInt(rc, 10); if (!isNaN(n)) sig.reviewCount = n; }
        const rv = ar && ar.ratingValue;
        if (rv != null) { const f = parseFloat(rv); if (!isNaN(f)) sig.ratingValue = f; }
      }
      if (o.review != null) sig.hasReview = true;
      if (o.shippingDetails != null || o.hasShippingService != null) sig.hasShipping = true; // offer- or store-level
      if (o.hasMerchantReturnPolicy != null) sig.hasReturnPolicy = true;
      if (o["@graph"]) walk(o["@graph"]);
      for (const k of Object.keys(o)) { const v = o[k]; if (v && typeof v === "object" && k !== "@type") walk(v); }
    };
    walk(data);
  });
  return { types: [...types], sig };
}

// Detect whether the URL is plausibly a PRODUCT page (vs a homepage/collection).
// Used only to warn the user — the audit still runs on any page.
function looksLikeProductPage(url, $, sig) {
  if (sig.hasProduct) return true;
  if (/\/products?\//i.test(url) || /\/product\//i.test(url) || /\/p\//i.test(url) || /\/dp\//i.test(url) || /\/item\//i.test(url)) return true;
  if ($('meta[property="og:type"]').attr("content") === "product") return true;
  if ($('meta[property="product:price:amount"]').length) return true;
  if ($('[itemtype*="schema.org/Product" i]').length) return true;
  return false;
}

// Scan visible page text for a keyword group (trust signals that may live in copy
// rather than schema — return policy, shipping, warranty).
function textHas(text, re) { return re.test(text); }

// ── Category analyzers ───────────────────────────────────────────────────────
// Each returns { name, checks:[{label, ok, kind}], score }. A check's `kind` is
// "fact" (provable on the page) or "suggestion" (best practice the merchant may
// legitimately choose to skip). Scores weight by importance within the category.

// The schema.org availability values engines accept; free text like "in stock" isn't one.
const AVAILABILITY_VALUES = /^(?:https?:\/\/schema\.org\/|schema:)?(InStock|OutOfStock|PreOrder|PreSale|BackOrder|Discontinued|InStoreOnly|LimitedAvailability|OnlineOnly|SoldOut|MadeToOrder|Reserved)$/;
const words = (s) => (String(s || "").replace(/<[^>]+>/g, " ").match(/[\p{L}\p{N}][\p{L}\p{N}'’-]*/gu) || []).length;

function catIdentity(sig, $, ldp, shopify, today) {
  const c = [
    { id: "product-schema", label: "Product schema (JSON-LD)", ok: sig.hasProduct, kind: "fact", w: 22 },
    { id: "offer-price", label: "Offer with price", ok: sig.hasPrice, kind: "fact", w: 20 },
    { id: "currency", label: "Price currency", ok: sig.hasCurrency, kind: "fact", w: 8 },
    { id: "availability", label: "Availability / in-stock status", ok: sig.hasAvailability, kind: "fact", w: 16 },
    { id: "brand", label: "Brand", ok: sig.hasBrand, kind: "fact", w: 10 },
    { id: "identifier", label: "Product identifier (GTIN / MPN / SKU)", ok: sig.hasIdentifier, kind: "fact", w: 14 },
    { id: "breadcrumb", label: "Breadcrumb schema", ok: sig.hasBreadcrumb, kind: "fact", w: 10 },
  ];
  if (ldp.blocks) c.push({ id: "ld-valid", label: "Every JSON-LD block is valid JSON", ok: !ldp.parseErrors, kind: "fact", w: 10,
    issue: `${ldp.parseErrors} of ${ldp.blocks} JSON-LD blocks aren't valid JSON, so engines skip them` });

  // What Google's merchant listings, OpenAI's product feed and Shopify's own
  // readiness scanner each ask of the Product markup itself.
  if (ldp.nodes.length) {
    const all = ldp.nodes.concat(ldp.variants);
    const name = ldp.nodes[0].name != null ? String(ldp.nodes[0].name) : "";
    c.push({ id: "product-image", label: "Product image in the markup", ok: all.some((n) => n.image != null && n.image !== "" && !(Array.isArray(n.image) && !n.image.length)), kind: "fact", w: 12 });
    c.push({ id: "name-length", label: "Product name in the markup, under 150 characters", ok: !!name.trim() && name.length <= 150, kind: "fact", w: 4,
      issue: name.trim() ? `The product name in the markup is ${name.length} characters; AI feeds cut it at 150` : null });
    c.push({ id: "schema-description", label: "Product description in the markup (20+ words)", ok: Math.max(0, ...ldp.nodes.map((n) => words(n.description))) >= 20, kind: "fact", w: 8 });
    c.push({ id: "attrs-markup", label: "Color, size or material in the markup", ok: all.some((n) => ["color", "size", "material", "pattern"].some((k) => n[k] != null && n[k] !== "")) || ldp.nodes.some((n) => n.variesBy), kind: "suggestion", w: 4 });
  }
  if (ldp.offers.length) {
    c.push({ id: "single-offer", label: "An Offer, not only an AggregateOffer", ok: ldp.offers.some((o) => !isAggregate(o)), kind: "fact", w: 6,
      issue: "The markup only has an AggregateOffer (a price range), which Google's merchant listings don't accept" });
    const avails = ldp.offers.map((o) => o.availability).filter((a) => a != null && a !== "");
    if (avails.length) {
      const odd = avails.filter((a) => !AVAILABILITY_VALUES.test(String(a).trim()));
      c.push({ id: "availability-value", label: "Availability uses a standard value (InStock, OutOfStock…)", ok: !odd.length, kind: "fact", w: 6,
        issue: `Availability "${odd[0]}" isn't a value engines understand; use https://schema.org/InStock or another standard value` });
    }
    const until = ldp.offers.map((o) => o.priceValidUntil).filter(Boolean).map((d) => String(d).slice(0, 10)).sort()[0];
    if (until) c.push({ id: "price-valid", label: "priceValidUntil hasn't passed", ok: until >= today, kind: "fact", w: 6,
      issue: `The markup's priceValidUntil (${until}) is in the past, so the price reads as expired` });
    c.push({ id: "item-condition", label: "Item condition in the markup (new, used…)", ok: ldp.offers.some((o) => o.itemCondition), kind: "suggestion", w: 2 });
  }
  if (shopify && shopify.mainImage && shopify.mainImage.width && shopify.mainImage.height) {
    const px = shopify.mainImage.width * shopify.mainImage.height;
    c.push({ id: "image-resolution", label: "Main photo is at least 50,000 pixels", ok: px >= 50000, kind: "fact", w: 6,
      issue: `The main photo is ${shopify.mainImage.width} × ${shopify.mainImage.height}, below the 50,000 pixels Google asks for` });
  }
  if (shopify) c.push({ id: "image-count", label: "3 or more product photos", ok: shopify.imageCount >= 3, kind: "suggestion", w: 3,
    issue: `This product has ${shopify.imageCount} photo${shopify.imageCount === 1 ? "" : "s"}` });
  return score("Product identity & data", c);
}

// Is the page's AggregateRating markup suspicious (the kind Google penalizes and
// AI engines distrust)? Rating in schema but NO visible reviews on the page =
// the classic injected/fake pattern; a claimed rating with 0 reviews, or an
// out-of-range value (>5 or <=0 on the 5-star scale), is likewise a red flag.
// Only meaningful WHEN the page actually has AggregateRating — otherwise null.
function ratingLooksFake(sig, hasVisibleStars) {
  if (!sig.hasAggregateRating) return false;
  if (!hasVisibleStars) return true;                              // schema-only stars, nothing on the page
  if (sig.reviewCount != null && sig.reviewCount <= 0) return true; // "rated" with zero reviews
  if (sig.ratingValue != null && (sig.ratingValue > 5 || sig.ratingValue <= 0)) return true; // impossible value
  return false;
}

// Review widgets as they appear in the page HTML: the class and id names of the
// common review apps, or rating microdata on a visible element. Only element
// attributes are read, never scripts or copy: the AggregateRating JSON-LD itself
// contains the word "aggregateRating" (that used to let every schema-only rating
// pass), an SVG's stroke-opacity contains "oke-", and "hand-stamped" is product copy.
const REVIEW_WIDGET = /star-rating|rating-stars|reviews?-count|\bjudge-?me|\bjdgm|\bloox|\byotpo|\bstamped|\bokendo|\boke-|\bokeReviews|\bspr-badge|\bspr-review|\bjunip|reviews-io|\brivyo|\baggregateRating\b/i;
const widgetAttrs = (body) => body.find("[class], [id], [itemprop]").toArray()
  .map((el) => `${el.attribs.class || ""} ${el.attribs.id || ""} ${el.attribs.itemprop || ""}`).join(" ");

// The page body without scripts, styles or templates: what a crawler that doesn't
// run JavaScript can read as content.
function visibleBody($) {
  const body = $("body").clone();
  body.find("script, style, noscript, template").remove();
  return body;
}

function catReviews(sig, body, bodyText) {
  const hasVisibleStars = REVIEW_WIDGET.test(widgetAttrs(body)) || /\b\d(\.\d)?\s*(out of\s*5|stars?)\b/i.test(bodyText);
  const fakeRating = ratingLooksFake(sig, hasVisibleStars);
  const c = [
    { id: "rating-schema", label: "AggregateRating schema (star ratings)", ok: sig.hasAggregateRating, kind: "fact", w: 40 },
    { id: "review-count", label: "Review count present", ok: sig.reviewCount != null && sig.reviewCount > 0, kind: "fact", w: 25 },
    { id: "review-schema", label: "Individual Review schema", ok: sig.hasReview, kind: "fact", w: 15 },
    { id: "visible-ratings", label: "Visible ratings on the page", ok: hasVisibleStars, kind: "fact", w: 20 },
    // Only counts against a page that HAS rating schema — a page with no rating
    // isn't penalized here (that gap is already caught by the checks above).
    { id: "rating-backed", label: "Rating markup backed by real, visible reviews", ok: !fakeRating, kind: "fact", w: sig.hasAggregateRating ? 30 : 0,
      issue: "The rating markup isn't backed by reviews shown on the page" },
  ];
  const out = score("Reviews & authority", c);
  out.fakeRating = fakeRating;
  return out;
}

// The part of the page about THIS product: <main> when the theme has one, else the
// body without its header, footer, menus and announcement bars. Footer links
// ("Refund policy"), menu links ("Size guide") and store-wide banners say nothing
// about the product, and nearly every store has them, so counting them turned
// these checks green on almost every page.
const NOT_PRODUCT_IN_MAIN = 'nav, [role="navigation"], [class*="announcement" i], [id*="announcement" i], [class*="newsletter" i], [class*="cookie" i], [class*="cart-drawer" i], [id*="cart-drawer" i], [class*="menu-drawer" i], [id*="menu-drawer" i]';
const NOT_PRODUCT = NOT_PRODUCT_IN_MAIN + ', header, footer, aside, [role="banner"], [role="contentinfo"], [id^="shopify-section-"][id*="header" i], [id^="shopify-section-"][id*="footer" i], [class*="shopify-section-group-header" i], [class*="shopify-section-group-footer" i]';
function productArea(body) {
  const main = body.find("main").first();
  const area = (main.length ? main : body).clone();
  area.find(main.length ? NOT_PRODUCT_IN_MAIN : NOT_PRODUCT).remove();
  return area;
}

// What a shopper asks an assistant before buying, as it shows up in product copy.
// Each pattern needs real information: "Size" next to a picker, "3 in stock" or
// "Shipping calculated at checkout" don't answer anything.
const SIZE_INFO = /\b(dimensions?|measurements?|measures|length|width|height|depth|diameter|thickness|weight|weighs|capacity|volume)\b|\b\d+(?:[.,]\d+)?\s?(?:mm|cm|m|in\.|inch(?:es)?|ft|feet|"|kg|g|lbs?|oz|ml|l|litres?|liters?)(?=[\s,.;:)\/x×]|$)/i;
const MATERIAL_INFO = /\b(materials?|made (?:of|from|with)|fabric|composition|ingredients?|cotton|linen|wool|merino|cashmere|silk|polyester|nylon|spandex|elastane|viscose|rayon|leather|suede|denim|canvas|stainless steel|steel|aluminium|aluminum|brass|copper|titanium|sterling silver|(?:\d{1,2}k|solid|plated|vermeil|filled) gold|wood(?:en)?|bamboo|oak|walnut|plastic|silicone|rubber|ceramic|porcelain|stoneware|glass|marble|resin|beeswax|soy wax)\b/i;
const CARE_INFO = /\b(care instructions?|care guide|how to care|caring for|machine[- ]wash(?:able)?|hand[- ]wash|dry[- ]clean|tumble[- ]dry|wash (?:cold|warm|separately|inside out)|do not (?:bleach|iron|tumble)|wipe (?:clean|down)|dishwasher[- ]safe|how to use|directions(?: for use)?|instructions for use|apply (?:to|a|evenly))\b/i;
const FIT_INFO = /\b(compatib\w*|fit guide|fits? (?:most|all|up to|sizes?|true|snug|loose|perfectly|standard|like)|(?:best|regular|relaxed|slim|true|classic|oversized|loose|tailored|athletic) fit|true to size|runs (?:small|large|big|true)|siz(?:e|ing) (?:up|down|guide|chart)|usual size|works with|suitable for|designed for|recommended for|model (?:is|wears))\b/i;
const RETURN_TERMS = /\b(\d+[- ]day (?:returns?|refunds?|money[- ]back|exchanges?|return policy)|free returns|easy returns|returns? (?:within|accepted|are free)|money[- ]back guarantee|refunds? within|exchanges? within|returnable|non[- ]returnable|final sale|no returns)\b/i;
const SHIPPING_TERMS = /\b(free (?:shipping|delivery)|ships? (?:in|within|out|today|tomorrow|next|from)|dispatch(?:es|ed)? (?:in|within|today)|delivery (?:in|within|by|time|estimate)|delivered (?:in|within|by)|arrives? (?:in|by)|estimated (?:delivery|arrival)|next[- ]day|same[- ]day|flat[- ]rate)\b|(?:ships?|deliver\w*|arriv\w*|dispatch\w*)[^.]{0,40}\b\d+\s?(?:-|–|to)\s?\d+\s?(?:business |working )?days\b/i;

// A policy page has to answer what a shopper asks: how many days to return, how
// long delivery takes or what it costs.
const RETURN_WINDOW = /\b\d{1,3}\s*[- ]?\s*(?:calendar |business |working )?days?\b/i;
const SHIPPING_FACTS = /\b\d+\s*(?:-|–|to)\s*\d+\s*(?:business |working )?days?\b|\b\d+\s*(?:business |working )?days?\b|free (?:shipping|delivery)|[$£€]\s?\d|flat[- ]rate|next[- ]day|same[- ]day/i;
const pageExists = (p) => !!p && p.status >= 200 && p.status < 300 && !!(p.text || "").trim();

// Digital goods (downloads, software, courses) have no size, materials or shipping,
// so those checks are skipped for them. Shopify tells us per variant; elsewhere the
// markup's type or the product copy does.
const DIGITAL_TYPES = /softwareapplication|webapplication|mobileapplication|videogame|course|digitaldocument|ebook/i;
function isDigital(shopify, types, areaText) {
  if (shopify && shopify.variants.length) return shopify.variants.every((v) => v.requiresShipping === false);
  return types.some((t) => DIGITAL_TYPES.test(String(t))) || /\b(?:instant|digital) download\b|\bdownloadable\b|\blicense key\b/i.test(areaText);
}

function catTrust(sig, areaText, policies, digital) {
  const c = [
    { id: "organization", label: "Store name in the markup (Organization or WebSite)", ok: sig.hasOrganization, kind: "fact", w: 20 },
    { id: "returns", label: "Return terms on the product page or in markup", ok: sig.hasReturnPolicy || RETURN_TERMS.test(areaText), kind: "fact", w: 22 },
    !digital && { id: "shipping", label: "Shipping time or cost on the product page or in markup", ok: sig.hasShipping || SHIPPING_TERMS.test(areaText), kind: "fact", w: 22 },
    { id: "returns-markup", label: "Return policy in the markup (hasMerchantReturnPolicy)", ok: sig.hasReturnPolicy, kind: "suggestion", w: 6 },
    !digital && { id: "shipping-markup", label: "Shipping details in the markup (shippingDetails)", ok: sig.hasShipping, kind: "suggestion", w: 6 },
    { id: "warranty", label: "Warranty / guarantee", ok: /\b(warranty|guarantee[ds]?)\b/i.test(areaText), kind: "suggestion", w: 10 },
    { id: "in-stock", label: "In-stock signal for buyers", ok: sig.hasAvailability, kind: "fact", w: 14 },
  ].filter(Boolean);
  if (policies) {
    const r = policies.returns, s = policies.shipping;
    c.push({ id: "returns-page", label: "Return policy page states a return window", ok: pageExists(r) && words(r.text) >= 15 && RETURN_WINDOW.test(r.text), kind: "fact", w: 10,
      issue: pageExists(r) ? "The return policy page doesn't say how many days a customer has to return" : "We couldn't find a return policy page" });
    if (!digital) c.push({ id: "shipping-page", label: "Shipping policy page states delivery times or costs", ok: pageExists(s) && SHIPPING_FACTS.test(s.text), kind: "fact", w: 10,
      issue: pageExists(s) ? "The shipping policy page doesn't give delivery times or costs" : "We couldn't find a shipping policy page" });
    const missing = [["privacy", "privacy policy"], ["terms", "terms of service"]].filter(([k]) => !pageExists(policies[k])).map(([, n]) => n);
    c.push({ id: "legal-pages", label: "Privacy policy and terms pages exist", ok: !missing.length, kind: "suggestion", w: 6,
      issue: `We couldn't find a ${missing.join(" or a ")} page` });
  }
  return score("Merchant trust signals", c);
}

// Can an AI agent that runs a browser (ChatGPT agent, Gemini in Chrome and the like)
// buy this? Agents act through the page's accessibility tree, which is what Google
// Lighthouse's Agentic Browsing audit checks: a buy button needs a name, options need
// labels, and a plain form post to the cart works even when the page's scripts don't.
// A sold-out product's button ("Sold out", disabled) is still the buy button.
const BUY_NAME = /\b(add to (?:cart|bag|basket|order)|buy (?:it )?now|pre-?order|buy|sold out|unavailable|notify me|coming soon)\b/i;
const accessibleName = (el) => (el.attr("aria-label") || el.text() || el.attr("value") || el.attr("title") || "").replace(/\s+/g, " ").trim();
function catAgent($, area) {
  const named = area.find('button, input[type="submit"], input[type="button"], [role="button"], a[href]').filter((_, el) => BUY_NAME.test(accessibleName($(el)))).first();
  const buy = named.length ? named : area.find('form[action*="/cart/add" i] button[type="submit"], form[action*="/cart/add" i] input[type="submit"], form[action*="/cart/add" i] button:not([type])').first();
  const form = buy.length ? buy.closest("form") : area.find('form[action*="/cart" i]').first();
  const action = (form.attr("action") || "").trim();
  // A buy link that goes straight to the cart (WooCommerce's ?add-to-cart=) works without scripts too.
  const href = buy.is("a") ? (buy.attr("href") || "").trim() : "";
  const linkToCart = !!href && href !== "#" && !/^javascript:/i.test(href) && /cart|checkout|basket|add-to-cart/i.test(href);
  const fields = area.find('select, input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="image"]), textarea').toArray();
  const unlabeled = fields.filter((el) => {
    const f = $(el), id = f.attr("id");
    return !(f.attr("aria-label") || f.attr("aria-labelledby") || f.closest("label").length || (id && $("label").filter((_, l) => $(l).attr("for") === id).length) || f.closest("fieldset").find("legend").length);
  });
  const c = [
    { id: "buy-button", label: "Buy button in the page HTML", ok: buy.length > 0, kind: "fact", w: 50,
      issue: "The buy button isn't in the page HTML, so it's probably drawn by JavaScript" },
    { id: "labeled-options", label: "Every option and quantity field has a label", ok: !unlabeled.length, kind: "suggestion", w: 25,
      issue: `${unlabeled.length} of ${fields.length} option or quantity fields have no label an agent can read` },
    { id: "buy-form", label: "The buy form works without JavaScript", ok: linkToCart || (form.length > 0 && !!action && action !== "#" && !/^javascript:/i.test(action)), kind: "suggestion", w: 25,
      issue: "The buy button isn't in a form that posts to the cart, so it only works when the page's scripts run" },
  ];
  return score("Agent buying path", c);
}

// Text reduced to lowercase words, so a description can be found in the page whatever
// its markup or entity encoding.
const plainWords = (s) => String(s || "").replace(/<[^>]+>/g, " ").replace(/&[a-z#0-9]+;/gi, " ").toLowerCase().replace(/[^\p{L}\p{N}]+/gu, " ").trim();

function catBuyerQ(sig, $, area, areaText, ldp, shopify, bodyText, digital) {
  const hasSpecTable = area.find('table, dl, [class*="spec" i], [class*="attribute" i], [class*="product-detail" i]').length > 0;
  const hasFaq = sig.hasFaqSchema || area.find('[class*="faq" i],[id*="faq" i]').length > 0 || /frequently asked questions/i.test(areaText);
  const ldDescription = Math.max(0, ...ldp.nodes.map((n) => plainWords(n.description).length));
  const descLen = Math.max(ldDescription, ($('meta[name="description"]').attr("content") || "").length + (area.find('[class*="description" i]').first().text() || "").length);
  const physical = digital ? [] : [
    { id: "attr-size", label: "Size, dimensions or weight", ok: SIZE_INFO.test(areaText), kind: "fact", w: 18 },
    { id: "attr-materials", label: "Materials or ingredients", ok: MATERIAL_INFO.test(areaText), kind: "fact", w: 18 },
    { id: "attr-care", label: "Care or how-to-use instructions", ok: CARE_INFO.test(areaText), kind: "suggestion", w: 10 },
    { id: "attr-fit", label: "Fit or compatibility", ok: FIT_INFO.test(areaText), kind: "suggestion", w: 10 },
  ];
  const c = [
    ...physical,
    { id: "specs", label: "Specs table or list", ok: hasSpecTable, kind: "suggestion", w: 10 },
    { id: "faq", label: "FAQ block or FAQPage schema", ok: hasFaq, kind: "suggestion", w: 14 },
    { id: "description", label: "Substantial product description", ok: descLen > 300, kind: "fact", w: 20 },
  ];
  // Shopify gives us the store's own description, so we can see whether the page's HTML
  // carries it or a script fills it in after load (which most AI crawlers never see).
  const probe = shopify ? plainWords(shopify.descriptionHtml).split(" ").slice(0, 8).join(" ") : "";
  if (probe) c.push({ id: "description-in-html", label: "Product description is in the page HTML", ok: (plainWords(bodyText) + " " + plainWords(ldp.nodes.map((n) => n.description || "").join(" "))).includes(probe), kind: "fact", w: 12,
    issue: "Your product description isn't in the page HTML, so it's loaded by JavaScript" });
  return score("Buyer-question coverage", c);
}

function catCommercial(url, $, sig) {
  const canonical = $('link[rel="canonical"]').attr("href");
  const ogType = $('meta[property="og:type"]').attr("content") || "";
  const ogImg = $('meta[property="og:image"]').attr("content");
  const ogTitle = $('meta[property="og:title"]').attr("content") || $("title").first().text();
  const c = [
    { id: "price-currency", label: "Price + currency readable in markup", ok: sig.hasPrice && sig.hasCurrency, kind: "fact", w: 30 },
    { id: "canonical", label: "Canonical URL", ok: !!canonical, kind: "fact", w: 20 },
    { id: "og-type", label: 'og:type = "product"', ok: /product/i.test(ogType), kind: "suggestion", w: 14 },
    { id: "og-image", label: "og:image (share preview)", ok: !!ogImg, kind: "fact", w: 18 },
    { id: "og-title", label: "og:title / page title", ok: !!ogTitle, kind: "fact", w: 18 },
  ];
  const title = $("title").first().text().replace(/\s+/g, " ").trim();
  c.push({ id: "title-length", label: "Page title is 30 to 60 characters", ok: title.length >= 30 && title.length <= 60, kind: "suggestion", w: 10,
    issue: title ? `The page title is ${title.length} characters` : "The page has no title" });
  return score("Commercial data hygiene", c);
}

// AI crawler access — ONE light check (not a full llms.txt tool). Blocked crawlers
// = your product literally can't be read by that engine.
// robots.txt text, or null when the site has none / it's unreachable.
async function fetchRobots(url) {
  try {
    const origin = new URL(url).origin;
    const r = await fetch(`${origin}/robots.txt`, { signal: AbortSignal.timeout(6000), headers: { "User-Agent": "Mozilla/5.0" } });
    return r.ok ? await r.text() : null;
  } catch (_) { return null; } // no robots or unreachable → treat as not-blocking
}

// The bots that decide whether a product can show up in AI answers. "search" bots
// build the indexes AI answers come from, "user" bots open a page when a person asks
// the assistant about it, "training" bots only collect for model training (blocking
// one doesn't hide you from AI search; each company keeps the controls separate).
const BOTS = [
  { name: "Googlebot", what: "search", w: 14, for: "Google Search, AI Overviews and AI Mode" },
  { name: "Bingbot", what: "search", w: 14, for: "Bing, which ChatGPT search and Copilot draw on" },
  { name: "OAI-SearchBot", what: "search", w: 16, for: "ChatGPT search" },
  { name: "PerplexityBot", what: "search", w: 12, for: "Perplexity's index" },
  { name: "Claude-SearchBot", what: "search", w: 8, for: "Claude's web search" },
  { name: "Applebot", what: "search", w: 4, for: "Siri and Spotlight" },
  { name: "ChatGPT-User", what: "user", w: 8, for: "ChatGPT opening your page for a shopper" },
  { name: "Claude-User", what: "user", w: 4, for: "Claude opening your page for a user" },
  { name: "Perplexity-User", what: "user", w: 4, for: "Perplexity opening your page for a user" },
  { name: "GPTBot", what: "training", w: 3, for: "OpenAI model training only" },
  { name: "ClaudeBot", what: "training", w: 2, for: "Anthropic model training only" },
  { name: "Google-Extended", what: "training", w: 1, for: "Gemini training only" },
];

// robots.txt as RFC 9309 reads it: consecutive User-agent lines share one group;
// a bot obeys its own group if there is one, otherwise the * group; the longest
// matching rule wins and Allow wins a tie; * matches anything and $ ends the path.
function parseRobots(txt) {
  const groups = [];
  let cur = null, lastWasAgent = false;
  for (const raw of txt.split(/\r?\n/)) {
    const m = raw.replace(/#.*$/, "").trim().match(/^([a-z-]+)\s*:\s*(.*)$/i);
    if (!m) continue;
    const key = m[1].toLowerCase(), val = m[2].trim();
    if (key === "user-agent") {
      if (!cur || !lastWasAgent) { cur = { agents: [], rules: [] }; groups.push(cur); }
      cur.agents.push(val.toLowerCase());
      lastWasAgent = true;
    } else {
      if (cur && (key === "allow" || key === "disallow") && val) cur.rules.push({ allow: key === "allow", path: val });
      lastWasAgent = false;
    }
  }
  return groups;
}
function robotsPathMatch(pattern, path) {
  const anchored = pattern.endsWith("$");
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const re = "^" + body.split("*").map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&")).join(".*") + (anchored ? "$" : "");
  return new RegExp(re).test(path);
}
function robotsAllows(groups, bot, path) {
  const b = bot.toLowerCase();
  let mine = groups.filter((g) => g.agents.some((a) => a === b || a.startsWith(b + "/")));
  if (!mine.length) mine = groups.filter((g) => g.agents.includes("*"));
  let best = null;
  for (const r of mine.flatMap((g) => g.rules)) {
    if (!robotsPathMatch(r.path, path)) continue;
    if (!best || r.path.length > best.path.length || (r.path.length === best.path.length && r.allow)) best = r;
  }
  return !best || best.allow;
}

const header = (h, name) => (!h ? null : typeof h.get === "function" ? h.get(name) : h[name] != null ? h[name] : h[name.toLowerCase()] != null ? h[name.toLowerCase()] : null);

// Same product? Shopify serves one product at /products/x and /collections/c/products/x,
// so compare the product handle when there is one, else the whole path.
function canonicalMatches(canonical, pageUrl) {
  try {
    const c = new URL(canonical, pageUrl), p = new URL(pageUrl);
    const handle = (u) => (u.pathname.match(/\/products\/([^/?#]+)/i) || [])[1];
    if (handle(c) || handle(p)) return !!handle(c) && !!handle(p) && handle(c).toLowerCase() === handle(p).toLowerCase();
    const norm = (u) => u.pathname.replace(/\/+$/, "").toLowerCase() || "/";
    return norm(c) === norm(p);
  } catch (_) { return false; }
}

// A bot told "go away" (or handed a much smaller page) where our browser-like read
// got the full page. The probe uses each bot's public user-agent name from our
// server, so it catches firewall and CDN rules keyed on the name; a CDN that checks
// the bot's network may still treat the bot itself differently.
function botsTurnedAway(botAccess, htmlBytes) {
  return Object.entries(botAccess).filter(([, r]) => r && (r.status >= 400 || (htmlBytes > 20000 && r.bytes < htmlBytes * 0.3))).map(([name]) => name);
}

function catCrawler({ robotsTxt, $, headers, pageUrl, sitemapListed, llmsTxt, botAccess, htmlBytes }) {
  let path = "/";
  try { path = new URL(pageUrl).pathname || "/"; } catch (_) {}
  const groups = robotsTxt != null ? parseRobots(robotsTxt) : [];
  const c = BOTS.map((b) => ({ id: "bot-" + b.name.toLowerCase(), label: `${b.name} can crawl`, ok: robotsAllows(groups, b.name, path), kind: "fact", w: b.w,
    issue: `robots.txt blocks ${b.name} from this page` + (b.what === "training" ? " (training only)" : "") }));

  const robotsMeta = $('meta[name="robots" i], meta[name="googlebot" i], meta[name="bingbot" i]').map((_, el) => $(el).attr("content") || "").get().join(",");
  const noindex = /\b(noindex|none)\b/i.test(robotsMeta) || /\b(noindex|none)\b/i.test(header(headers, "x-robots-tag") || "");
  c.push({ id: "indexable", label: "Page can be indexed (no noindex tag)", ok: !noindex, kind: "fact", w: 30,
    issue: "A noindex tag or header keeps this page out of search indexes" });

  const canonical = $('link[rel="canonical"]').attr("href");
  if (canonical) c.push({ id: "canonical-match", label: "Canonical tag points to this product", ok: canonicalMatches(canonical, pageUrl), kind: "fact", w: 14,
    issue: `The canonical tag points to ${canonical}, not this product` });
  if (sitemapListed != null) c.push({ id: "sitemap", label: "Listed in the store's sitemap", ok: sitemapListed, kind: "fact", w: 10,
    issue: "This product isn't in the store's sitemap" });
  if (botAccess) {
    const away = botsTurnedAway(botAccess, htmlBytes);
    c.push({ id: "bot-access", label: "AI bots get the same page shoppers get", ok: !away.length, kind: "fact", w: 12,
      issue: away.length ? `Your server turned away ${away.join(", ")} while letting a browser in` : null });
  }
  c.push({ id: "llms-txt", label: "llms.txt file (small bonus)", ok: !!(llmsTxt && llmsTxt.trim()), kind: "suggestion", w: 3, issue: "No llms.txt file" });

  const out = score("AI crawler access & indexing", c);
  out.robotsFound = robotsTxt != null;
  return out;
}

// ── The page's own product in its JSON-LD ────────────────────────────────────
// Top-level Product / ProductGroup nodes (the root, an @graph, or a WebPage's
// mainEntity) and their hasVariant children. Products nested anywhere else
// (related items, carousels) are other products. A block that isn't valid JSON is
// invisible to every engine, so those are counted too.
const isProductNode = (o) => !!o && typeof o === "object" && [].concat(o["@type"] || []).some((t) => /^(product|productgroup)$/i.test(String(t)));
const isAggregate = (o) => [].concat(o["@type"] || []).some((t) => /aggregateoffer/i.test(String(t)));
function productLd($) {
  const nodes = [];
  let blocks = 0, parseErrors = 0;
  $('script[type="application/ld+json"]').each((_, el) => {
    blocks++;
    let data;
    try { data = JSON.parse($(el).contents().text()); } catch (_) { parseErrors++; return; }
    const tops = [].concat(data).flatMap((d) => (d && d["@graph"] ? [].concat(d["@graph"]) : [d]));
    for (const t of tops) {
      if (isProductNode(t)) nodes.push(t);
      else if (t && isProductNode(t.mainEntity)) nodes.push(t.mainEntity);
    }
  });
  const variants = nodes.flatMap((n) => [].concat(n.hasVariant || []).filter(isProductNode));
  const offersOf = (n) => [].concat(n.offers || []).flatMap((o) => (o && o.offers ? [o].concat(o.offers) : [o])).filter((o) => o && typeof o === "object");
  const offers = nodes.concat(variants).flatMap(offersOf);
  return { nodes, variants, offers, blocks, parseErrors };
}
const offerPrice = (o) => num(o.price != null ? o.price : o.priceSpecification ? [].concat(o.priceSpecification)[0].price : null);
const brandName = (b) => (b == null ? null : typeof b === "string" ? b : [].concat(b)[0] && [].concat(b)[0].name != null ? String([].concat(b)[0].name) : null);
const ldGtins = (ldp) => ldp.nodes.concat(ldp.variants).flatMap((n) => ["gtin", "gtin8", "gtin12", "gtin13", "gtin14"].map((k) => n[k])).filter((g) => g != null && String(g).trim()).map(String);

// GTIN-8/12/13/14 with a correct check digit (OpenAI's product feed rejects the rest).
function gtinValid(code) {
  const s = String(code).replace(/[\s-]/g, "");
  if (!/^(\d{8}|\d{12}|\d{13}|\d{14})$/.test(s)) return false;
  const d = s.split("").map(Number), check = d.pop();
  const sum = d.reverse().reduce((t, n, i) => t + n * (i % 2 === 0 ? 3 : 1), 0);
  return (10 - (sum % 10)) % 10 === check;
}

// Does the markup tell the same story as the store? Compared against Shopify's live
// product data when there is some, else against the price and buy button a shopper
// sees (noisier, so those mismatches are suggestions). Then the variant data that
// Shopify Catalog and the AI shopping feeds read: SKUs, barcodes, option names,
// photos per color, and whether the markup lists every variant.
function catVariants($, ldp, shopify) {
  const c = [];
  const offers = ldp.offers.filter((o) => !isAggregate(o));
  const aggs = ldp.offers.filter(isAggregate);
  const prices = offers.map(offerPrice).filter((n) => n != null && n > 0);
  const cur = (offers[0] && offers[0].priceCurrency ? offers[0].priceCurrency + " " : "");
  const avails = ldp.offers.map((o) => normAvail(o.availability)).filter(Boolean);
  const vs = shopify ? shopify.variants : [];

  if (shopify && vs.some((v) => v.price != null) && (prices.length || aggs.length)) {
    const real = [...new Set(vs.filter((v) => v.price != null).map((v) => cents(v.price)))].sort((a, b) => a - b);
    const lo = real[0], hi = real[real.length - 1];
    const stray = prices.find((p) => !real.includes(cents(p)));
    const badRange = aggs.some((a) => (num(a.lowPrice) != null && cents(num(a.lowPrice)) < lo) || (num(a.highPrice) != null && cents(num(a.highPrice)) > hi));
    const realTxt = lo === hi ? cur + money(lo / 100) : `${cur}${money(lo / 100)} to ${money(hi / 100)}`;
    c.push({ id: "price-match", label: "Markup price matches the store's price", ok: stray == null && !badRange, kind: "fact", w: 22, impact: "high",
      issue: stray != null ? `The markup says ${cur}${money(stray)} but the store sells this product for ${realTxt}` : `The markup's price range doesn't match the store's ${realTxt}` });
  } else if (!shopify && prices.length) {
    const vp = visiblePrice($);
    if (vp != null) c.push({ id: "price-match", label: "Markup price matches the price shown", ok: prices.some((p) => cents(p) === cents(vp)), kind: "suggestion", w: 14,
      issue: `The markup says ${cur}${money(prices[0])} but the page shows ${money(vp)}` });
  }

  if (shopify && vs.some((v) => v.available != null) && avails.length) {
    const anyIn = vs.some((v) => v.available === true);
    const saysIn = avails.includes("InStock"), saysOut = avails.every((a) => a === "OutOfStock");
    c.push({ id: "stock-match", label: "Markup stock status matches the store", ok: !(saysIn && !anyIn) && !(saysOut && anyIn), kind: "fact", w: 20, impact: "high",
      issue: saysIn && !anyIn ? "The markup says in stock, but every variant is sold out in the store" : "The markup says sold out, but the store has variants in stock" });
  } else if (!shopify && avails.length) {
    const vis = visibleStock($);
    if (vis) c.push({ id: "stock-match", label: "Markup stock status matches the page", ok: vis === avails[0], kind: "fact", w: 14,
      issue: `The markup says ${avails[0]} but the page shows ${vis === "OutOfStock" ? "it sold out" : "an active buy button"}` });
  }

  if (shopify) {
    // A ProductGroup's own sku is usually its group code (often = productGroupID),
    // not a variant SKU, so only products, variants and offers are compared.
    const isGroup = (n) => [].concat(n["@type"] || []).some((t) => /^productgroup$/i.test(String(t)));
    const groupCodes = new Set(ldp.nodes.map((n) => n.productGroupID).filter(Boolean).map((s) => String(s).trim()));
    const realSkus = new Set(vs.map((v) => v.sku.trim()).filter(Boolean));
    const ldSkus = [...new Set(ldp.nodes.filter((n) => !isGroup(n)).concat(ldp.variants).map((n) => n.sku).concat(offers.map((o) => o.sku))
      .filter((s) => s != null && String(s).trim()).map((s) => String(s).trim()))].filter((s) => !groupCodes.has(s));
    if (realSkus.size && ldSkus.length) {
      const stray = ldSkus.filter((s) => !realSkus.has(s));
      c.push({ id: "sku-match", label: "Markup SKU is one of the store's SKUs", ok: !stray.length, kind: "fact", w: 10,
        issue: `The markup's SKU ${stray.slice(0, 3).join(", ")} isn't one of this product's SKUs in the store` });
    }
  }

  if (ldp.nodes.length) {
    const facts = ldp.nodes.map((n) => {
      const o = [].concat(n.offers || [])[0] || {};
      return { name: n.name, price: num(o.price != null ? o.price : o.lowPrice), availability: normAvail(o.availability), brand: brandName(n.brand), gtin: n.gtin || n.gtin13 || n.gtin12 || n.gtin8 || n.gtin14 || null };
    });
    const differ = ["name", "price", "availability", "brand", "gtin"].filter((k) => new Set(facts.map((f) => f[k]).filter((v) => v != null && v !== "").map((v) => String(v).toLowerCase().trim())).size > 1);
    c.push({ id: "one-product-block", label: "One consistent Product block", ok: !differ.length, kind: "fact", w: 14,
      issue: `This page has ${ldp.nodes.length} Product blocks that disagree on ${differ.join(", ")}` });
  }

  if (shopify) {
    const skus = vs.map((v) => v.sku.trim());
    const noSku = skus.filter((s) => !s).length;
    c.push({ id: "variant-skus", label: "Every variant has its own SKU", ok: !noSku && new Set(skus).size === skus.length, kind: "fact", w: 10,
      issue: noSku ? `${noSku} of ${vs.length} variants have no SKU` : "Some variants share the same SKU" });
    const noBarcode = vs.filter((v) => !v.barcode.trim()).length;
    c.push({ id: "variant-barcodes", label: "Every variant has a barcode (GTIN, UPC or EAN)", ok: !noBarcode, kind: "fact", w: 12,
      issue: `${noBarcode} of ${vs.length} variants have no barcode` });
  }

  const codes = [...new Set((shopify ? vs.map((v) => v.barcode.trim()) : []).concat(ldGtins(ldp)).filter(Boolean))];
  if (codes.length) {
    const bad = codes.filter((g) => !gtinValid(g));
    c.push({ id: "gtin-valid", label: "Barcodes are valid GTINs (check digit)", ok: !bad.length, kind: "fact", w: 10,
      issue: `These barcodes aren't valid GTINs: ${bad.slice(0, 3).join(", ")}${bad.length > 3 ? ` and ${bad.length - 3} more` : ""}` });
  }

  if (shopify) {
    const multi = vs.length > 1;
    const vague = shopify.options.filter((o) => /^(option|variant)\s*\d*$/i.test(o.name.trim()) || (multi && /^title$/i.test(o.name.trim())) ||
      o.values.some((v) => /^(style|type|option|variant|version|model|design)\s*[a-z0-9]{1,2}$/i.test(v.trim()) || (multi && /^default( title)?$/i.test(v.trim()))));
    c.push({ id: "option-names", label: "Option names and values say what changes", ok: !vague.length, kind: "fact", w: 8,
      issue: `The option ${vague.map((o) => `"${o.name}"`).join(", ")} doesn't say what changes between variants` });

    const idx = shopify.options.findIndex((o) => /colou?r|pattern|finish|print|shade|style/i.test(o.name) && o.values.length > 1);
    if (idx >= 0) {
      const missing = shopify.options[idx].values.filter((val) => !vs.some((v) => v.options[idx] === val && v.hasImage));
      c.push({ id: "variant-images", label: `Each ${shopify.options[idx].name.toLowerCase()} has its own photo`, ok: !missing.length, kind: "suggestion", w: 8,
        issue: `No photo is linked to ${missing.slice(0, 3).join(", ")}${missing.length > 3 ? ` and ${missing.length - 3} more` : ""}` });
    }

    if (multi && ldp.nodes.length) {
      const listed = Math.max(offers.length, ldp.variants.length, ...aggs.map((a) => parseInt(a.offerCount, 10) || 0));
      c.push({ id: "variants-in-markup", label: "Markup lists every variant", ok: listed >= vs.length, kind: "fact", w: 10,
        issue: `The markup lists ${listed} of ${vs.length} variants, so AI reads only part of what you sell` });
    }
  }

  // What Shopify's own readiness scanner asks of variant markup: a photo and the
  // option values on each hasVariant entry. Google also accepts variants that each
  // have a full page of their own, so these stay suggestions.
  if (ldp.variants.length >= 2) {
    const photos = new Set(ldp.variants.map((v) => JSON.stringify(v.image != null ? v.image : null)).filter((x) => x !== "null"));
    c.push({ id: "variant-markup-images", label: "Each variant in the markup has its own photo", ok: photos.size >= 2, kind: "suggestion", w: 6,
      issue: "The variants in the markup have no photos of their own" });
    // A variant name that adds the option to the product name ("Studio Bag - Denim",
    // the way Shopify's own structured_data filter writes it) counts too.
    const groupName = String(ldp.nodes[0].name || "").trim().toLowerCase();
    const namesOption = (v) => { const n = String(v.name || "").trim().toLowerCase(); return !!n && n !== groupName && (!groupName || n.length > groupName.length); };
    const bare = ldp.variants.filter((v) => !["color", "size", "material", "pattern", "additionalProperty"].some((k) => v[k] != null && v[k] !== "") && !namesOption(v)).length;
    c.push({ id: "variant-markup-options", label: "Each variant in the markup names its color, size or option", ok: !bare, kind: "suggestion", w: 6,
      issue: `${bare} of ${ldp.variants.length} variants in the markup don't say which color, size or option they are` });
  }
  return c.length ? score("Price, stock & variants", c) : null;
}

// ── What ChatGPT's product feed would get ───────────────────────────────────
// OpenAI's product feed spec (developers.openai.com/commerce/specs/feed) lists the
// fields ChatGPT uses to show and match a product. Shopify's Agentic Storefronts
// fills that feed from a store's product data; other stores send their own. This
// maps the page, its markup and its public product data onto those fields.
function feedCoverage({ ldp, sig, shopify, $, policies, pageUrl }) {
  const n = ldp.nodes[0] || {}, all = ldp.nodes.concat(ldp.variants), vs = shopify ? shopify.variants : [];
  const any = (k) => all.some((x) => x[k] != null && x[k] !== "");
  const fields = {
    required: {
      item_id: any("sku") || ldp.offers.some((o) => o.sku) || vs.some((v) => v.sku || v.id),
      title: !!n.name || !!(shopify && shopify.title),
      description: !!n.description || !!(shopify && shopify.descriptionHtml),
      url: !!pageUrl,
      brand: !!brandName(n.brand) || !!(shopify && shopify.vendor),
      seller_name: sig.hasOrganization || !!$('meta[property="og:site_name"]').attr("content"),
      image_url: any("image") || !!$('meta[property="og:image"]').attr("content"),
      availability: ldp.offers.some((o) => o.availability) || vs.some((v) => v.available != null),
      price: ldp.offers.some((o) => offerPrice(o) != null || o.lowPrice != null) || vs.some((v) => v.price != null),
    },
    optional: {
      gtin: ldGtins(ldp).some(gtinValid) || vs.some((v) => gtinValid(v.barcode)),
      mpn: any("mpn"),
      condition: ldp.offers.some((o) => o.itemCondition),
      product_category: any("category"),
      material: any("material"),
      color: any("color"),
      size: any("size"),
      "gender / age_group": any("audience") || any("suggestedGender") || any("suggestedAge"),
      dimensions: any("depth") || any("width") || any("height"),
      weight: any("weight"),
      additional_image_urls: all.some((x) => Array.isArray(x.image) && x.image.length > 1) || !!(shopify && shopify.imageCount > 1),
      "variants (group_id)": ldp.variants.length > 1 || ldp.nodes.some((x) => x.productGroupID || x.inProductGroupWithID),
      shipping: sig.hasShipping,
      "returns (accepts_returns)": sig.hasReturnPolicy,
      return_policy: !!(policies && pageExists(policies.returns)),
      "review_count / star_rating": sig.hasAggregateRating && sig.reviewCount > 0,
    },
  };
  const split = (o) => ({ found: Object.keys(o).filter((k) => o[k]), missing: Object.keys(o).filter((k) => !o[k]) });
  return { required: split(fields.required), optional: split(fields.optional) };
}

// Each category's share of the overall score, and its short tag on a finding.
const CATEGORY_WEIGHT = {
  "Product identity & data": 0.22, "Reviews & authority": 0.14, "Merchant trust signals": 0.14,
  "Buyer-question coverage": 0.12, "Price, stock & variants": 0.12, "Commercial data hygiene": 0.06,
  "AI crawler access & indexing": 0.14, "Agent buying path": 0.06,
};
const AREA = {
  "Product identity & data": "Identity", "Reviews & authority": "Reviews", "Merchant trust signals": "Trust",
  "Buyer-question coverage": "Buyer Qs", "Price, stock & variants": "Data match", "Commercial data hygiene": "Commercial",
  "AI crawler access & indexing": "Crawler", "Agent buying path": "Agent",
};

// Weighted category score from its checks.
function score(name, checks) {
  const total = checks.reduce((s, c) => s + c.w, 0) || 1;
  const got = checks.reduce((s, c) => s + (c.ok ? c.w : 0), 0);
  return { name, score: clamp((got / total) * 100), checks: checks.map(({ w, ...rest }) => rest) };
}

// ── Findings: turn failed checks into ranked issues with why + fix ───────────
// Keyed by check id. Bots get theirs from botAdvice() below.
const ADVICE = {
  "product-schema": { why: "Product schema is how AI shopping engines read what your item is, its price, and whether it's in stock. Without it, agents can't confidently recommend it.", fix: "Add Product JSON-LD on the page (name, image, description, brand, sku). Most modern themes and platforms output it, or a schema app can fill the gap." },
  "offer-price": { why: "AI agents only recommend products they can price. If price and currency aren't in structured data, your item gets skipped in AI shopping answers.", fix: "Include an Offer in your Product schema with price, priceCurrency, and availability so agents can read the price directly." },
  "availability": { why: "Agents avoid recommending items they can't confirm are in stock. Missing availability makes your product a risky pick they'll pass over.", fix: "Add availability (e.g. https://schema.org/InStock) to the Offer, and keep it synced with real stock so it never goes stale." },
  "brand": { why: "A clear brand entity helps AI match your product to brand-specific queries and trust it as a real listing.", fix: "Add a brand field to the Product schema with your brand name (and logo/URL via Organization)." },
  "identifier": { why: "Product identifiers let AI shopping engines match your item across the web and merge it into their product graph. Without one, your listing floats unmatched.", fix: "Add a GTIN (or MPN/SKU) to the Product schema. Retailers usually have the barcode; it's the single best matching signal." },
  "breadcrumb": { why: "Breadcrumb schema tells AI and search how the product sits in your catalog, which strengthens category and comparison matching.", fix: "Emit BreadcrumbList JSON-LD reflecting the product's category path. Most themes do this automatically." },
  "ld-valid": { why: "A JSON-LD block with a syntax error (a stray comma, an unescaped quote) is thrown away whole by Google, Bing and AI crawlers, so everything in it is invisible.", fix: "Run the page through Google's Rich Results Test or a JSON validator, find the broken block, and fix the app or theme snippet that writes it." },
  "product-image": { why: "Google's merchant listings require an image in the Product markup, and OpenAI's product feed requires one too. Without it, the product can't show as a shoppable result.", fix: "Add your main product photo's URL to the Product JSON-LD image field. Most themes do this; check the app or snippet that writes your product markup." },
  "name-length": { why: "OpenAI's feed and Google both cut product names at about 150 characters, so a longer name gets truncated, and an empty one leaves agents guessing.", fix: "Use the plain product name in the markup: brand, product type and the key detail, under 150 characters." },
  "schema-description": { why: "Agents quote the markup's description when they explain a product, and Shopify's own scanner asks for at least 20 words. A one-line description gives them nothing to say.", fix: "Put a real description (what it is, what it's made of, who it's for) in the Product JSON-LD description, 20 words or more." },
  "attrs-markup": { why: "Google lists color, size, material and pattern as recommended Product fields, and AI shopping answers filter on them (\"black, size M, cotton\").", fix: "Add color, size and material to the Product markup, or to each variant in a ProductGroup." },
  "single-offer": { why: "Google's merchant listings need an Offer with one price; an AggregateOffer (a price range) only qualifies for plain product snippets.", fix: "Output one Offer per variant, or a ProductGroup with a variant per option, instead of a single AggregateOffer." },
  "availability-value": { why: "Engines only understand the standard schema.org values. Free text like \"in stock\" or \"yes\" reads as missing.", fix: "Use https://schema.org/InStock, OutOfStock, PreOrder or BackOrder in the Offer's availability." },
  "price-valid": { why: "A priceValidUntil date in the past tells Google and AI feeds the price has expired, so the offer can be dropped.", fix: "Remove priceValidUntil, or set it to a future date and keep it current." },
  "item-condition": { why: "OpenAI's feed and Google both read item condition. It matters most when you sell used or refurbished items.", fix: "Add itemCondition (https://schema.org/NewCondition, UsedCondition or RefurbishedCondition) to the Offer." },
  "image-resolution": { why: "Google asks for product images of at least 50,000 pixels (width times height). Smaller photos can keep the product out of shopping results.", fix: "Upload a main photo of at least 800 × 800 pixels." },
  "image-count": { why: "Google recommends several photos, and OpenAI's feed has a field for extra images. More angles give agents and shoppers more to go on.", fix: "Add at least 3 photos: the product alone, in use, and a close-up or scale shot." },
  "rating-schema": { why: "Ratings are one of the strongest recommendation signals. AI agents lean toward products with visible, structured review data.", fix: "Use a reviews app (Judge.me, Loox, Yotpo) that renders visible stars and outputs AggregateRating schema." },
  "rating-backed": { why: "Your page has rating schema but no matching visible reviews, or a rating that can't be right. Google penalizes fake rating markup and AI engines distrust a listing whose stars don't match the page, so this can hurt more than having no rating at all.", fix: "Only output AggregateRating when you have real reviews shown on the page, and make the schema numbers match what shoppers see. Remove hardcoded or app-injected ratings that aren't tied to actual reviews." },
  "review-count": { why: "Review volume and text give agents the social proof they cite when recommending a product over a competitor's.", fix: "Collect and display reviews, and make sure the app writes reviewCount and Review nodes into structured data." },
  "organization": { why: "The store name tells agents who sells the product. OpenAI's feed requires a seller name, and Shopify's scanner looks for Organization or WebSite markup.", fix: "Add Organization (name, logo, url, sameAs) or WebSite markup with your store name. Most themes include it on every page." },
  "returns": { why: "Return terms are one of the first things shoppers ask an assistant about. Terms written on the product page or in the markup are what it can quote; a footer link to a policy page isn't.", fix: "State the return window on the product page (for example \"Free returns within 30 days\") and add hasMerchantReturnPolicy to the markup." },
  "shipping": { why: "Shoppers ask how long delivery takes and what it costs. \"Shipping calculated at checkout\" answers neither.", fix: "Show delivery time and cost near the buy button (for example \"Ships in 1-2 days, free over $50\") and add shippingDetails to the markup." },
  "returns-markup": { why: "Google reads return policy markup for merchant listings and recommends defining it once for the whole store under Organization.", fix: "Add a MerchantReturnPolicy (applicableCountry, returnPolicyCategory, merchantReturnDays) to your Organization markup or to the Offer." },
  "shipping-markup": { why: "Shipping details in the markup let Google and AI feeds show delivery cost and time without guessing.", fix: "Add shippingDetails (rate and delivery time) to the Offer, or a store-wide shipping policy to your Organization markup." },
  "warranty": { why: "A stated warranty or guarantee is a trust nudge that can tip an AI recommendation in your favor.", fix: "State any warranty or satisfaction guarantee on the product page. Even a short line helps." },
  "in-stock": { why: "Agents avoid recommending items they can't confirm are in stock. Missing availability makes your product a risky pick they'll pass over.", fix: "Add availability (e.g. https://schema.org/InStock) to the Offer, and keep it synced with real stock so it never goes stale." },
  "returns-page": { why: "Agents open your return policy to answer return questions, and OpenAI's feed asks for its link. A page that never says how many days a customer has can't answer the main question.", fix: "Put the return window in days near the top of your return policy (for example \"Return within 30 days of delivery\"). On Shopify: Settings, Policies." },
  "shipping-page": { why: "Agents read the shipping policy to answer \"how long will it take\" and \"how much is shipping\". Without times or costs it can't answer either.", fix: "List delivery times and costs for your main regions in the shipping policy. On Shopify: Settings, Policies." },
  "legal-pages": { why: "Checkout inside ChatGPT requires links to the seller's privacy policy and terms of service.", fix: "Publish a privacy policy and terms of service (on Shopify: Settings, Policies) and link both in your footer." },
  "attr-size": { why: "\"Will it fit?\" and \"How big is it?\" are among the most common questions shoppers ask an assistant, and most stores leave dimensions out.", fix: "Add dimensions, weight or capacity to the description or a specs table, with units (cm, in, kg, ml)." },
  "attr-materials": { why: "Shoppers ask what a product is made of, and AI filters on it. When the page doesn't say, the assistant picks a product that does.", fix: "Name the materials or ingredients in the description or specs (for example \"100% organic cotton\")." },
  "attr-care": { why: "Care and how-to-use details answer the follow-up questions that decide a purchase, and they're the kind of specific fact an assistant quotes.", fix: "Add care instructions or directions for use to the product page." },
  "attr-fit": { why: "Fit and compatibility (\"true to size\", \"fits iPhone 15\") answer the will-it-work question that stops many purchases.", fix: "Say how it fits or what it works with, and link a size chart from the product page." },
  "specs": { why: "Agents answer buyer questions like size, material, and compatibility from your specs. If they're not on the page, your product can't satisfy those queries.", fix: "Add a specs table or attribute list (size, material, dimensions, compatibility) so buyer questions are answered on-page." },
  "faq": { why: "FAQ content directly answers the questions that trigger AI recommendations. It's some of the most citable text on a product page.", fix: "Add a short product FAQ answering the top buyer questions, and mark it up with FAQPage schema." },
  "description": { why: "A thin description gives AI little to work with. Rich, specific copy is what agents quote when they recommend you.", fix: "Expand the product description with specific detail. Aim for a few real paragraphs, not one line." },
  "price-match": { why: "When the markup and the store disagree on price, Google treats it as misrepresentation and an agent can quote the wrong price, so it drops the product or the order fails.", fix: "Make the markup read the live variant price. If an app or a hard-coded snippet writes the price, update or remove it." },
  "stock-match": { why: "Agents won't recommend a product that might be sold out, and markup that says \"in stock\" for a sold-out item gets flagged by Google.", fix: "Make the markup's availability follow real stock for each variant. An inventory app that keeps stock accurate fixes this at the source." },
  "sku-match": { why: "A SKU in the markup that the store doesn't have breaks the link between your page, your feed and your inventory, so engines can't tie them together.", fix: "Make the markup use each variant's real SKU. Old SKUs usually come from a hard-coded snippet or an app's cached data." },
  "one-product-block": { why: "When a theme and an app each write their own Product block and they disagree, engines can't tell which is true.", fix: "Keep one Product source (usually the theme's) and turn off Product markup in the other app or snippet." },
  "variant-skus": { why: "Shopify Catalog and AI feeds track each variant by its SKU. A missing or shared SKU merges or drops variants.", fix: "Give every variant its own SKU in the product's Variants section." },
  "variant-barcodes": { why: "A barcode (GTIN, UPC or EAN) is the strongest way for Google, OpenAI's feed and Shopify Catalog to match your product to the same item elsewhere.", fix: "Add the barcode for every variant in the product's Variants section. If you make the product yourself, you can get GTINs from GS1." },
  "gtin-valid": { why: "OpenAI's feed requires a GTIN of 8, 12, 13 or 14 digits with a valid check digit. A made-up or mistyped barcode is rejected or matched to the wrong product.", fix: "Replace invalid barcodes with the correct GTIN from the packaging or your supplier, or leave the field empty if the product has none." },
  "option-names": { why: "An option called \"Option 1\" with values like \"Style A\" tells AI nothing about what differs between variants, so it can't match a shopper asking for a color or size.", fix: "Rename options for what changes (Color, Size, Material) and use real values (Black, Medium, Oak)." },
  "variant-images": { why: "When a shopper asks for the red one, the agent needs a red photo to show. Shopify's own scanner checks for a photo per variant.", fix: "Assign a photo to every color or style variant in the product's Variants section." },
  "variants-in-markup": { why: "If the markup lists one offer for a product with several variants, AI sees one size or color and misses the rest.", fix: "Output a ProductGroup with a variant for each option, or one Offer per variant with its own price, SKU and availability." },
  "price-currency": { why: "AI agents only recommend products they can price. If price and currency aren't in structured data, your item gets skipped in AI shopping answers.", fix: "Include an Offer in your Product schema with price, priceCurrency, and availability so agents can read the price directly." },
  "canonical": { why: "Without a canonical URL, AI and search can split signals across duplicate product URLs and cite the wrong one.", fix: "Add a self-referencing canonical link on each product URL so duplicate/variant URLs don't split signals." },
  "og-type": { why: "Marking the page as a product with og:type helps some engines classify it correctly as a shoppable item.", fix: 'Add <meta property="og:type" content="product"> to the page head.' },
  "og-image": { why: "Open Graph tags control how your product looks when shared and previewed, including inside some AI surfaces.", fix: "Add an og:image (1200×630) so the product previews well when shared." },
  "og-title": { why: "Open Graph tags control how your product looks when shared and previewed, including inside some AI surfaces.", fix: "Set a clear og:title/page title with the product name and brand." },
  "title-length": { why: "The page title is the headline in search results and many AI answers. Shopify's scanner looks for 30 to 60 characters: long enough to describe the product, short enough not to be cut.", fix: "Write a title with the product name, type and brand, 30 to 60 characters." },
  "indexable": { why: "A noindex tag or header keeps the page out of Google's and Bing's indexes, and ChatGPT search, Copilot and Google's AI answers draw on those indexes.", fix: "Remove the noindex from this page (check your theme and any SEO app) unless you mean to hide the product." },
  "canonical-match": { why: "A canonical tag that points to another URL tells engines this page is a copy, so they index and cite the other one.", fix: "Make the canonical tag point to this product's own URL. On Shopify, check theme edits and SEO apps that rewrite it." },
  "sitemap": { why: "Search engines and AI crawlers find products through the sitemap. Shopify lists every published product automatically, so a missing one is usually not published to the Online Store.", fix: "Check the product is active and published to the Online Store sales channel." },
  "bot-access": { why: "robots.txt says what bots may read, but a firewall or CDN can still turn them away; Cloudflare blocks AI bots by default on new sites since July 2025. We sent requests using each bot's public name. Real bots come from their own networks and may be treated differently, so confirm in your settings.", fix: "In your CDN or firewall (for example Cloudflare's AI Crawl Control), allow the AI search and assistant bots you want: OAI-SearchBot, ChatGPT-User, PerplexityBot, Claude-SearchBot." },
  "llms-txt": { why: "Shopify's scanner and Google's Lighthouse check for an llms.txt file, but no AI search engine has said it uses one. Treat it as a small bonus.", fix: "Add /llms.txt: a short Markdown file with your store name, what you sell, and links to your main collections and policies." },
  "buy-button": { why: "Agents that read the page without running scripts can't see a button that JavaScript draws, and agents that do run scripts find a plain, named button faster. Shopify's standard product form puts the button in the HTML.", fix: "Render the Add to cart button in the page HTML (the theme's standard product form does this), and give an icon-only button an aria-label." },
  "description-in-html": { why: "Your store's product description isn't in the page HTML, so a script loads it. Crawlers that don't run scripts, which is most AI crawlers, see a product with no description.", fix: "Render the description in the theme's product template (the standard product description block) instead of loading it with an app or script." },
  "variant-markup-images": { why: "Shopify's own readiness scanner checks for a photo on each variant in the markup. With one, an agent can show the exact color a shopper asked for without opening another page.", fix: "Add an image to each hasVariant entry in your ProductGroup markup." },
  "variant-markup-options": { why: "Variants in the markup that don't say their color or size make AI open each variant page to learn what it is. Shopify's scanner checks for option values; Google also accepts variants that each have a full page of their own.", fix: "Give each hasVariant entry its option values (color, size, material) and list them in the group's variesBy." },
  "labeled-options": { why: "Agents choose size and color through form labels. An unlabeled select or swatch is a field they can't identify; Google Lighthouse's Agentic Browsing audit flags the same thing.", fix: "Give every option and quantity field a <label>, or an aria-label on swatches." },
  "buy-form": { why: "A buy button inside a form that posts to the cart keeps working when an agent's browser doesn't run your scripts. A button that only works through JavaScript can fail for agents.", fix: "Keep the theme's standard product form (form action=\"/cart/add\" with the variant id) rather than a script-only button." },
};
ADVICE["currency"] = ADVICE["offer-price"];
ADVICE["visible-ratings"] = ADVICE["rating-schema"];
ADVICE["review-schema"] = ADVICE["review-count"];

function botAdvice(id) {
  const b = BOTS.find((x) => "bot-" + x.name.toLowerCase() === id);
  if (!b) return null;
  if (b.what === "training") return {
    why: `${b.name} collects pages for ${b.for.replace(/ only$/, "")}. Blocking it only stops training; it doesn't hide the product from AI search or shopping answers.`,
    fix: "Nothing to change for AI shopping. Allow it only if you want your pages used for model training.",
  };
  if (b.what === "user") return {
    why: `${b.name} is used for ${b.for}. Blocked, the assistant may not be able to read this product while it helps a shopper.`,
    fix: `Remove the robots.txt rule that blocks ${b.name} on product pages.`,
  };
  return {
    why: `${b.name} builds the index for ${b.for}. Blocked in robots.txt, this product can't show up there.`,
    fix: `Remove the robots.txt rule that blocks ${b.name} on product pages (on Shopify, edit robots.txt.liquid in your theme).`,
  };
}
const adviceFor = (id) => ADVICE[id] || botAdvice(id) || {};

// Impact tiers (high = blocks the recommendation outright; medium = weakens it).
const HIGH = new Set(["product-schema", "offer-price", "currency", "price-currency", "availability", "identifier", "product-image", "rating-schema", "rating-backed", "indexable", "bot-googlebot", "bot-bingbot", "bot-oai-searchbot", "bot-perplexitybot"]);
const LOW = new Set(["breadcrumb", "warranty", "og-type", "llms-txt", "item-condition", "image-count", "bot-gptbot", "bot-claudebot", "bot-google-extended", "bot-applebot"]);
function impactFor(id, kind) {
  let imp = HIGH.has(id) ? "high" : LOW.has(id) ? "low" : "medium";
  if (kind === "suggestion" && imp === "high") imp = "medium"; // a suggestion never outranks a measured blocker
  return imp;
}
// The core schema gaps that get the paste-ready JSON-LD snippet.
const SNIPPET_IDS = new Set(["product-schema", "offer-price", "currency", "price-currency", "availability", "identifier", "brand", "product-image"]);
const IMPACT_RANK = { high: 0, medium: 1, low: 2 };

// App funnel — lead with the Shopify apps, tie each to a detected gap.
function recommendApps(cats, sig) {
  const apps = [];
  const by = {}; cats.forEach((c) => (by[c.name] = c));
  const failed = (name, label) => { const c = by[name]; return c && c.checks.some((x) => x.label === label && !x.ok); };
  if (failed("Reviews & authority", "AggregateRating schema (star ratings)") || failed("Reviews & authority", "Visible ratings on the page")) {
    apps.push({ app: "PopBoost", icon: "/icons/popboost.webp", why: "adds visible social proof and review/rating widgets, a top AI recommendation signal", url: "/popboost" });
  }
  if (!sig.hasOffer || failed("Product identity & data", "Offer with price")) {
    apps.push({ app: "EZBundle", icon: "/icons/ezbundle.webp", why: "builds offers and bundles with clean pricing that AI shopping can read", url: "/ezbundle" });
  }
  // EZStock always — accurate inventory/availability is exactly what agents need.
  apps.push({ app: "EZStock", icon: "/icons/ezstock.webp", why: "keeps stock and availability accurate so your in-stock signal never goes stale for AI", url: "/ezstock" });
  // Quizzo for discovery/attributes.
  apps.push({ app: "Quizzo", icon: "/icons/quizzo.webp", why: "a product quiz that surfaces attributes and recommends the right item to buyers", url: "/quizzo" });
  return apps;
}

// ── Upgrade A: SSR-vs-client rendering probe ─────────────────────────────────
// Many stores render Product JSON-LD in the browser with JavaScript, so it's
// absent from the raw HTML an AI crawler reads (most AI shopping crawlers don't
// run JS). We detect that WITHOUT headless Chrome: for Shopify, `<product>.json`
// returns the product object with no rendering; as a fallback we look for OG
// product tags / microdata that some stores inject even when JSON-LD is JS-only.
// Returns ground-truth data (title/price/availability/sku) when reachable, so we
// can (a) report the client-rendered finding and (b) pre-fill the fix kit.
// Shopify's public product data in one shape, whether it came from <product>.js (prices
// in cents, live stock per variant) or <product>.json (prices as text, currency, no
// stock). Every variant is kept: the variant checks compare each one to the markup.
function normalizeShopify(p, source) {
  if (!p || !p.title || !Array.isArray(p.variants) || !p.variants.length) return null;
  const isJs = source === "shopify-js";
  const price = (v) => (v == null || v === "" ? null : isJs ? Number(v) / 100 : parseFloat(v));
  const images = isJs ? (p.media || []).filter((m) => m && (m.media_type === "image" || m.width)) : (p.images || []);
  return {
    source, id: p.id, handle: p.handle, title: p.title, vendor: p.vendor || null, type: p.type || p.product_type || null,
    descriptionHtml: p.description || p.body_html || "",
    currency: p.variants[0].price_currency || null,
    options: (p.options || []).map((o) => (typeof o === "string" ? { name: o, values: [] } : { name: String(o.name || ""), values: (o.values || []).map(String) })),
    variants: p.variants.map((v) => ({
      id: v.id, title: v.title || v.public_title || "", sku: String(v.sku || ""), barcode: String(v.barcode || ""),
      price: price(v.price), available: typeof v.available === "boolean" ? v.available : null,
      requiresShipping: v.requires_shipping !== false,
      hasImage: isJs ? !!v.featured_image : v.image_id != null,
      options: [v.option1, v.option2, v.option3].filter((x) => x != null).map(String),
    })),
    imageCount: images.length,
    mainImage: images[0] ? { width: images[0].width || null, height: images[0].height || null } : null,
  };
}

// The network half: Shopify's product endpoints, or null on a non-Shopify page.
async function fetchShopifyProduct(url) {
  let base = null;
  try {
    const u = new URL(url); u.hash = ""; u.search = "";
    if (/\/products\/[^/]+$/i.test(u.pathname)) base = u.origin + u.pathname.replace(/\/$/, "");
  } catch (_) {}
  if (!base) return null;
  for (const [ext, source] of [[".js", "shopify-js"], [".json", "shopify-json"]]) {
    try {
      await validateUrl(base + ext); // SSRF guard on the probe target too
      const r = await fetch(base + ext, { redirect: "follow", signal: AbortSignal.timeout(8000), headers: { "User-Agent": "Mozilla/5.0", "Accept": "application/json" } });
      if (!r.ok) continue;
      const j = JSON.parse(await r.text());
      const p = normalizeShopify(source === "shopify-js" ? j : j && j.product, source);
      if (p) return p;
    } catch (_) { /* blocked or unreachable → try the next endpoint */ }
  }
  return null;
}

function probeStructuredData($, schemaInRawHtml, shopify) {
  const out = { schemaInRawHtml, dataViaEndpoint: false, clientRendered: false, source: null, data: null };

  // OG / microdata already in the raw HTML (server-rendered even without JSON-LD).
  const ogPrice = $('meta[property="product:price:amount"]').attr("content") || $('meta[property="og:price:amount"]').attr("content");
  const ogTitle = $('meta[property="og:title"]').attr("content");
  const microPrice = $('[itemprop="price"]').attr("content") || $('[itemprop="price"]').first().text();
  const hasOgProductData = !!(ogPrice || microPrice);

  if (shopify) {
    const v = shopify.variants[0];
    out.dataViaEndpoint = true; out.source = shopify.source;
    out.data = { title: shopify.title, price: v.price != null ? money(v.price) : null, currency: shopify.currency, available: v.available, sku: v.sku || null, vendor: shopify.vendor };
  }

  if (!out.dataViaEndpoint && hasOgProductData) {
    out.dataViaEndpoint = true; out.source = "og-microdata";
    out.data = { title: ogTitle || null, price: (ogPrice || microPrice || "").toString().trim() || null, currency: $('meta[property="product:price:currency"]').attr("content") || $('meta[property="og:price:currency"]').attr("content") || null, available: null, sku: null, vendor: null };
  }

  // Client-rendered = the machine-readable Product schema wasn't in the raw HTML,
  // but the product data IS reachable another way → it's injected by JS.
  out.clientRendered = !schemaInRawHtml && out.dataViaEndpoint;
  return out;
}

// ── Upgrade B: paste-ready JSON-LD fix kit ───────────────────────────────────
// Build a minimal valid Product + Offer JSON-LD from whatever we could discover
// (raw-HTML OG tags, the .json endpoint, <title>, canonical). Real values where
// known; a clearly-marked "REPLACE_ME" where not. Zero tokens — pure templating.
// Reject junk titles from bot-challenge / error pages so we never pre-fill the
// snippet with "Just a moment..." or "404 Not Found".
const BAD_TITLE = /^(just a moment|attention required|access denied|403 forbidden|404|not found|error|please wait|checking your browser|are you a robot|site maintenance)/i;
function cleanTitle(t) { t = (t || "").trim(); return t && !BAD_TITLE.test(t) ? t : null; }

function buildFixKit(url, $, sig, endpointData) {
  const d = endpointData || {};
  const title = cleanTitle(d.title) || cleanTitle($('meta[property="og:title"]').attr("content")) || cleanTitle($("title").first().text()) || "REPLACE_ME product name";
  const canonical = $('link[rel="canonical"]').attr("href") || url;
  const img = $('meta[property="og:image"]').attr("content") || "REPLACE_ME https://.../image.jpg";
  const price = d.price || "REPLACE_ME e.g. 19.99";
  const currency = d.currency || "USD";
  const avail = d.available === false ? "https://schema.org/OutOfStock" : "https://schema.org/InStock";
  const sku = d.sku || "REPLACE_ME your SKU";
  const brand = d.vendor || "REPLACE_ME your brand";
  const obj = {
    "@context": "https://schema.org",
    "@type": "Product",
    name: title,
    image: img,
    description: "REPLACE_ME a specific, benefit-led product description",
    sku: sku,
    gtin: "REPLACE_ME your GTIN/UPC/EAN barcode",
    brand: { "@type": "Brand", name: brand },
    offers: {
      "@type": "Offer",
      url: canonical,
      price: price,
      priceCurrency: currency,
      availability: avail,
      itemCondition: "https://schema.org/NewCondition",
    },
  };
  return JSON.stringify(obj, null, 2);
}

// ── Orchestrator ─────────────────────────────────────────────────────────────
// analyze() is the no-network core: everything checkProduct fetched goes in, the
// report comes out. The tests feed it hand-made pages.
function analyze({ url, finalUrl, html, headers, robotsTxt, shopify, sitemapListed, llmsTxt, botAccess, policies, now }) {
  const today = (now || new Date()).toISOString().slice(0, 10);
  const $ = cheerio.load(html);
  const text = $("body").text().replace(/\s+/g, " ").toLowerCase();

  const { types, sig } = readJsonLd($);
  const isProductPage = looksLikeProductPage(url, $, sig);

  // Upgrade A: probe for client-rendered product data (no headless Chrome).
  const rendering = probeStructuredData($, sig.hasProduct, shopify);
  // If data is only reachable via the endpoint (client-rendered), lift the
  // identity signals from ground truth so we don't false-zero a well-built store —
  // the schema exists, it's just JS-injected. The client-rendered FINDING (added
  // below) is where we flag that it's invisible to AI crawlers.
  if (rendering.clientRendered && rendering.data) {
    if (rendering.data.price != null) { sig.hasPrice = true; sig.hasOffer = true; }
    if (rendering.data.available != null) sig.hasAvailability = true;
    if (rendering.data.sku) sig.hasIdentifier = true;
    if (rendering.data.vendor) sig.hasBrand = true;
  }

  const body = visibleBody($);
  const bodyText = body.text().replace(/\s+/g, " ").toLowerCase();

  const area = productArea(body);
  const areaText = area.text().replace(/\s+/g, " ").toLowerCase();

  const ldp = productLd($);
  const identity = catIdentity(sig, $, ldp, shopify, today);
  const reviews = catReviews(sig, body, bodyText);
  const digital = isDigital(shopify, types, areaText);
  const trust = catTrust(sig, areaText, policies, digital);
  const buyerQ = catBuyerQ(sig, $, area, areaText, ldp, shopify, bodyText, digital);
  const variants = catVariants($, ldp, shopify);
  const agent = catAgent($, area);
  const commercial = catCommercial(url, $, sig);
  const crawler = catCrawler({ robotsTxt, $, headers, pageUrl: finalUrl || url, sitemapListed, llmsTxt, botAccess, htmlBytes: html.length });

  // A category with nothing to compare (no Shopify data and no price shown) is left
  // out, and the other weights scale up to fill its share.
  const categories = [identity, reviews, trust, buyerQ, variants, commercial, crawler, agent].filter(Boolean);

  // Overall = weighted blend (identity/reviews/crawler-access matter most for a rec).
  const wsum = categories.reduce((s, c) => s + CATEGORY_WEIGHT[c.name], 0);
  const overall = clamp(categories.reduce((s, c) => s + c.score * CATEGORY_WEIGHT[c.name], 0) / wsum);

  // Upgrade A: the client-rendered finding — the single most decisive AI-readiness
  // signal. Product data exists but only after JS runs, so a non-JS AI crawler
  // sees an empty page. Prepended as a high-impact fact with a paste-ready fix.
  const fixKit = buildFixKit(url, $, sig, rendering.data);
  const renderingIssues = [];
  if (rendering.clientRendered) {
    renderingIssues.push({
      area: "Rendering", kind: "fact", impact: "high", impactRank: IMPACT_RANK.high,
      text: "Product data loads with JavaScript, so it's not in the HTML an AI crawler reads",
      why: "We found your product data through the store's data endpoint but not in the raw HTML, which means it's rendered in the browser with JavaScript. Most AI shopping crawlers don't run JavaScript, so they see an empty page and can't recommend the product.",
      fix: "Output Product and Offer JSON-LD in the server-rendered HTML (not injected client-side). Paste this as a starting point and fill in the REPLACE_ME values:",
      snippet: fixKit,
    });
  } else if (!sig.hasProduct && !rendering.dataViaEndpoint) {
    // Honest couldn't-read state — never silently score 0.
    renderingIssues.push({
      area: "Rendering", kind: "fact", impact: "high", impactRank: IMPACT_RANK.high,
      text: "We couldn't read product data from this page at all",
      why: "There's no Product schema in the HTML and no readable product data endpoint. The page may be fully client-rendered or blocking automated reads. This is also how a non-JavaScript AI crawler sees you: with nothing to recommend.",
      fix: "Serve Product and Offer JSON-LD in the initial HTML response. Paste this as a starting point:",
      snippet: fixKit,
    });
  }

  // Findings from every FAILED check across categories.
  const issues = [];
  for (const cat of categories) {
    for (const chk of cat.checks) {
      if (chk.ok) continue;
      const kind = chk.kind || "fact";
      const impact = chk.impact || impactFor(chk.id, kind);
      const advice = adviceFor(chk.id);
      const iss = {
        area: AREA[cat.name] || cat.name,
        text: chk.issue || chk.label + ": not detected",
        kind, impact, impactRank: IMPACT_RANK[impact],
        why: advice.why || null, fix: advice.fix || null,
      };
      // Attach the paste-ready snippet to the core schema/offer gaps where it helps.
      if (SNIPPET_IDS.has(chk.id)) iss.snippet = fixKit;
      issues.push(iss);
    }
  }
  // Informational notes, never scored. (1) The two kinds of sources AI shopping
  // uses: feeds and the live page. This tool reads the page; it can't see a feed.
  const infoIssues = [{
    area: "Coverage", kind: "suggestion", impact: "medium", impactRank: IMPACT_RANK.medium,
    text: "AI shopping reads feeds and the live page. This checks the page",
    why: "ChatGPT gets products from merchant feeds (Shopify's Agentic Storefronts sends one for Shopify stores) and from search indexes such as Bing's. Google AI Mode and Gemini use Google Merchant Center and Google's index, Copilot uses Microsoft Merchant Center and Bing, and Perplexity crawls pages. This tool reads the live page the way the crawlers do. A strong page can still be missing from a feed.",
    fix: "Keep your feeds on (Google Merchant Center, Microsoft Merchant Center, and Agentic Storefronts on Shopify) and keep each feed's price, stock, GTIN and title the same as the page. A mismatch drops the product from the feed even when the page is perfect.",
  }];
  // (2) What ChatGPT's product feed would get from this page.
  const feed = feedCoverage({ ldp, sig, shopify, $, policies, pageUrl: finalUrl || url });
  const reqTotal = feed.required.found.length + feed.required.missing.length, optTotal = feed.optional.found.length + feed.optional.missing.length;
  const feedImpact = feed.required.missing.length ? "medium" : "low";
  infoIssues.push({
    area: "ChatGPT feed", kind: "suggestion", impact: feedImpact, impactRank: IMPACT_RANK[feedImpact],
    text: `ChatGPT's product feed: this page fills ${feed.required.found.length} of ${reqTotal} required fields and ${feed.optional.found.length} of ${optTotal} optional ones`,
    why: "OpenAI's product feed spec lists the fields ChatGPT uses to show and match a product: 9 required (ID, title, description, link, brand, seller, image, availability, price) and optional ones such as GTIN, material, color, size, dimensions, return window and ratings. On Shopify, Agentic Storefronts builds this feed from your product data; other stores send their own. Either way, these are the facts ChatGPT has about the product.",
    fix: (feed.required.missing.length ? `Missing required fields: ${feed.required.missing.join(", ")}. ` : "") +
      (feed.optional.missing.length ? `Fields you could add: ${feed.optional.missing.join(", ")}. Put them in the product markup and, on Shopify, in the product's category attributes and metafields.` : "Every optional field we can see is filled in."),
  });
  // (3) Shopify stores: the admin data no product page shows.
  if (shopify) infoIssues.push({
    area: "Shopify admin", kind: "suggestion", impact: "medium", impactRank: IMPACT_RANK.medium,
    text: "Check these in your Shopify admin: a product page can't show them",
    why: "Shopify Catalog, which sends your products to AI channels such as ChatGPT, Gemini, Copilot and Perplexity through Agentic Storefronts, reads your product data in the admin. Shopify says it groups products by standard attributes and metafields, so an empty category attribute is a fact AI never gets.",
    fix: "Set a specific product category, then fill in every attribute it opens (color, material, size, age group, target gender). Name each option for what changes (Color, Size) with real values. Give every variant its own SKU, barcode, price and stock. Check that the AI channels are on in Agentic Storefronts. Add your policies and FAQs to Shopify's Knowledge Base app so agents can answer questions about returns and shipping.",
  });

  const allIssues = renderingIssues.concat(issues).concat(infoIssues);
  allIssues.sort((a, b) => a.impactRank - b.impactRank || (a.kind === b.kind ? 0 : a.kind === "fact" ? -1 : 1));

  return {
    ok: true,
    url,
    finalUrl: finalUrl || url,
    isProductPage,
    overall,
    categories,
    issues: allIssues,
    recommendedApps: recommendApps(categories, sig),
    feed,
    schemaTypes: types,
    robotsFound: crawler.robotsFound,
    rendering: { schemaInRawHtml: rendering.schemaInRawHtml, dataViaEndpoint: rendering.dataViaEndpoint, clientRendered: rendering.clientRendered, source: rendering.source },
  };
}

// ── The network half: everything analyze() needs beyond the page itself ─────
// Each fetch is SSRF-guarded, time-limited and size-capped, and a failure only
// means that check is left out (or reads as "not found"), never a crash.
async function getText(u, { cap = 3e6, timeout = 8000, ua = "Mozilla/5.0" } = {}) {
  await validateUrl(u);
  const r = await fetch(u, { redirect: "follow", signal: AbortSignal.timeout(timeout), headers: { "User-Agent": ua } });
  if (+r.headers.get("content-length") > cap) return { status: r.status, type: r.headers.get("content-type") || "", text: "" };
  const text = await r.text();
  return { status: r.status, type: r.headers.get("content-type") || "", text: text.length > cap ? text.slice(0, cap) : text };
}

// Shopify's sitemap index splits products into files by product ID (?from=&to=), so
// one file holds this product. Locale copies (/fr/...) are skipped.
function pickProductSitemap(indexXml, productId) {
  const locs = [...indexXml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1].replace(/&amp;/g, "&"))
    .filter((l) => { try { return /^\/sitemap_products_\d+\.xml$/i.test(new URL(l).pathname); } catch (_) { return false; } });
  const inRange = locs.find((l) => { const q = new URL(l).searchParams, from = +q.get("from"), to = +q.get("to"); return from && to && productId >= from && productId <= to; });
  return inRange || (locs.length === 1 ? locs[0] : null);
}
const listedInSitemap = (xml, handle) => xml.includes(`/products/${handle}</loc>`);
async function fetchSitemapListed(pageUrl, shopify) {
  if (!shopify || !shopify.handle || !shopify.id) return null;
  try {
    const index = await getText(new URL("/sitemap.xml", pageUrl).toString(), { cap: 2e6 });
    const file = index.status === 200 && pickProductSitemap(index.text, shopify.id);
    if (!file) return null;
    const xml = await getText(file, { cap: 12e6 });
    return xml.status === 200 && xml.text ? listedInSitemap(xml.text, shopify.handle) : null;
  } catch (_) { return null; }
}

async function fetchLlmsTxt(pageUrl) {
  try {
    const r = await getText(new URL("/llms.txt", pageUrl).toString(), { cap: 5e5, timeout: 6000 });
    return r.status === 200 && !/html/i.test(r.type) ? r.text : null; // a soft-404 HTML page isn't an llms.txt
  } catch (_) { return null; }
}

// The bots that decide AI search and assistant visits, by the user-agent names their
// companies publish. Training-only bots aren't probed: blocking them is a choice.
const PROBE_UA = {
  "OAI-SearchBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; OAI-SearchBot/1.3; +https://openai.com/searchbot",
  "ChatGPT-User": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko); compatible; ChatGPT-User/1.0; +https://openai.com/bot",
  PerplexityBot: "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; PerplexityBot/1.0; +https://perplexity.ai/perplexitybot)",
  "Claude-SearchBot": "Mozilla/5.0 AppleWebKit/537.36 (KHTML, like Gecko; compatible; Claude-SearchBot/1.0; +https://www.anthropic.com)",
};
async function probeBots(pageUrl) {
  const out = {};
  await Promise.all(Object.entries(PROBE_UA).map(async ([name, ua]) => {
    try { const r = await getText(pageUrl, { ua, timeout: 8000 }); out[name] = { status: r.status, bytes: r.text.length }; }
    catch (_) { /* a timeout says nothing about blocking */ }
  }));
  return Object.keys(out).length ? out : null;
}

// Policy pages: Shopify's fixed /policies/ paths, or same-site links on the page.
const SHOPIFY_POLICY = { returns: "/policies/refund-policy", shipping: "/policies/shipping-policy", privacy: "/policies/privacy-policy", terms: "/policies/terms-of-service" };
const POLICY_LINK = { returns: /refund|return/i, shipping: /shipping|delivery/i, privacy: /privacy/i, terms: /terms/i };
function policyLinks($, pageUrl) {
  const origin = new URL(pageUrl).origin, found = {};
  $("a[href]").each((_, a) => {
    const href = $(a).attr("href"), label = $(a).text() + " " + href;
    for (const [k, re] of Object.entries(POLICY_LINK)) {
      if (found[k] || !re.test(label)) continue;
      try { const u = new URL(href, pageUrl); if (u.origin === origin) { found[k] = u.toString(); break; } } catch (_) {}
    }
  });
  return found;
}
async function fetchPolicies(pageUrl, $, isShopify) {
  const origin = new URL(pageUrl).origin;
  const targets = isShopify ? Object.fromEntries(Object.entries(SHOPIFY_POLICY).map(([k, p]) => [k, origin + p])) : policyLinks($, pageUrl);
  if (!Object.keys(targets).length) return null;
  const out = {};
  await Promise.all(Object.keys(SHOPIFY_POLICY).map(async (k) => {
    if (!targets[k]) { out[k] = { status: 404, text: "" }; return; }
    try {
      const r = await getText(targets[k], { cap: 2e6, timeout: 7000 });
      const $p = cheerio.load(r.status === 200 ? r.text : "");
      $p("script, style, noscript, template, header, footer, nav").remove();
      out[k] = { status: r.status, text: $p("body").text().replace(/\s+/g, " ").trim().slice(0, 20000) };
    } catch (_) { out[k] = { status: 0, text: "" }; }
  }));
  return out;
}

async function checkProduct(input) {
  const url = await validateUrl(input); // throws on bad/SSRF
  const { res, html } = await fetchPage(url);
  const finalUrl = res.url || url;
  const [robotsTxt, shopify, llmsTxt, botAccess] = await Promise.all([fetchRobots(url), fetchShopifyProduct(url), fetchLlmsTxt(finalUrl), probeBots(finalUrl)]);
  const [sitemapListed, policies] = await Promise.all([fetchSitemapListed(finalUrl, shopify), fetchPolicies(finalUrl, cheerio.load(html), !!shopify)]);
  return analyze({ url, finalUrl, html, headers: res.headers, robotsTxt, shopify, sitemapListed, llmsTxt, botAccess, policies });
}

// ── Upgrade C: competitive comparison ────────────────────────────────────────
// Run the same check on the user's URL + up to 2 competitor URLs (user-supplied,
// not auto-discovered) and return a compact side-by-side. Reuses checkProduct
// (already SSRF-guarded + zero-token). Cost-capped at 3 total URLs.
const COMPARE_SIGNALS = [
  { id: "product-schema", key: "schema", label: "Product schema" },
  { id: "offer-price", key: "price", label: "Offer with price" },
  { id: "availability", key: "availability", label: "Availability" },
  { id: "identifier", key: "identifier", label: "Product identifier" },
  { id: "rating-schema", key: "ratings", label: "Star ratings" },
  { id: "returns", key: "returns", label: "Return terms" },
];
function summarize(report) {
  const has = (id) => (report.categories || []).some((c) => c.checks.some((x) => x.id === id && x.ok));
  const signals = {}; COMPARE_SIGNALS.forEach((s) => (signals[s.key] = has(s.id)));
  return {
    url: report.finalUrl || report.url,
    overall: report.overall,
    categories: (report.categories || []).map((c) => ({ name: c.name, score: c.score })),
    signals,
    clientRendered: !!(report.rendering && report.rendering.clientRendered),
  };
}
async function checkCompare(youUrl, competitorUrls) {
  const you = await checkProduct(youUrl); // throws on bad/SSRF
  const comps = [];
  for (const cu of (competitorUrls || []).slice(0, 2)) {
    try { comps.push(summarize(await checkProduct(cu))); }
    catch (e) { comps.push({ url: cu, error: e.message || "Could not read that URL" }); }
  }
  return { ok: true, you: summarize(you), competitors: comps, signalLabels: COMPARE_SIGNALS.map((s) => ({ key: s.key, label: s.label })) };
}

module.exports = { validateUrl, checkProduct, checkCompare, analyze, summarize, normalizeShopify, gtinValid, pickProductSitemap, listedInSitemap, policyLinks, ratingLooksFake };
