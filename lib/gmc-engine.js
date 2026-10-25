// Free "Google Merchant Center Compliance Checker" engine. Audits a single
// PRODUCT-page URL for Merchant Center misrepresentation / suspension risk from
// the on-page signals Google reads: all Product JSON-LD nodes, meta price/stock,
// and visible DOM. Pure fetch + Cheerio + rules — ZERO LLM / Anthropic tokens, no
// model calls anywhere, nothing stored.
//
// Reuses the store-auditor's SSRF-guarded validateUrl + fetchPage (same repo).
// Exports: validateUrl (re-export), checkProduct(url) -> { ok, ...report }.
//
// HEADLINE differentiator vs a static checklist: it keeps EACH Product JSON-LD
// node separately and flags when the theme + an SEO app tell Google two different
// stories about the same product (the top misrepresentation trigger). No other
// free tool does this.

const cheerio = require("cheerio");
const { validateUrl, fetchPage } = require("./audit-engine");

const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));
const num = (v) => {
  if (v == null) return null;
  const n = parseFloat(String(v).replace(/[^0-9.]/g, ""));
  return isNaN(n) ? null : n;
};
const first = (v) => (Array.isArray(v) ? v[0] : v);

// ── Collect EVERY Product/ProductGroup JSON-LD node, separately ───────────────
// Unlike a boolean signal read, this keeps each node's identity fields so we can
// compare sources against each other (the schema-conflict check). Returns an
// array of normalized product records + the raw @type set.
function normOffer(off) {
  const o = first(off) || {};
  return {
    price: num(o.price != null ? o.price : o.lowPrice),
    priceCurrency: o.priceCurrency != null ? String(o.priceCurrency) : null,
    availability: o.availability != null ? String(o.availability).replace(/^https?:\/\/schema\.org\//i, "") : null,
    hasShipping: o.shippingDetails != null,
    hasReturnPolicy: o.hasMerchantReturnPolicy != null,
  };
}
function brandName(b) {
  if (b == null) return null;
  if (typeof b === "string") return b;
  const bb = first(b);
  return bb && typeof bb === "object" ? (bb.name != null ? String(bb.name) : null) : String(bb);
}
function productRecord(o) {
  const offer = normOffer(o.offers);
  return {
    name: o.name != null ? String(o.name) : null,
    brand: brandName(o.brand),
    gtin: o.gtin || o.gtin13 || o.gtin12 || o.gtin8 || o.gtin14 || null,
    mpn: o.mpn != null ? String(o.mpn) : null,
    sku: o.sku != null ? String(o.sku) : null,
    compareAt: num(first(o.offers) && first(o.offers).priceSpecification &&
      first(first(o.offers).priceSpecification).price),
    price: offer.price,
    priceCurrency: offer.priceCurrency,
    availability: offer.availability,
    hasShipping: offer.hasShipping,
    hasReturnPolicy: offer.hasReturnPolicy,
    hasRating: o.aggregateRating != null,
    hasReview: o.review != null,
  };
}

// Only the page's own product counts as a Product block: a top-level Product or
// ProductGroup (the root, an @graph, or a WebPage's mainEntity), the way the AI
// Shopping checker reads it. A group's hasVariant entries are its variants, not
// more blocks (Shopify's structured_data prints every product with options this
// way). Products nested anywhere else (related items, carousels) are other products.
const isProductNode = (o) => !!o && typeof o === "object" && [].concat(o["@type"] || []).some((t) => /^(product|productgroup)$/i.test(String(t)));
const isGroupNode = (o) => [].concat(o["@type"] || []).some((t) => /^productgroup$/i.test(String(t)));
const COMPARE_KEYS = ["name", "price", "brand", "availability", "gtin"];
const normValue = (v) => (v == null ? null : String(v).toLowerCase().trim());

// The variant the page shows: the one in ?variant=, else the first in stock (what
// Shopify themes select), else the first.
function shownVariant(variants, pageUrl) {
  const m = /[?&]variant=(\d+)/.exec(pageUrl || "");
  if (m) {
    const re = new RegExp(`[?&]variant=${m[1]}(\\D|$)`);
    const hit = variants.find((v) => [v["@id"], v.url].concat([].concat(v.offers || []).map((o) => o && o.url))
      .some((s) => s != null && re.test(String(s))));
    if (hit) return hit;
  }
  return variants.find((v) => /instock/i.test(String((first(v.offers) || {}).availability || ""))) || variants[0];
}

// One record per block. A group takes its price, stock and identifiers from the
// shown variant and its name and brand from itself; `alts` keeps every value the
// block stands for, so another block only disagrees when it matches none of them,
// and `prices` lets the price checks accept any variant's price.
function blockRecord(o, pageUrl) {
  const variants = isGroupNode(o) ? [].concat(o.hasVariant || []).filter(isProductNode) : [];
  const own = productRecord(o);
  let rec = own, parts = [own];
  if (variants.length) {
    const vrecs = variants.map(productRecord);
    const shown = vrecs[variants.indexOf(shownVariant(variants, pageUrl))];
    rec = { ...shown };
    for (const k of Object.keys(own)) if (rec[k] == null) rec[k] = own[k];
    rec.name = own.name != null ? own.name : shown.name;
    rec.brand = own.brand || shown.brand;
    rec.hasRating = own.hasRating || shown.hasRating;
    rec.hasReview = own.hasReview || shown.hasReview;
    parts = [own].concat(vrecs);
  }
  rec.alts = {};
  for (const k of COMPARE_KEYS) rec.alts[k] = new Set(parts.map((p) => normValue(p[k])).filter(Boolean));
  rec.prices = parts.map((p) => p.price).filter((p) => p != null);
  return rec;
}

function collectProductNodes($, pageUrl) {
  const nodes = [];
  const types = new Set();
  let orgName = null;

  $('script[type="application/ld+json"]').each((_, el) => {
    let data;
    try { data = JSON.parse($(el).contents().text()); } catch { return; }
    const walk = (o) => {
      if (!o || typeof o !== "object") return;
      if (Array.isArray(o)) return o.forEach(walk);
      const t = o["@type"];
      if (t) [].concat(t).forEach((x) => types.add(String(x)));
      const tl = t ? [].concat(t).map((x) => String(x).toLowerCase()) : [];
      if ((tl.includes("organization") || tl.includes("onlinestore") || tl.includes("store")) && o.name != null && !orgName) {
        orgName = String(o.name);
      }
      if (o["@graph"]) walk(o["@graph"]);
      for (const k of Object.keys(o)) { const v = o[k]; if (v && typeof v === "object" && k !== "@type") walk(v); }
    };
    walk(data);
    const tops = [].concat(data).flatMap((d) => (d && d["@graph"] ? [].concat(d["@graph"]) : [d]));
    for (const top of tops) {
      const node = isProductNode(top) ? top : top && isProductNode(top.mainEntity) ? top.mainEntity : null;
      if (node) nodes.push({ sourceIndex: nodes.length, ...blockRecord(node, pageUrl) });
    }
  });
  return { nodes, types: [...types], orgName };
}

// ── Meta + DOM ground truth (what a human/Google sees on the rendered page) ───
function readMeta($) {
  const m = (sel) => { const v = $(sel).attr("content"); return v != null ? v.trim() : null; };
  const ogPrice = m('meta[property="og:price:amount"]') || m('meta[property="product:price:amount"]');
  const ogCurrency = m('meta[property="og:price:currency"]') || m('meta[property="product:price:currency"]');
  const siteName = m('meta[property="og:site_name"]');
  const ogType = m('meta[property="og:type"]');
  const ogAvail = m('meta[property="product:availability"]') || m('meta[property="og:availability"]');
  return { ogPrice: num(ogPrice), ogCurrency, siteName, ogType, ogAvail: ogAvail ? String(ogAvail).toLowerCase() : null };
}
// A conservatively-scraped visible price. Only trusts a $-amount inside a
// price-ish node, and SKIPS installment / pay-later contexts ("4 payments of
// $41.25", Klarna / Afterpay / Shop Pay) which otherwise produce a false price
// mismatch. Returns null when the visible price is ambiguous — we never fail a
// critical check on a guess.
function visiblePrice($) {
  const INSTALL = /(payment|installment|as low as|\/mo|per month|afterpay|klarna|shop\s?pay|sezzle|affirm|4 interest|x\s?\$)/i;
  const sels = ['[class*="price" i]', '[data-price]', '[itemprop="price"]'];
  for (const s of sels) {
    let found = null;
    $(s).slice(0, 10).each((_, el) => {
      if (found != null) return;
      const txt = $(el).text().replace(/\s+/g, " ");
      if (INSTALL.test(txt)) return;            // skip pay-later widgets
      const cls = ($(el).attr("class") || "").toLowerCase();
      if (/install|afterpay|klarna|sezzle|affirm|shop-?pay|subscription|per-?month/.test(cls)) return;
      const mt = txt.match(/[$£€]\s?([0-9][0-9.,]*)/);
      if (mt) { const n = num(mt[1]); if (n != null && n > 0) found = n; }
    });
    if (found != null) return found;
  }
  return null;
}
// Visible stock intent — conservative to avoid false OutOfStock. A working
// "Add to cart" is the strongest in-stock signal and OVERRIDES stray "sold out"
// text elsewhere on the page (a variant, related product, or template string).
// We only report OutOfStock when the add-to-cart is genuinely disabled, or the
// primary buy button itself reads "sold out" / "notify me". Returns null when
// ambiguous — never fail a critical check on a guess.
function visibleStock($) {
  const atc = $('form[action*="/cart/add" i] button[type="submit"], button[name="add"], [class*="add-to-cart" i] button, button[class*="add-to-cart" i], button[class*="product-form__submit" i]').first();
  if (atc.length) {
    const label = atc.text().replace(/\s+/g, " ").trim().toLowerCase();
    const disabled = atc.attr("disabled") != null || /(^|\s)(disabled|sold-?out|unavailable)(\s|$)/i.test(atc.attr("class") || "") || atc.attr("aria-disabled") === "true";
    if (/sold\s?out|out of stock|unavailable|notify me|coming soon|pre-?order/.test(label)) {
      return /pre-?order/.test(label) ? "PreOrder" : "OutOfStock";
    }
    if (disabled) return "OutOfStock";
    if (/add to (cart|bag)|buy now|add to basket/.test(label) || label === "") return "InStock";
    // a present, enabled buy button with an unknown label → treat as in stock
    return "InStock";
  }
  return null; // no identifiable buy button — don't guess
}

// ── Is this even a product page? (honest "can't score" guard) ─────────────────
function looksLikeProductPage(url, $, nodes, meta) {
  if (nodes.length) return true;
  if (/\/products?\//i.test(url) || /\/p\//i.test(url) || /\/dp\//i.test(url) || /\/item\//i.test(url)) return true;
  if (meta.ogType === "product") return true;
  if ($('meta[property="product:price:amount"]').length) return true;
  if ($('[itemtype*="schema.org/Product" i]').length) return true;
  return false;
}

// ── The 10 checks ─────────────────────────────────────────────────────────────
// Each finding: { id, label, category, status: pass|warn|fail,
//   severity: critical|warning, detail, evidence?, nudge?, fix? }
// `fix` is a short, concrete next step shown under a fail — the thing a merchant
// actually does, not a restatement of the problem.

// Hedged guess at what KIND of source a Product node came from. The markup does
// NOT name the emitting app, so we never assert an app name — we describe the
// node's shape ("looks like a review app's block") so the merchant knows which
// one to turn off. Always phrased as "likely", never definitive.
function sourceSmell(node) {
  if (!node) return null;
  // A block carrying ratings/reviews but no real Offer is almost always a
  // review app (Judge.me, Loox, Okendo, Stamped…) re-emitting Product.
  if (node.hasReview || node.hasRating) {
    if (node.price == null) return "a review app (it adds ratings but no price)";
    return "a review app";
  }
  // A block with a full Offer + identifiers is typically the source of truth —
  // usually the theme's own product structured data.
  if (node.price != null && (node.gtin || node.mpn || node.hasShipping)) return "your theme's product structured data";
  // A lean Product block with a name + price but nothing else often comes from
  // an SEO app re-describing the product.
  if (node.price != null) return "an SEO app or the theme";
  return null;
}

const AVAIL_ALIASES = { instock: "InStock", "in stock": "InStock", outofstock: "OutOfStock",
  "out of stock": "OutOfStock", soldout: "OutOfStock", preorder: "PreOrder", backorder: "BackOrder" };
const normAvail = (a) => {
  if (!a) return null;
  const k = String(a).toLowerCase().replace(/^https?:\/\/schema\.org\//, "");
  return AVAIL_ALIASES[k] || (a.includes("InStock") ? "InStock" : a.includes("OutOfStock") ? "OutOfStock" : a);
};

function runChecks(url, $, nodes, meta, text) {
  const findings = [];
  const push = (f) => findings.push(f);

  // 1. Duplicate / conflicting Product schema — HEADLINE
  if (nodes.length > 1) {
    // Two blocks disagree on a field when both have values for it and none match.
    const valuesOf = (n, k) => (n.alts ? n.alts[k] : new Set([normValue(n[k])].filter(Boolean)));
    const differing = COMPARE_KEYS.filter((k) => nodes.some((a, i) => nodes.slice(i + 1).some((b) => {
      const va = valuesOf(a, k), vb = valuesOf(b, k);
      return va.size > 0 && vb.size > 0 && ![...va].some((v) => vb.has(v));
    })));
    if (differing.length) {
      const [a, b] = nodes;
      const fieldSet = (n) => ["name", "price", "availability", "brand", "gtin"].map((k) => ({
        k, v: n[k] == null ? "(none)" : (k === "price" && n.priceCurrency ? `${n.priceCurrency} ${n[k]}` : String(n[k])),
      }));
      const smellA = sourceSmell(a), smellB = sourceSmell(b);
      const labelFor = (n, i, smell) => "Source " + (i + 1) + (smell ? " · likely " + smell : " · JSON-LD block");
      // Point the fix at whichever block is the weaker/duplicate one: prefer to
      // keep the block with the full Offer, disable the other (usually a review
      // or SEO app re-emitting Product).
      const keep = (a.gtin || a.mpn || a.hasShipping) ? "the first" : (b.gtin || b.mpn || b.hasShipping) ? "the second" : "the theme's";
      const drop = keep === "the first" ? "the second" : "the first";
      push({ id: "schema-conflict", label: "Two Product blocks disagree", category: "Schema integrity",
        status: "fail", severity: "critical",
        detail: `This page has ${nodes.length} Product blocks and they disagree on ${differing.join(", ")}. Google reads every Product block on the page — when they conflict, it can't tell which is true, and a price or stock mismatch is what it treats as misrepresentation.`,
        fix: `Keep one Product source. Keep ${keep} block (the one with the full Offer) and turn off Product/JSON-LD markup in ${drop} source${smellB && drop === "the second" ? " — " + smellB.replace(/^(a|an|your) /, "") : ""}. Most review and SEO apps have a "disable Product structured data" toggle.`,
        evidence: { differing, sources: [
          { label: labelFor(a, 0, smellA), fields: fieldSet(a) },
          { label: labelFor(b, 1, smellB), fields: fieldSet(b) },
        ] } });
    } else {
      push({ id: "schema-conflict", label: "Two identical Product blocks", category: "Schema integrity",
        status: "warn", severity: "warning",
        detail: `This page has ${nodes.length} Product blocks with the same values. Not a suspension risk today, but if one drifts (a review or SEO app updating price/stock on its own) they'll disagree.`,
        fix: "Trim to a single Product source so they can't drift apart — keep the theme's, disable the app's Product markup." });
    }
  } else {
    push({ id: "schema-conflict", label: "Single Product schema source", category: "Schema integrity",
      status: "pass", severity: "warning",
      detail: nodes.length === 1 ? "One Product schema source — Google reads a single, consistent story." : "No duplicate Product schema detected." });
  }

  // 2. GMC-required Offer fields
  const p = nodes[0] || {};
  const missing = [];
  if (p.price == null) missing.push({ f: "price", crit: true });
  if (!p.priceCurrency) missing.push({ f: "priceCurrency", crit: true });
  if (!p.availability) missing.push({ f: "availability", crit: true });
  if (!p.brand) missing.push({ f: "brand", crit: false });
  if (!p.gtin && !p.mpn) missing.push({ f: "gtin or mpn (product identifier)", crit: false });
  if (nodes.length) {
    const critMissing = missing.filter((m) => m.crit);
    if (critMissing.length) {
      push({ id: "offer-fields", label: "Missing required Offer fields", category: "Schema integrity",
        status: "fail", severity: "critical",
        detail: `Google Merchant Center requires these on every product: ${missing.map((m) => m.f).join(", ")} ${missing.length === 1 ? "is" : "are"} missing from your Offer.`,
        evidence: { missing: missing.map((m) => m.f) } });
    } else if (missing.length) {
      push({ id: "offer-fields", label: "Some Offer fields missing", category: "Schema integrity",
        status: "warn", severity: "warning",
        detail: `Present but incomplete: ${missing.map((m) => m.f).join(", ")} missing. Not an instant suspension, but GMC prefers a full identifier + brand.`,
        evidence: { missing: missing.map((m) => m.f) } });
    } else {
      push({ id: "offer-fields", label: "Required Offer fields present", category: "Schema integrity",
        status: "pass", severity: "warning", detail: "price, priceCurrency, availability, brand and a product identifier were all found." });
    }
  }

  // 3. shippingDetails + hasMerchantReturnPolicy
  if (nodes.length) {
    const miss = [];
    if (!p.hasShipping) miss.push("shippingDetails");
    if (!p.hasReturnPolicy) miss.push("hasMerchantReturnPolicy");
    if (miss.length) {
      push({ id: "shipping-returns", label: "Shipping / return policy not in schema", category: "Schema integrity",
        status: "warn", severity: "warning",
        detail: `${miss.join(" and ")} not found in your Offer. Google now surfaces these in Merchant listings — adding them improves eligibility, though GMC can also read them from account settings.` });
    } else {
      push({ id: "shipping-returns", label: "Shipping + return policy in schema", category: "Schema integrity",
        status: "pass", severity: "warning", detail: "Both shippingDetails and hasMerchantReturnPolicy are present." });
    }
  }

  // 5. Price mismatch — a THREE-WAY read of the three prices that matter on a
  //    Shopify product page:
  //      (a) Product schema offers.price   — what a feed/GMC reads
  //      (b) og:price / product:price meta — what social + some feeds read
  //      (c) the visible price a shopper sees
  //    (a) vs (b) are both structured and unambiguous → a disagreement there is
  //    CRITICAL (classic misrepresentation flag). (c) is scraped DOM and noisy
  //    (nav / related / installment amounts), so a schema-vs-visible gap is only
  //    a WARNING that says "look at this", never a critical on its own — that's
  //    the false-positive lesson from greatjonesgoods.com.
  const cur = p.priceCurrency ? p.priceCurrency + " " : "$";
  const vp = visiblePrice($);
  const eq = (x, y) => x != null && y != null && Math.round(x * 100) === Math.round(y * 100);
  // A ProductGroup stands for all its variants' prices (og:price is usually the cheapest).
  const schemaHas = (x) => (p.prices && p.prices.length ? p.prices : [p.price]).some((y) => eq(y, x));
  if (p.price != null && p.price > 0) {
    if (meta.ogPrice != null && meta.ogPrice > 0 && !schemaHas(meta.ogPrice)) {
      // structured-vs-structured disagreement = critical
      const vals = [
        { src: "Product schema (offers.price)", v: cur + p.price.toFixed(2) },
        { src: "og:price / product:price meta", v: cur + meta.ogPrice.toFixed(2) },
      ];
      if (vp != null) vals.push({ src: "Visible on page", v: "$" + vp.toFixed(2) });
      push({ id: "price-mismatch", label: "Structured prices disagree", category: "Data consistency",
        status: "fail", severity: "critical",
        detail: "Your Product schema price and your Open Graph / product meta price don't match. Google reads both, so a feed built from one won't match a page read from the other — a classic misrepresentation flag.",
        fix: "Make one price the source of truth. Usually the theme's Offer price is right; find the app or meta tag emitting the other price and align or remove it.",
        evidence: { values: vals } });
    } else if (vp != null && !schemaHas(vp)) {
      // schema-vs-visible only = warning, not critical (DOM price is noisy)
      push({ id: "price-mismatch", label: "Visible price differs from schema", category: "Data consistency",
        status: "warn", severity: "warning",
        detail: `The price in your Product schema (${cur + p.price.toFixed(2)}) doesn't match a price we read on the page ($${vp.toFixed(2)}). This can be harmless — a related item, a per-unit or installment amount — but if it's the real product price, Google will see a mismatch. Worth a manual look.`,
        fix: "Open the product page and confirm the price shoppers see matches the offers.price in your Product schema.",
        evidence: { values: [
          { src: "Product schema (offers.price)", v: cur + p.price.toFixed(2) },
          { src: "Visible on page", v: "$" + vp.toFixed(2) },
        ] } });
    } else {
      push({ id: "price-mismatch", label: "Prices agree across sources", category: "Data consistency",
        status: "pass", severity: "critical",
        detail: meta.ogPrice != null
          ? "Your schema price and meta price match" + (vp != null && schemaHas(vp) ? ", and the visible price agrees." : ".")
          : "Your schema price is set" + (vp != null && schemaHas(vp) ? " and matches the visible price." : ".") });
    }
  }

  // 6. Availability mismatch — carries the EZStock nudge
  const schemaAvail = normAvail(p.availability);
  const visAvail = visibleStock($);
  if (schemaAvail && visAvail) {
    if (schemaAvail !== visAvail) {
      push({ id: "availability-mismatch", label: "Availability mismatch", category: "Data consistency",
        status: "fail", severity: "critical", nudge: "ezstock",
        detail: `Your schema says ${schemaAvail} but the page shows ${visAvail === "OutOfStock" ? "it's sold out" : "an active Add to cart"}. When the stock status Google reads drifts from what a shopper sees, that's misrepresentation.`,
        fix: "Get the schema availability to follow real stock. If an app or theme hard-codes InStock, switch it to read the variant's actual inventory — an inventory app that keeps availability in sync fixes this at the source.",
        evidence: { values: [{ src: "Product schema", v: schemaAvail }, { src: "Visible on page", v: visAvail }] } });
    } else {
      push({ id: "availability-mismatch", label: "Availability is consistent", category: "Data consistency",
        status: "pass", severity: "critical", detail: `Schema and page agree: ${schemaAvail}.` });
    }
  }

  // 7. Fake / excessive compare-at
  if (p.compareAt != null && p.price != null && p.compareAt > p.price) {
    const disc = (p.compareAt - p.price) / p.compareAt;
    if (disc > 0.7) {
      push({ id: "compare-at", label: "Implausible strike-through discount", category: "Data consistency",
        status: "warn", severity: "warning",
        detail: `Your compare-at price implies a ${Math.round(disc * 100)}% discount. GMC flags inflated "was" prices — sustained discounts above ~70% draw manual review.` });
    }
  }

  // 8. GTIN / MPN sanity
  if (p.mpn) {
    const looksInternal = (p.sku && p.mpn === p.sku) || /^[A-Z]{2,6}[-_][A-Z0-9]+([-_][A-Z0-9]+)*$/.test(p.mpn);
    if (looksInternal) {
      push({ id: "mpn-sanity", label: "MPN looks like an internal SKU", category: "Data hygiene",
        status: "warn", severity: "warning",
        detail: `Your mpn "${p.mpn}" resembles an internal Shopify SKU, not a manufacturer part number. Submitting internal SKUs as MPNs is a common GMC data-quality flag.` });
    }
  }

  // 9. Brand consistency
  if (p.brand && (meta.siteName || meta.orgName)) {
    const other = meta.siteName || meta.orgName;
    if (other && p.brand.toLowerCase().trim() !== String(other).toLowerCase().trim() &&
        !p.brand.toLowerCase().includes(String(other).toLowerCase()) &&
        !String(other).toLowerCase().includes(p.brand.toLowerCase())) {
      push({ id: "brand-consistency", label: "Brand differs from store name", category: "Data hygiene",
        status: "warn", severity: "warning",
        detail: `Schema brand "${p.brand}" differs from your store name "${other}". That can be correct (you resell a brand) — just make sure the feed's brand matches the manufacturer, not your shop.` });
    }
  }

  // 10. Image ALT text
  const mainImg = $('[class*="product" i] img, [id*="product" i] img, main img').first();
  if (mainImg.length) {
    const alt = (mainImg.attr("alt") || "").trim();
    const bareFile = /\.(jpe?g|png|webp|gif)$/i.test(alt) || /^(img|dsc|image|photo)[-_ ]?\d+/i.test(alt);
    if (!alt || bareFile) {
      push({ id: "image-alt", label: "Main image ALT text weak", category: "Data hygiene",
        status: "warn", severity: "warning",
        detail: alt ? `The main product image alt is "${alt}", which looks like an import filename. Descriptive alt text helps Google match the image to the product.` : "The main product image has no alt text. Descriptive alt text helps Google match the image to the product." });
    }
  }

  return findings;
}

// ── Score + assemble ──────────────────────────────────────────────────────────
const PENALTY = { critFail: 22, warnFail: 8, warn: 4 };
function scoreFindings(findings) {
  let penalty = 0;
  for (const f of findings) {
    if (f.status === "fail" && f.severity === "critical") penalty += PENALTY.critFail;
    else if (f.status === "fail") penalty += PENALTY.warnFail;
    else if (f.status === "warn") penalty += PENALTY.warn;
  }
  return clamp(100 - penalty);
}
function categoryScore(findings, name) {
  const cf = findings.filter((f) => f.category === name);
  let penalty = 0;
  for (const f of cf) {
    if (f.status === "fail" && f.severity === "critical") penalty += PENALTY.critFail;
    else if (f.status === "fail") penalty += PENALTY.warnFail;
    else if (f.status === "warn") penalty += PENALTY.warn;
  }
  return clamp(100 - penalty);
}

const CANT_CHECK = [
  "GMC account settings and policy status",
  "Feed-file conflicts (values submitted in your product feed)",
  "Real Merchant Center return & shipping configuration",
  "Business & website verification",
  "Account cool-down / re-review status after a suspension",
];
// Honest one-line scope, shown as a badge on every report so the tool never
// reads like a fake account scanner (the gmcchecker.* niche).
const SCOPE = "Page-level check — reads your product page's structured data. It does not log into Merchant Center.";

async function checkProduct(input) {
  const url = await validateUrl(input); // throws on bad / SSRF
  const { res, html } = await fetchPage(url);
  const finalUrl = (res && res.url) || url;
  return analyze({ url, finalUrl, html });
}

// The no-network core: a fetched page in, the report out (tests call it directly).
function analyze({ url, finalUrl, html }) {
  const $ = cheerio.load(html);
  const text = $("body").text().replace(/\s+/g, " ");

  const { nodes, types, orgName } = collectProductNodes($, finalUrl || url);
  const meta = readMeta($);
  meta.orgName = orgName;

  if (!looksLikeProductPage(url, $, nodes, meta)) {
    return {
      ok: true, url, finalUrl, isProductPage: false,
      score: null, riskLevel: null,
      message: "This doesn't look like a product page. Paste a single product URL (e.g. /products/your-item) so the checker can read its structured data.",
      categories: [], findings: [], cantCheck: CANT_CHECK,
    };
  }

  // Honesty guard: it's an apparent product page but the server HTML has NO Product
  // JSON-LD. That means the schema is injected client-side (or lives only in the
  // feed) — so we CANNOT run the schema-based checks and, crucially, must NOT return
  // a fake-clean high score. This gap is itself a real GMC-relevant signal: Google's
  // crawler and some feed paths read the server-rendered page, so JS-only structured
  // data may never reach them. Return an honest "can't read your schema" state plus
  // any meta/DOM findings we still legitimately detected.
  if (nodes.length === 0) {
    const metaFindings = runChecks(url, $, nodes, meta, text)
      .filter((f) => ["price-mismatch", "availability-mismatch", "image-alt"].includes(f.id) && f.status !== "pass");
    return {
      ok: true, url, finalUrl, isProductPage: true, noSchema: true,
      score: null, riskLevel: null, schemaSources: 0,
      message: "No Product structured data was found in this page's HTML source. Your theme or SEO app is likely injecting it with JavaScript — which means Google's crawler and your Merchant Center feed may not see it reliably. We can't run the schema-based checks (including the duplicate-schema check) on a page whose schema isn't in the source.",
      findings: metaFindings, categories: [], cantCheck: CANT_CHECK, scope: SCOPE,
    };
  }

  const findings = runChecks(url, $, nodes, meta, text);
  const score = scoreFindings(findings);
  const riskLevel = score >= 80 ? "Low" : score >= 50 ? "Elevated" : "High";

  const categories = ["Schema integrity", "Data consistency", "Data hygiene"].map((name) => ({
    name, score: categoryScore(findings, name),
    findings: findings.filter((f) => f.category === name),
  }));

  return {
    ok: true, url, finalUrl, isProductPage: true,
    schemaSources: nodes.length, types,
    score, riskLevel,
    critical: findings.filter((f) => f.status === "fail" && f.severity === "critical").length,
    warnings: findings.filter((f) => f.status === "warn" || (f.status === "fail" && f.severity === "warning")).length,
    categories, findings, cantCheck: CANT_CHECK, scope: SCOPE,
  };
}

module.exports = { validateUrl, checkProduct, analyze, collectProductNodes, runChecks, visiblePrice, visibleStock, normAvail };
