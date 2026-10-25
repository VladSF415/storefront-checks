// Free Shopify store auditor engine. Pure fetch + Cheerio HTML/header analysis
// + the FREE Google PageSpeed Insights API. ZERO LLM / Anthropic tokens — no
// model calls anywhere. Adapted from the RoastWeb audit engine (analyzer logic +
// SSRF-guarded validateUrl), stripped of every LLM/Firestore/queue dependency.
//
// Exports: validateUrl(input), auditUrl(url) -> { ok, ...report }.

const dns = require("dns").promises;
const cheerio = require("cheerio");

// ── SSRF guard (ported from roastweb/src/lib/validation.ts) ─────────────────
function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);
  return (
    p[0] === 10 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    p[0] === 127 ||
    (p[0] === 169 && p[1] === 254) ||
    p[0] === 0
  );
}
function isPrivateIPv6(ip) {
  const l = ip.toLowerCase();
  return (
    l === "::1" || l === "::" ||
    l.startsWith("fc") || l.startsWith("fd") || l.startsWith("fe80") ||
    l.startsWith("::ffff:") || l.startsWith("100::") || l.startsWith("2001:db8")
  );
}

async function validateUrl(input) {
  let url;
  try { url = new URL(input); } catch { throw new Error("Invalid URL format"); }
  if (!["http:", "https:"].includes(url.protocol)) throw new Error("Only HTTP/HTTPS URLs are allowed");
  const hostname = url.hostname;
  if (["localhost", "127.0.0.1", "::1"].includes(hostname)) throw new Error("Localhost URLs are not allowed");
  // Literal IPs in the hostname
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname) && isPrivateIPv4(hostname)) throw new Error("Private IP addresses are not allowed");
  let ok = false;
  try {
    for (const ip of await dns.resolve4(hostname)) if (isPrivateIPv4(ip)) throw new Error("Private IP addresses are not allowed");
    ok = true;
  } catch (e) { if (e.message.includes("Private IP")) throw e; }
  try {
    for (const ip of await dns.resolve6(hostname)) if (isPrivateIPv6(ip)) throw new Error("Private IP addresses are not allowed");
    ok = true;
  } catch (e) { if (e.message.includes("Private IP")) throw e; }
  if (!ok) throw new Error("Domain not found");
  return url.toString();
}

// ── Fetch with a real UA + timeout ──────────────────────────────────────────
async function fetchPage(url) {
  const res = await fetch(url, {
    redirect: "follow",
    signal: AbortSignal.timeout(12000),
    headers: {
      "User-Agent": "Mozilla/5.0 (compatible; ExtensionsMarketStoreAudit/1.0; +https://extensionsmarket.com/free-shopify-store-audit)",
      "Accept": "text/html,application/xhtml+xml",
    },
  });
  const html = await res.text();
  return { res, html };
}

const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));

// ── Shopify detection ───────────────────────────────────────────────────────
async function detectShopify(url, html, headers) {
  const signals = [];
  if (/cdn\.shopify\.com/i.test(html)) signals.push("cdn.shopify.com assets");
  if (/Shopify\.theme|window\.Shopify|shopify-features/i.test(html)) signals.push("Shopify JS globals");
  if (/myshopify\.com/i.test(html) || /myshopify\.com/i.test(url)) signals.push("myshopify.com");
  const powered = headers.get("powered-by") || "";
  if (/shopify/i.test(powered)) signals.push("Powered-By header");
  if (headers.get("x-shopify-stage") || headers.get("x-shopid") || headers.get("x-shardid")) signals.push("Shopify response headers");
  // /products.json probe (public on most Shopify stores)
  let productsJson = false;
  try {
    const origin = new URL(url).origin;
    const r = await fetch(`${origin}/products.json?limit=1`, { signal: AbortSignal.timeout(6000), headers: { "User-Agent": "Mozilla/5.0" } });
    if (r.ok) { const j = await r.json(); if (j && Array.isArray(j.products)) { productsJson = true; signals.push("/products.json endpoint"); } }
  } catch (_) {}
  return { isShopify: signals.length > 0, signals, productsJson };
}

// ── SEO ─────────────────────────────────────────────────────────────────────
async function analyzeSEO(url, $) {
  const issues = []; let score = 100;
  const title = $("title").first().text().trim();
  if (!title) { issues.push("Missing <title> tag"); score -= 20; }
  else if (title.length < 30 || title.length > 65) { issues.push(`Title is ${title.length} chars (aim 30–60)`); score -= 8; }
  const desc = $('meta[name="description"]').attr("content");
  if (!desc) { issues.push("Missing meta description"); score -= 15; }
  else if (desc.length < 120 || desc.length > 165) { issues.push(`Meta description is ${desc.length} chars (aim 120–160)`); score -= 6; }
  if ($('link[rel="canonical"]').length === 0) { issues.push("No canonical tag (duplicate-content risk)"); score -= 10; }
  const h1 = $("h1").length;
  if (h1 === 0) { issues.push("No H1 heading"); score -= 12; }
  else if (h1 > 1) { issues.push(`${h1} H1 headings (use one)`); score -= 6; }
  // robots + sitemap
  let hasRobots = false, hasSitemap = false;
  try {
    const origin = new URL(url).origin;
    const rob = await fetch(`${origin}/robots.txt`, { signal: AbortSignal.timeout(6000) });
    if (rob.ok) { hasRobots = true; const t = await rob.text(); if (/sitemap:/i.test(t)) hasSitemap = true; }
    if (!hasSitemap) { const sm = await fetch(`${origin}/sitemap.xml`, { signal: AbortSignal.timeout(6000) }); if (sm.ok) hasSitemap = true; }
  } catch (_) {}
  if (!hasRobots) { issues.push("No robots.txt"); score -= 8; }
  if (!hasSitemap) { issues.push("No sitemap.xml"); score -= 8; }
  return { score: clamp(score), title, titleLength: title.length, metaDescription: !!desc, hasCanonical: $('link[rel="canonical"]').length > 0, h1Count: h1, hasRobots, hasSitemap, issues };
}

// ── Structured data (product/offer schema matters for stores) ───────────────
// Also derives an "AI shopping readiness" read: AI shopping surfaces (Google AI
// Mode / Shopping Graph, ChatGPT & Perplexity shopping) read Product + Offer data
// — price, currency, availability, and merchant identity.
function analyzeSchema($) {
  const issues = []; let score = 100;
  const types = new Set();
  let offers = { hasOffers: false, hasPrice: false, hasCurrency: false, hasAvailability: false };
  $('script[type="application/ld+json"]').each((_, el) => {
    try {
      const data = JSON.parse($(el).contents().text());
      const walk = (o) => {
        if (!o || typeof o !== "object") return;
        if (Array.isArray(o)) return o.forEach(walk);
        if (o["@type"]) [].concat(o["@type"]).forEach((t) => types.add(String(t)));
        // Offer signals (may be nested under a Product's `offers`)
        const off = o.offers;
        if (off) {
          [].concat(off).forEach((of) => {
            if (of && typeof of === "object") {
              offers.hasOffers = true;
              if (of.price != null || of.lowPrice != null || of.highPrice != null) offers.hasPrice = true;
              if (of.priceCurrency != null) offers.hasCurrency = true;
              if (of.availability != null) offers.hasAvailability = true;
            }
          });
        }
        if (o["@graph"]) walk(o["@graph"]);
        // recurse into plain nested objects too (offers can sit deeper)
        for (const k of Object.keys(o)) { const v = o[k]; if (v && typeof v === "object" && k !== "@type") walk(v); }
      };
      walk(data);
    } catch (_) {}
  });
  const has = (t) => [...types].some((x) => x.toLowerCase() === t.toLowerCase());
  if (types.size === 0) { issues.push("No structured data (JSON-LD) found"); score -= 30; }
  if (!has("Product") && !has("Organization") && !has("WebSite")) { issues.push("No Product / Organization / WebSite schema"); score -= 15; }
  if (!has("BreadcrumbList")) { issues.push("No BreadcrumbList schema (helps rich results)"); score -= 8; }

  // AI shopping visibility (homepage-scoped, so word it as "on the homepage")
  const hasMerchant = has("Organization") || has("Store") || has("LocalBusiness");
  const aiShopping = {
    hasProduct: has("Product"),
    hasOffers: offers.hasOffers,
    hasPrice: offers.hasPrice,
    hasAvailability: offers.hasAvailability,
    hasMerchant,
  };
  // Product present but no price/availability = AI shopping surfaces can't read it.
  if (has("Product") && offers.hasOffers && !(offers.hasPrice && offers.hasAvailability)) {
    issues.push("Product schema is missing price/availability (AI shopping + rich results can't read it)");
    score -= 8;
  }
  if (!hasMerchant) { issues.push("No Organization/merchant schema on the homepage (weakens brand entity for AI shopping)"); score -= 6; }

  return { score: clamp(score), types: [...types], aiShopping, issues };
}

// ── Images ──────────────────────────────────────────────────────────────────
function analyzeImages($, html) {
  const issues = []; let score = 100;
  const imgs = $("img");
  const total = imgs.length;
  let missingAlt = 0, noLazy = 0, modern = 0;
  imgs.each((_, el) => {
    const alt = $(el).attr("alt");
    if (alt === undefined || alt.trim() === "") missingAlt++;
    const loading = $(el).attr("loading");
    if (loading !== "lazy") noLazy++;
    const src = ($(el).attr("src") || "") + ($(el).attr("srcset") || "");
    if (/\.webp|\.avif/i.test(src)) modern++;
  });
  if (total > 0) {
    if (missingAlt / total > 0.3) { issues.push(`${missingAlt}/${total} images missing alt text (SEO + a11y)`); score -= 15; }
    if (noLazy / total > 0.5 && total > 6) { issues.push("Most images aren't lazy-loaded (slows first paint)"); score -= 10; }
    if (modern / total < 0.3) { issues.push("Few modern image formats (WebP/AVIF) — larger downloads"); score -= 10; }
  }
  return { score: clamp(score), total, missingAlt, issues };
}

// ── Mobile ──────────────────────────────────────────────────────────────────
function analyzeMobile($) {
  const issues = []; let score = 100;
  const vp = $('meta[name="viewport"]').attr("content") || "";
  if (!vp) { issues.push("No viewport meta tag (mobile rendering broken)"); score -= 30; }
  else if (!/width=device-width/i.test(vp)) { issues.push("Viewport not set to device-width"); score -= 15; }
  if (/user-scalable\s*=\s*no|maximum-scale\s*=\s*1/i.test(vp)) { issues.push("Zoom disabled (accessibility issue)"); score -= 10; }
  return { score: clamp(score), viewport: !!vp, issues };
}

// ── Performance (header/resource heuristics) ────────────────────────────────
function analyzePerformance(headers, $, html) {
  const issues = []; let score = 100;
  const enc = headers.get("content-encoding") || "";
  if (!/gzip|br|deflate/i.test(enc)) { issues.push("No text compression (gzip/brotli)"); score -= 15; }
  const cache = headers.get("cache-control") || "";
  if (!cache || /no-store/i.test(cache)) { issues.push("Weak/absent cache-control on the document"); score -= 5; }
  const scripts = $("script[src]").length;
  const styles = $('link[rel="stylesheet"]').length;
  if (scripts > 25) { issues.push(`${scripts} external scripts (heavy — hurts load time)`); score -= 12; }
  else if (scripts > 15) { issues.push(`${scripts} external scripts (on the heavy side)`); score -= 6; }
  if (styles > 8) { issues.push(`${styles} stylesheets (consider consolidating)`); score -= 5; }
  const bytes = Buffer.byteLength(html, "utf8");
  if (bytes > 400000) { issues.push(`HTML document is ${(bytes / 1024).toFixed(0)} KB (large)`); score -= 8; }
  return { score: clamp(score), scripts, styles, compressed: /gzip|br|deflate/i.test(enc), htmlBytes: bytes, issues };
}

// ── Third-party / app-script bloat (Shopify-tuned) ──────────────────────────
function analyzeThirdParty($, baseHost) {
  const issues = []; let score = 100;
  const hosts = {};
  $("script[src]").each((_, el) => {
    const src = $(el).attr("src") || "";
    try { const h = new URL(src, "https://" + baseHost).hostname; if (h && h !== baseHost && !/cdn\.shopify\.com/.test(h)) hosts[h] = (hosts[h] || 0) + 1; } catch (_) {}
  });
  const thirdParty = Object.keys(hosts).length;
  if (thirdParty > 12) { issues.push(`${thirdParty} third-party script hosts (app bloat slows the store)`); score -= 18; }
  else if (thirdParty > 7) { issues.push(`${thirdParty} third-party script hosts (watch app bloat)`); score -= 8; }
  return { score: clamp(score), thirdPartyHosts: thirdParty, topHosts: Object.keys(hosts).slice(0, 8), issues };
}

// ── Broken internal links (cost-capped: sample ≤10, HEAD, 5s, SSRF-guarded) ──
async function analyzeLinks(url, $) {
  const issues = []; let score = 100;
  try {
    const origin = new URL(url).origin;
    const baseHost = new URL(url).hostname;
    const seen = new Set();
    const candidates = [];
    $("a[href]").each((_, el) => {
      let href = ($(el).attr("href") || "").trim();
      if (!href || href.startsWith("#") || /^(mailto:|tel:|javascript:|data:)/i.test(href)) return;
      let abs;
      try { abs = new URL(href, origin); } catch { return; }
      if (!/^https?:$/.test(abs.protocol)) return;
      if (abs.hostname !== baseHost) return; // internal only
      abs.hash = "";
      const key = abs.toString();
      if (seen.has(key)) return;
      seen.add(key);
      candidates.push(key);
    });
    const sample = candidates.slice(0, 10); // hard cap
    if (sample.length === 0) return { score: 100, checked: 0, broken: 0, brokenUrls: [], issues: [] };

    const checkOne = async (link) => {
      try {
        await validateUrl(link); // SSRF guard on every fetch target
        let r;
        try {
          r = await fetch(link, { method: "HEAD", redirect: "follow", signal: AbortSignal.timeout(5000), headers: { "User-Agent": "Mozilla/5.0 (compatible; ExtensionsMarketStoreAudit/1.0)" } });
          if (r.status === 405 || r.status === 501) { // HEAD not allowed → fall back to GET
            r = await fetch(link, { method: "GET", redirect: "follow", signal: AbortSignal.timeout(5000), headers: { "User-Agent": "Mozilla/5.0 (compatible; ExtensionsMarketStoreAudit/1.0)" } });
          }
        } catch { return { link, broken: true }; }
        return { link, broken: r.status >= 400 };
      } catch { return { link, broken: true }; }
    };
    const results = await Promise.all(sample.map(checkOne));
    const brokenUrls = results.filter((x) => x.broken).map((x) => { try { return new URL(x.link).pathname; } catch { return x.link; } });
    const broken = brokenUrls.length;
    if (broken > 0) {
      const shown = brokenUrls.slice(0, 3).join(", ");
      issues.push(`${broken} of ${sample.length} sampled internal links are broken (4xx/5xx): ${shown}${broken > 3 ? "…" : ""}`);
      score -= Math.min(25, Math.round((broken / sample.length) * 40));
    }
    return { score: clamp(score), checked: sample.length, broken, brokenUrls: brokenUrls.slice(0, 5), issues };
  } catch (_) {
    return { score: 100, checked: 0, broken: 0, brokenUrls: [], issues: [] }; // never break the audit
  }
}

// ── Security headers / SSL ──────────────────────────────────────────────────
function analyzeTrust(url, headers) {
  const issues = []; let score = 100;
  if (!url.startsWith("https:")) { issues.push("Not served over HTTPS"); score -= 40; }
  if (!headers.get("strict-transport-security")) { issues.push("No HSTS header"); score -= 8; }
  if (!headers.get("content-security-policy")) { issues.push("No Content-Security-Policy"); score -= 6; }
  if (!headers.get("x-content-type-options")) { issues.push("No X-Content-Type-Options: nosniff"); score -= 4; }
  return { score: clamp(score), https: url.startsWith("https:"), issues };
}

// ── Conversion / store-trust heuristics → map to Vlad's apps ────────────────
function analyzeConversion($, html, shopify) {
  const issues = []; const apps = [];
  const text = html.toLowerCase();
  // Social proof / urgency widgets (PopBoost)
  const hasReviews = /aggregateRating|"@type"\s*:\s*"review"|judge\.me|loox|yotpo|stamped/i.test(html);
  const hasUrgency = /countdown|selling fast|only \d+ left|low stock|hurry|almost gone/i.test(text);
  if (!hasUrgency) { issues.push("Consider testing urgency / social-proof on the homepage (none detected)"); apps.push({ app: "PopBoost", icon: "/icons/popboost.webp", why: "adds social-proof popups, countdown timers and low-stock badges", url: "/popboost" }); }
  // Bundles (EZBundle)
  const hasBundles = /bundle|buy together|frequently bought|volume discount/i.test(text);
  if (!hasBundles) { apps.push({ app: "EZBundle", icon: "/icons/ezbundle.webp", why: "adds product bundles and buy-more-save-more offers to lift AOV", url: "/ezbundle" }); }
  // Reviews schema (helps SEO + trust) — this one IS a measurable fact (schema
  // is present or not), so keep it factual, not a "consider".
  if (!hasReviews) { issues.push("No product review schema detected (hurts rich results + trust)"); }
  // Email capture / drops (EZDrop)
  const hasCapture = /newsletter|subscribe|klaviyo|mailchimp|email/i.test(text);
  if (!hasCapture) { issues.push("Consider adding email capture to recover first-time visitors (none detected)"); apps.push({ app: "EZDrop", icon: "/icons/ezdrop.webp", why: "runs viral product drops and referral waitlists to grow your list", url: "/ezdrop" }); }
  // Inventory (EZStock) — always relevant to a store owner
  apps.push({ app: "EZStock", icon: "/icons/ezstock.webp", why: "inventory management, low-stock alerts and purchase orders", url: "/ezstock" });
  // Quiz (Quizzo)
  apps.push({ app: "Quizzo", icon: "/icons/quizzo.webp", why: "product quiz that recommends bundles and boosts conversion", url: "/quizzo" });
  // Per-element pass/fail so the UI can show what's already in place (not just gaps).
  const checks = [
    { label: "urgency / social proof", ok: hasUrgency },
    { label: "product reviews", ok: hasReviews },
    { label: "bundles / cross-sell", ok: hasBundles },
    { label: "email capture", ok: hasCapture },
  ];
  return { issues, apps, checks };
}

// ── Google PageSpeed Insights (free; graceful fallback) ─────────────────────
async function fetchPageSpeed(url) {
  try {
    const key = process.env.GOOGLE_PAGESPEED_API_KEY;
    let api = `https://www.googleapis.com/pagespeedonline/v5/runPagespeed?url=${encodeURIComponent(url)}&strategy=mobile&category=performance`;
    if (key) api += `&key=${key}`;
    // Google's lab run is slow and highly variable (measured ~14s light sites,
    // ~35s mid, 60-80s for very heavy stores). 40s catches the large majority;
    // heavier stores fall back to the header/resource heuristic + the honest
    // "CWV unavailable, try again" note. (We deliberately don't block the audit
    // longer than this — the rest of the report is fast.)
    const r = await fetch(api, { signal: AbortSignal.timeout(40000) });
    if (!r.ok) return null;
    const j = await r.json();
    const lh = j.lighthouseResult;
    if (!lh) return null;
    const cat = lh.categories && lh.categories.performance;
    const a = lh.audits || {};
    const ms = (id) => (a[id] && a[id].numericValue != null ? Math.round(a[id].numericValue) : null);
    return {
      performanceScore: cat ? Math.round(cat.score * 100) : null,
      lcp: ms("largest-contentful-paint"),
      cls: a["cumulative-layout-shift"] ? a["cumulative-layout-shift"].numericValue : null,
      tbt: ms("total-blocking-time"),
      fcp: ms("first-contentful-paint"),
      speedIndex: ms("speed-index"),
    };
  } catch (_) { return null; }
}

// ── Per-issue fix guidance (keyword → one concrete next step) ───────────────
// Maps an issue's text to a short, actionable fix. Keyed on distinctive words so
// it survives the dynamic numbers in the messages.
const FIXES = [
  [/title/i, "Set a unique 30–60 char title per page in your theme's SEO settings (or Search &amp; Discovery)."],
  [/meta description/i, "Write a 120–160 char meta description; on Shopify, edit it under the page's Search engine listing."],
  [/canonical/i, "Most themes add canonical tags automatically — if missing, add <link rel=\"canonical\"> in theme.liquid's &lt;head&gt;."],
  [/h1/i, "Use exactly one H1 per page — usually the product or page title. Fix duplicate H1s in the theme sections."],
  [/robots\.txt/i, "Shopify generates robots.txt automatically; if it's missing, check for a redirect or a blocked route."],
  [/sitemap/i, "Shopify serves /sitemap.xml automatically and submits it — verify it loads and add it in Google Search Console."],
  [/structured data|schema/i, "Add Product, Organization, and BreadcrumbList JSON-LD. Many themes include it; a schema app fills gaps."],
  [/review schema/i, "Use a reviews app (Judge.me, Loox, Yotpo) that outputs AggregateRating schema so stars show in search."],
  [/alt text/i, "Add descriptive alt text to product and content images in the theme editor / product media."],
  [/lazy-load/i, "Add loading=\"lazy\" to below-the-fold images (most modern themes do this; older ones need a tweak)."],
  [/modern image|webp|avif/i, "Serve WebP/AVIF — Shopify's CDN can, so re-upload large images or use an image-optimizer app."],
  [/viewport/i, "Add &lt;meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"&gt; to theme.liquid's &lt;head&gt;."],
  [/zoom disabled/i, "Remove user-scalable=no / maximum-scale=1 from the viewport tag so mobile users can pinch-zoom."],
  [/compression/i, "Ensure gzip/brotli is on — Shopify does this by default; a proxy or custom code can break it."],
  [/cache-control/i, "Set sensible cache headers on static assets; on Shopify this is handled by the CDN for theme assets."],
  [/external scripts/i, "Audit and remove apps you don't use — each adds scripts. Combine or defer non-critical ones."],
  [/stylesheets/i, "Reduce the number of CSS files — many come from apps. Remove unused apps' leftover theme code and let your theme bundle its own styles."],
  [/HTML document is/i, "Trim the homepage: fewer sections, lazy-load below the fold, and remove unused app embeds."],
  [/third-party script hosts|app bloat/i, "Uninstall unused apps and confirm they removed their theme code — that's the #1 Shopify speed fix."],
  [/HTTPS/i, "Enable SSL in Shopify (Settings → Domains); every store gets a free certificate."],
  [/HSTS|Content-Security-Policy|nosniff/i, "Security headers are set at the platform/CDN level — usually fine on Shopify; note for custom setups."],
  [/urgency|social-proof/i, "Add social proof and urgency (reviews, low-stock, countdowns). PopBoost does this without a theme edit."],
  [/bundle/i, "Offer bundles or buy-more-save-more to lift average order value. EZBundle adds this."],
  [/email capture/i, "Add a timed email popup (after ~15s or on exit) with a real incentive — not on page load."],
  [/price\/availability|ai shopping/i, "Output Offer schema with price, priceCurrency, and availability on product pages so AI shopping and rich results can read them — most themes do; a schema app fills gaps."],
  [/merchant schema/i, "Add Organization schema (name, logo, URL, sameAs) so search engines and AI shopping recognize your brand as an entity."],
  [/broken/i, "Fix or redirect broken internal links — set up 301 redirects under Settings → Navigation / URL redirects, and check menu links after theme edits."],
];
function fixFor(text) {
  for (const [re, fix] of FIXES) if (re.test(text)) return fix;
  return null;
}

// ── Business-impact ranking (NOT raw technical severity) ────────────────────
// Keyword → impact. Prioritizes what costs sales or blocks discovery over hygiene.
const IMPACT = [
  // high — lost sales, broken UX, or can't be found/indexed
  [/HTTPS|not served over https/i, "high"],
  [/viewport|mobile rendering broken/i, "high"],
  [/missing <title>|no h1 heading/i, "high"],
  [/broken/i, "high"],
  [/app bloat|third-party script hosts/i, "high"],
  [/urgency|social-proof|review schema/i, "high"],
  [/price\/availability|ai shopping/i, "high"],
  [/no structured data/i, "high"],
  // medium — meaningful SEO / trust / conversion drag
  [/meta description|canonical|title is \d+ chars/i, "medium"],
  [/sitemap|robots\.txt/i, "medium"],
  [/alt text/i, "medium"],
  [/external scripts|HTML document is|compression/i, "medium"],
  [/merchant schema|breadcrumblist|product \/ organization/i, "medium"],
  [/zoom disabled|device-width/i, "medium"],
  [/lazy-load|modern image|webp|avif/i, "medium"],
  // everything else (HSTS, CSP, nosniff, cache-control, stylesheet count…) → low
];
function impactFor(text) {
  for (const [re, imp] of IMPACT) if (re.test(text)) return imp;
  return "low";
}
const IMPACT_RANK = { high: 0, medium: 1, low: 2 };

// ── Why it matters (keyword → the consequence, not the fix) ─────────────────
// One short "why" per issue type, so a merchant knows the stakes, not just the
// action. Keyed on the same distinctive words as FIXES/IMPACT.
const WHY = [
  [/HTTPS|not served over https/i, "Without HTTPS, browsers warn shoppers the site isn't secure and Google demotes it. That kills trust right at checkout."],
  [/viewport|mobile rendering broken/i, "Most Shopify traffic is mobile. A broken viewport means the store renders wrong on phones, and those visitors bounce."],
  [/missing <title>/i, "The title is the clickable headline in Google results. Without one, the page looks broken in search and gets far fewer clicks."],
  [/no h1 heading|h1/i, "The H1 tells Google and shoppers what the page is about. Missing or duplicate H1s blur that signal and weaken ranking."],
  [/broken/i, "Broken internal links dead-end shoppers and waste Google's crawl budget, chipping away at trust and indexing."],
  [/app bloat|third-party script hosts/i, "Every third-party app script blocks the page from loading. App bloat is the top cause of slow Shopify stores, and speed drives both ranking and conversion."],
  [/review schema/i, "Review schema is what puts star ratings in Google results. Without it you lose the trust signal that lifts click-through."],
  [/urgency|social-proof/i, "Social proof and urgency are among the biggest conversion levers. Without any, visitors have less reason to buy now."],
  [/price\/availability|ai shopping/i, "AI shopping surfaces like Google AI Mode, ChatGPT, and Perplexity read price and availability from Offer schema. Without it your products can't show up there."],
  [/no structured data/i, "Structured data is how search engines and AI understand your products. Without it you miss rich results and AI shopping visibility."],
  [/meta description/i, "The meta description is the sales pitch under your search result. A good one lifts click-through even when your ranking doesn't change."],
  [/canonical/i, "Without a canonical tag, Google can treat variant and filtered URLs as duplicate pages and split your ranking signals."],
  [/sitemap|robots\.txt/i, "robots.txt and the sitemap tell Google what to crawl and index. Problems here can quietly keep pages out of search."],
  [/alt text/i, "Alt text is how search and screen readers understand images. Missing it loses image-search traffic and fails accessibility."],
  [/external scripts|HTML document is|compression/i, "Heavy pages load slower, and slower pages rank lower and convert worse. Speed is money on a storefront."],
  [/merchant schema/i, "Organization schema makes Google and AI recognize your store as a real brand entity, which strengthens every result you show in."],
  [/breadcrumblist|product \/ organization/i, "This schema powers breadcrumb and product rich results in Google. Without it your listings look plainer and get fewer clicks."],
  [/zoom disabled|device-width/i, "Blocking zoom or mis-setting the viewport frustrates mobile shoppers and fails accessibility guidelines."],
  [/lazy-load|modern image|webp|avif/i, "Oversized, eagerly-loaded images are usually the biggest drag on Core Web Vitals, which Google uses for ranking."],
  [/bundle/i, "Bundles and buy-more-save-more raise average order value. No bundle option leaves revenue on the table per order."],
  [/email capture/i, "Most first-time visitors don't buy. Without email capture you lose the chance to bring them back and recover the sale."],
  [/HSTS|Content-Security-Policy|nosniff/i, "These are security-hardening headers. Low priority on Shopify since the platform handles the basics; worth noting only for custom setups."],
  [/cache-control|stylesheets/i, "Minor performance hygiene. Small individual impact, but it adds up on a heavy page."],
];
function whyFor(text) {
  for (const [re, why] of WHY) if (re.test(text)) return why;
  return null;
}

// ── Finding kind: measurable FACT vs conversion SUGGESTION ───────────────────
// From Shopify Community feedback (Icey.Lane, 9yr CRO): separate what the tool
// can PROVE on the public page (missing title, broken link, measured LCP) from a
// conversion HYPOTHESIS ("no urgency"). The second isn't automatically a defect —
// adding artificial urgency can even hurt trust — and the tool can't always see
// widgets that load via JS. So we label suggestions as "consider/test", not
// "you're failing", and never let them outrank a real measured problem.
// A finding is a SUGGESTION when it's a conversion best-practice the merchant may
// legitimately choose to skip; everything else is a FACT observed on the page.
const SUGGESTION = /urgency|social-proof|social proof|bundle|email capture|cross-sell/i;
function kindFor(text) {
  return SUGGESTION.test(text) ? "suggestion" : "fact";
}

// ── Orchestrator ────────────────────────────────────────────────────────────
async function auditUrl(input) {
  const url = await validateUrl(input); // throws on bad/SSRF
  const { res, html } = await fetchPage(url);
  const headers = res.headers;
  const $ = cheerio.load(html);
  const baseHost = new URL(url).hostname;

  const [seo, shopify, pagespeed, links] = await Promise.all([
    analyzeSEO(url, $),
    detectShopify(url, html, headers),
    fetchPageSpeed(url),
    analyzeLinks(url, $),
  ]);
  const schema = analyzeSchema($);
  const images = analyzeImages($, html);
  const mobile = analyzeMobile($);
  const perf = analyzePerformance(headers, $, html);
  const thirdParty = analyzeThirdParty($, baseHost);
  const trust = analyzeTrust(url, headers);
  const conversion = analyzeConversion($, html, shopify);

  // Performance score: prefer real PageSpeed, else header/resource heuristic.
  const perfScore = pagespeed && pagespeed.performanceScore != null ? pagespeed.performanceScore : perf.score;

  const categories = {
    performance: perfScore,
    seo: seo.score,
    mobile: mobile.score,
    trust: Math.round((trust.score + thirdParty.score) / 2),
    structured_data: schema.score,
  };
  const overall = clamp(
    categories.performance * 0.3 + categories.seo * 0.25 + categories.mobile * 0.15 +
    categories.trust * 0.15 + categories.structured_data * 0.15
  );

  const mk = (area) => (t) => {
    const kind = kindFor(t);
    // A conversion SUGGESTION is never "high" — it's a hypothesis the merchant
    // may deliberately skip, so it can't outrank a measured fact. Cap it at
    // "medium" and mark it as a suggestion so the UI frames it as consider/test.
    let impact = impactFor(t);
    if (kind === "suggestion" && impact === "high") impact = "medium";
    return { area, text: t, kind, why: whyFor(t), fix: fixFor(t), impact, impactRank: IMPACT_RANK[impact] };
  };
  const allIssues = []
    .concat(seo.issues.map(mk("SEO")))
    .concat(perf.issues.map(mk("Performance")))
    .concat(mobile.issues.map(mk("Mobile")))
    .concat(schema.issues.map(mk("Structured data")))
    .concat(images.issues.map(mk("Images")))
    .concat(links.issues.map(mk("Links")))
    .concat(thirdParty.issues.map(mk("App bloat")))
    .concat(trust.issues.map(mk("Trust")))
    .concat(conversion.issues.map(mk("Conversion")))
    // Sort by business impact, then facts before suggestions within a tier — a
    // measured problem always reads above a conversion hypothesis. Stable sort
    // keeps area grouping within each group.
    .sort((a, b) => a.impactRank - b.impactRank || (a.kind === b.kind ? 0 : a.kind === "fact" ? -1 : 1));

  return {
    ok: true,
    url,
    finalUrl: res.url || url,
    isShopify: shopify.isShopify,
    shopifySignals: shopify.signals,
    overall,
    categories,
    coreWebVitals: pagespeed || null,
    details: { seo, schema, images, mobile, performance: perf, thirdParty, trust, links, conversion: { checks: conversion.checks } },
    issues: allIssues,
    recommendedApps: conversion.apps,
  };
}

module.exports = { validateUrl, fetchPage, auditUrl };
