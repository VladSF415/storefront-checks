// Free "Checkout Deadline Checker" engine. Flags a Shopify store's exposure to the
// 2026 Checkout Extensibility deadlines — the platform event that removes legacy
// checkout.liquid, locks the Additional Scripts field, and sunsets Shopify Scripts,
// reverting unmigrated stores to a default checkout and breaking Meta/GA attribution.
//
// Two honest layers (nothing is guessed):
//   1) DETECTED — legacy-tracking / migration risk signals we can actually see in a
//      storefront HTML fetch (inline Meta Pixel / GA / GTM vs the migrated Web Pixel;
//      legacy tracking patterns). Each failed check becomes a ranked finding.
//   2) VERIFY IN ADMIN — the authoritative "am I on legacy checkout" signal lives in
//      Settings -> Checkout (an "Upgrade" button), which is NOT externally fetchable.
//      So we return a dated checklist for the parts we can't see, and never claim
//      certainty we don't have.
//
// Pure fetch + Cheerio + rules — ZERO LLM / Anthropic tokens, no model calls, nothing
// stored. Reuses the store-auditor's SSRF-guarded validateUrl + fetchPage (same repo).
// Exports: validateUrl (re-export), checkCheckout(url) -> { ok, ...report }.

const cheerio = require("cheerio");
const { validateUrl, fetchPage } = require("./audit-engine");

const clamp = (n) => Math.max(0, Math.min(100, Math.round(n)));

// ── Dated deadline facts (single source of truth, used by the engine + surfaced to
// the page as citation bait). Verified via Shopify migration guides, Aug 2026. ─────
const DEADLINES = {
  scriptsSunset: "June 30, 2026",       // Shopify Scripts -> Functions
  additionalScriptsLocked: "August 28, 2025", // Additional Scripts field read-only; order-status/thank-you legacy
  hardBlockPlus: "August 13, 2026",     // checkout.liquid hard-block for Plus
  hardBlockAll: "August 26, 2026",      // legacy checkout removed for all stores -> default checkout
};

// ── Shopify detection (own light copy — the deep detector lives in audit-engine but
// isn't exported; this mirrors its signals so the tool only grades Shopify stores). ─
async function detectShopify(url, html, headers) {
  const signals = [];
  if (/cdn\.shopify\.com/i.test(html)) signals.push("cdn.shopify.com assets");
  if (/Shopify\.theme|window\.Shopify|shopify-features/i.test(html)) signals.push("Shopify JS globals");
  if (/myshopify\.com/i.test(html) || /myshopify\.com/i.test(url)) signals.push("myshopify.com");
  const powered = (headers.get && headers.get("powered-by")) || "";
  if (/shopify/i.test(powered)) signals.push("Powered-By header");
  if (headers.get && (headers.get("x-shopify-stage") || headers.get("x-shopid") || headers.get("x-shardid"))) signals.push("Shopify response headers");
  return { isShopify: signals.length > 0, signals };
}

// ── Signal detection from the storefront HTML ────────────────────────────────────
// Everything here is externally observable. We deliberately do NOT claim to see the
// checkout page itself (auth/cart gated) — only the tracking + migration signals a
// non-checkout page exposes, which is where the real post-lockdown breakage shows up.
function detectSignals($, html) {
  const s = {};

  // Migrated path (good): Shopify Web Pixels manager / custom web-pixel element.
  s.webPixel = /web-pixels-manager|shopify-web-pixels|web-pixel-|trekkie|monorail-edge\.shopifysvc\.com/i.test(html);

  // Legacy Meta Pixel injected inline (should be the Facebook & Instagram app + Web
  // Pixel now; inline fbq is the additional-scripts pattern that lost PII on lockdown).
  s.inlineMetaPixel = /fbq\s*\(\s*['"]init['"]|connect\.facebook\.net\/[^"']*\/fbevents\.js/i.test(html);

  // Legacy Google Analytics / gtag / Universal Analytics injected inline.
  s.inlineGA = /gtag\s*\(\s*['"]config['"]|www\.googletagmanager\.com\/gtag\/js|\bga\s*\(\s*['"]create['"]|google-analytics\.com\/analytics\.js/i.test(html);

  // Google Tag Manager container in the page (a common Additional Scripts remnant;
  // its checkout-side use is exactly what the lockdown broke).
  s.gtmContainer = /googletagmanager\.com\/gtm\.js|GTM-[A-Z0-9]{4,}/.test(html);

  // A raw dataLayer push tied to purchase/checkout — the classic legacy conversion
  // tracking that stopped receiving PII when Additional Scripts was locked.
  s.legacyPurchaseTracking = /dataLayer\.push\s*\(\s*\{[^}]*('|")?(event|ecommerce)('|")?\s*:/i.test(html) && /purchase|checkout|conversion/i.test(html);

  // If there IS a legacy purchase push, look at the value/currency it carries. A fired
  // event with no value, a zero value, or a hardcoded literal is the failure mode people
  // miss: the pixel "works" in a debugger but reports garbage revenue to the ad platform.
  // We can only inspect what's in the fetched HTML (server-side), so this is an on-page
  // signal, not proof of what GA4/Meta actually received — the checklist covers the rest.
  s.purchaseValueIssue = null;
  if (s.legacyPurchaseTracking) {
    // Grab a window around a purchase/conversion push to inspect its payload.
    const m = html.match(/dataLayer\.push\s*\(\s*\{[\s\S]{0,600}?(?:purchase|conversion|checkout)[\s\S]{0,600}?\}\s*\)/i);
    const blob = m ? m[0] : "";
    const hasValueKey = /['"]?(value|revenue|price|amount|total)['"]?\s*:/i.test(blob);
    const hasCurrencyKey = /['"]?currenc(y|yCode)['"]?\s*:/i.test(blob);
    // A value that's the literal 0, "0", or an empty string = broken revenue.
    const zeroValue = /['"]?(value|revenue|amount|total)['"]?\s*:\s*(['"]0*(\.0+)?['"]|0(\.0+)?)\s*[,}]/i.test(blob);
    if (blob) {
      if (!hasValueKey) s.purchaseValueIssue = "no-value";
      else if (zeroValue) s.purchaseValueIssue = "zero-value";
      else if (!hasCurrencyKey) s.purchaseValueIssue = "no-currency";
    }
  }

  // TikTok / other inline pixels (same additional-scripts class).
  s.otherInlinePixel = /ttq\.(track|load)|analytics\.tiktok\.com|snaptr\(|pintrk\(/i.test(html);

  // Any third-party tracker inline at all (rollup used for the summary).
  s.anyInlineTracker = s.inlineMetaPixel || s.inlineGA || s.gtmContainer || s.legacyPurchaseTracking || s.otherInlinePixel;

  // GA4 present but NOT via the inline-legacy path → it's running through the Shopify
  // web pixel (the migrated way). A green reassurance, not a gap. Only claim this when
  // a real G-XXXXXXXXXX id is on the page AND we didn't flag inline GA.
  s.hasGa4Id = /\bG-[A-Z0-9]{8,}\b/.test(html);
  s.ga4ViaPixel = s.hasGa4Id && !s.inlineGA && s.webPixel;

  // Marketing/email apps that historically injected checkout/order tracking through
  // the Additional Scripts field. Presence isn't a failure — it's a "verify this app
  // moved its tracking to a Web Pixel" nudge (the field is locked now).
  const APP_SIGS = [
    ["Klaviyo", /static\.klaviyo\.com|klaviyo\.js|klaviyoOnsite|_learnq/i],
    ["Omnisend", /omnisend|soundest/i],
    ["Attentive", /attentive\.com|__attentive/i],
    ["Postscript", /postscript\.io|__postscript/i],
    ["Yotpo", /yotpo\.com|yotpoTrackingId/i],
    ["Recharge", /rechargeapps\.com|rechargecdn/i],
  ];
  s.marketingApps = APP_SIGS.filter(([, re]) => re.test(html)).map(([name]) => name);

  // Theme name via the `Shopify.theme = {...}` global. A "Copy of…" (or empty) name is
  // a low-confidence neglect signal — informational only, never a scored fail.
  const tm = html.match(/Shopify\.theme\s*=\s*\{[^}]*?"name":"((?:[^"\\]|\\.)*)"/i);
  s.themeName = tm ? tm[1].replace(/\\\//g, "/").replace(/\\"/g, '"').trim() : null;
  s.themeNeglect = !!s.themeName && /copy of/i.test(s.themeName);

  return s;
}

// ── Checks -> weighted category score (mirrors the ai-shopping-engine pattern) ────
// Each check: { label, ok, kind, w }. kind = "fact" (provable from the fetch) or
// "suggestion" (best-practice the merchant may reasonably handle differently).
function score(name, checks) {
  const total = checks.reduce((a, c) => a + c.w, 0) || 1;
  const got = checks.reduce((a, c) => a + (c.ok ? c.w : 0), 0);
  return { name, score: clamp((got / total) * 100), checks: checks.map(({ w, ...rest }) => rest) };
}

// Tracking & pixels — the externally-visible heart of the check. "ok" means the
// MIGRATED state (no legacy inline tracker / Web Pixel present).
function catTracking(s) {
  const c = [
    { label: "No legacy Meta Pixel injected inline", ok: !s.inlineMetaPixel, kind: "fact", w: 26 },
    { label: "No legacy Google Analytics / gtag injected inline", ok: !s.inlineGA, kind: "fact", w: 22 },
    { label: "No Google Tag Manager container in the page", ok: !s.gtmContainer, kind: "suggestion", w: 14 },
    { label: "No legacy purchase/conversion dataLayer tracking", ok: !s.legacyPurchaseTracking, kind: "fact", w: 18 },
    { label: "No other inline ad pixels (TikTok / Snap / Pinterest)", ok: !s.otherInlinePixel, kind: "suggestion", w: 8 },
    { label: "Shopify Web Pixels manager present (migrated tracking)", ok: s.webPixel, kind: "fact", w: 12 },
  ];
  // Only score the purchase value/currency check when there IS a legacy purchase push to
  // inspect — otherwise it's not applicable (a migrated store has nothing to read here).
  if (s.legacyPurchaseTracking) {
    const label = s.purchaseValueIssue === "no-value"
        ? "Legacy purchase event has no order value in its payload"
        : s.purchaseValueIssue === "zero-value"
        ? "Legacy purchase event reports a zero order value"
        : s.purchaseValueIssue === "no-currency"
        ? "Legacy purchase event has a value but no currency code"
        : "Legacy purchase event carries an order value and currency";
    c.push({ label, ok: !s.purchaseValueIssue, kind: "fact", w: 10 });
  }
  return score("Tracking & pixels", c);
}

// ── Findings: failed checks -> ranked issues with why + fix ───────────────────────
const WHY = [
  [/legacy meta pixel/i, `An inline Meta Pixel is the "Additional Scripts" pattern that stopped receiving customer data when Shopify locked that field on ${DEADLINES.additionalScriptsLocked}. Your Meta conversions can under-report, which drags reported ROAS down.`],
  [/legacy google analytics|gtag/i, `Inline Google Analytics in the theme/checkout is the legacy tracking path. After the ${DEADLINES.additionalScriptsLocked} lockdown it stops passing purchase data reliably, so GA4 logs conversions as unattributed sessions.`],
  [/google tag manager/i, "A GTM container that fed checkout tracking is exactly what the Additional Scripts lockdown broke. Purchase events routed through it can silently stop attributing revenue."],
  [/dataLayer|purchase\/conversion/i, "Legacy dataLayer purchase tracking depended on Additional Scripts running at checkout. That path is gone, so these conversions may no longer reach your ad platforms."],
  [/purchase event has no order value|reports a zero order value|no currency code/i, "A purchase event that fires with no value, a zero value, or no currency is the failure people miss: a pixel debugger shows the event firing and looks fine, but the ad platform records the wrong revenue (or none), so your ROAS and value-based bidding run on bad numbers. Seeing the value hardcoded in the page is a red flag that it isn't reading the real order total."],
  [/other inline ad pixels/i, "Inline TikTok/Snap/Pinterest pixels are the same legacy pattern. They need to move to the Web Pixel API or their official Shopify app or they lose checkout events."],
  [/web pixels manager/i, "Shopify's Web Pixels manager is the migrated way to run tracking after checkout extensibility. Not seeing it suggests your tracking may still rely on the legacy path that's being removed."],
  [/marketing app|klaviyo|omnisend|attentive|postscript|yotpo|recharge/i, "Email and marketing apps often used the Additional Scripts field to fire checkout and order events. That field is locked now, so any tracking they left there stopped working. Most have shipped a Web Pixel version, but old installs can still be on the broken path."],
];
const FIX = [
  [/legacy meta pixel/i, "Move Meta tracking to the official Facebook & Instagram app (which uses the Conversions API + Web Pixel). Remove the inline fbq snippet from your theme and Additional Scripts."],
  [/legacy google analytics|gtag/i, "Connect the Google & YouTube app so GA4 tracking runs through Shopify's supported integration, then remove the inline gtag/analytics snippet."],
  [/google tag manager/i, "Rebuild any checkout/purchase tags as a Custom Pixel via Settings > Customer events (Web Pixel API), or use the official channel apps. Don't rely on a GTM container for checkout events."],
  [/dataLayer|purchase\/conversion/i, "Recreate purchase/conversion tracking as a Custom Pixel in Settings > Customer events so it fires on the new checkout with customer data intact."],
  [/purchase event has no order value|reports a zero order value|no currency code/i, "Rebuild the purchase event as a Custom Pixel in Settings > Customer events and map value to the real order total (checkout.totalPrice.amount) and currency to checkout.currencyCode. Then place a low-value test order and confirm the exact value and currency show up in GA4 and each ad platform, not just that the event fired."],
  [/other inline ad pixels/i, "Add each ad platform via its official Shopify channel app or a Custom Pixel, then delete the inline snippet."],
  [/web pixels manager/i, "Set up your tracking through Settings > Customer events (Custom Pixels) and the official channel apps so it runs on the extensibility-based checkout."],
  [/marketing app|klaviyo|omnisend|attentive|postscript|yotpo|recharge/i, "Open the app and confirm its Shopify integration is on the Web Pixel / Customer events path, not the old Additional Scripts snippet. Update the app if it still asks you to paste code into Additional Scripts."],
];
function whyFor(t) { for (const [re, v] of WHY) if (re.test(t)) return v; return null; }
function fixFor(t) { for (const [re, v] of FIX) if (re.test(t)) return v; return null; }

// Impact: a legacy inline conversion tracker = high (it's actively losing attribution
// after the lockdown). Missing Web Pixel = medium. GTM/other = medium/low.
const HIGH = /legacy meta pixel|legacy google analytics|gtag|dataLayer|purchase\/conversion|no order value|zero order value|no currency code/i;
const LOW = /other inline ad pixels/i;
function impactFor(text, kind) {
  let imp = HIGH.test(text) ? "high" : LOW.test(text) ? "low" : "medium";
  if (kind === "suggestion" && imp === "high") imp = "medium"; // a suggestion never outranks a measured fact
  return imp;
}
const IMPACT_RANK = { high: 0, medium: 1, low: 2 };

// ── Admin checklist — the parts we CANNOT see from outside. Dated + actionable. ────
function adminChecklist() {
  return [
    { label: `Settings > Checkout shows an "Upgrade" button`, hint: `That means you're still on the legacy checkout. Unmigrated stores auto-revert to a default checkout by ${DEADLINES.hardBlockAll} (${DEADLINES.hardBlockPlus} for Plus).` },
    { label: "Any live Shopify Scripts (discounts, shipping, payment)", hint: `Shopify Scripts stopped running on ${DEADLINES.scriptsSunset}. Rebuild that logic as Shopify Functions or your custom discount/shipping/bundle rules silently stopped working.` },
    { label: "The Additional Scripts field still has code in it", hint: `That field was locked ${DEADLINES.additionalScriptsLocked}. Anything there no longer runs at checkout, so move it to Custom Pixels or official apps.` },
    { label: "Thank-you / order-status page customizations", hint: "Legacy order-status page edits don't carry over. Rebuild them as checkout UI extensions or post-purchase blocks." },
    { label: "checkout.liquid customizations in your theme", hint: "checkout.liquid is deprecated and being removed. Move branding to the Checkout Editor and logic to UI extensions + Functions." },
    { label: "Place a low-value test order after any tracking or checkout change", hint: "This is the one thing this checker can't do for you. We only see the storefront HTML, not what your ad platforms received. After any pixel, consent-banner, theme, or checkout change, buy something cheap and confirm the exact order value AND currency landed in GA4 and each ad platform. A pixel debugger showing an event firing does not prove the value and currency arrived correctly." },
  ];
}

// ── App funnel — map detected gaps to the most relevant app (Vlad's call). ─────────
function recommendApps(signals) {
  const apps = [];
  // Scripts -> Functions is the discount/bundle story: EZBundle + Quizzo are Function-based.
  apps.push({ app: "EZBundle", icon: "/icons/ezbundle.webp", why: "runs bundle & volume discounts as a Shopify Function, the supported replacement for the discount logic Scripts used to handle", url: "/ezbundle" });
  // Tracking/attribution breakage -> social proof + drops (pixel-aware) apps.
  if (signals.anyInlineTracker) {
    apps.push({ app: "PopBoost", icon: "/icons/popboost.webp", why: "recovers conversions with on-site social proof and urgency that don't depend on legacy checkout tracking", url: "/popboost" });
    apps.push({ app: "EZDrop", icon: "/icons/ezdrop.webp", why: "runs drops & waitlists with modern Web-Pixel-based tracking instead of the legacy Additional Scripts path", url: "/ezdrop" });
  }
  // Quizzo — discount at checkout via a Function (same migration story).
  apps.push({ app: "Quizzo", icon: "/icons/quizzo.webp", why: "applies quiz-driven discounts through a Shopify Function, the extensibility-safe way to give a cart discount", url: "/quizzo" });
  return apps;
}

// Host of a URL, lowercased, no leading www. Empty string on parse failure.
function hostOf(u) { try { return new URL(u).hostname.replace(/^www\./i, "").toLowerCase(); } catch { return ""; } }

// The store's OWN canonical/permanent host, if the page advertises a different one than
// the URL we were given (e.g. the .myshopify.com mirror of a custom domain, or vice
// versa). Lets the tool say "this is the same store as X" so identical scans make sense.
function canonicalStoreHost($, html, requestedUrl) {
  const reqHost = hostOf(requestedUrl);
  const cands = [];
  const canon = $('link[rel="canonical"]').attr("href");
  if (canon) cands.push(hostOf(canon));
  const ogUrl = $('meta[property="og:url"]').attr("content");
  if (ogUrl) cands.push(hostOf(ogUrl));
  const ms = html.match(/([a-z0-9-]+\.myshopify\.com)/i);
  if (ms) cands.push(ms[1].toLowerCase());
  for (const h of cands) {
    if (h && h !== reqHost) return h; // first host that differs from what was entered
  }
  return null;
}

// A password-protected / pre-launch Shopify store redirects to /password and serves a
// lock screen, NOT the real storefront. Scanning it would report a meaningless "no
// legacy tracking" 100 (the theme/tracking/apps are all hidden), so we detect it and
// return an honest "can't scan" state instead of a fabricated score.
function isPasswordPage(finalUrl, $, html) {
  if (/\/password\/?($|[?#])/i.test(finalUrl || "")) return true;
  if ($('form[action$="/password"], #login_form[action*="password"]').length) return true;
  if (/class="[^"]*password-dialog|template-password|Shopify\.template\s*=\s*"password"/i.test(html)) return true;
  return false;
}

// ── Orchestrator ─────────────────────────────────────────────────────────────────
async function checkCheckout(input) {
  const url = await validateUrl(input); // throws on bad/SSRF
  const { res, html } = await fetchPage(url);
  const $ = cheerio.load(html);
  const finalUrl = res.url || url;

  const shop = await detectShopify(url, html, res.headers);
  const signals = detectSignals($, html);

  // Locked storefront: honest "can't scan" state, never a fabricated 100. The deadline
  // checklist + deadlines still apply, so keep them.
  if (isPasswordPage(finalUrl, $, html)) {
    return {
      ok: true, url, finalUrl, isShopify: true, passwordProtected: true,
      shopifySignals: shop.signals,
      overall: null,
      scoreLabel: "Tracking",
      verdict: null,
      categories: [],
      issues: [],
      infoLines: [],
      adminChecklist: adminChecklist(),
      deadlines: DEADLINES,
      recommendedApps: recommendApps(signals),
      note: "This store is password-protected, so we can only see its lock screen, not the real storefront. Remove the password (Online Store > Preferences) or scan a public product URL, then re-run. The deadline checklist below still applies.",
    };
  }

  // Non-Shopify (or undetectable) store: be honest, don't fabricate a checkout score.
  if (!shop.isShopify) {
    return {
      ok: true, url, finalUrl: res.url || url, isShopify: false,
      shopifySignals: shop.signals,
      overall: null,
      scoreLabel: "Tracking",
      verdict: null,
      categories: [],
      issues: [],
      infoLines: [],
      adminChecklist: adminChecklist(),
      deadlines: DEADLINES,
      recommendedApps: recommendApps(signals),
      note: "We couldn't confirm this is a Shopify store from the page, so we can't grade its checkout signals. The deadlines below are Shopify-specific.",
    };
  }

  const tracking = catTracking(signals);
  const categories = [tracking];

  // The score measures TRACKING ONLY — the one thing observable from a storefront
  // fetch. It is deliberately NOT a whole-checkout-readiness score; the checkout
  // version and Shopify Scripts are admin-only (see verdict + adminChecklist).
  const trackingScore = clamp(tracking.score);

  // Findings from every failed tracking check.
  const issues = [];
  for (const cat of categories) {
    for (const chk of cat.checks) {
      if (chk.ok) continue;
      const kind = chk.kind || "fact";
      const impact = impactFor(chk.label, kind);
      issues.push({
        area: "Tracking",
        text: chk.label.replace(/^No /, "Legacy: ").replace(/ present \(migrated tracking\)/, ""),
        kind, impact, impactRank: IMPACT_RANK[impact],
        why: whyFor(chk.label), fix: fixFor(chk.label),
      });
    }
  }
  // Marketing/email apps → suggestion findings (verify each moved off Additional
  // Scripts). Not part of the tracking score; they're "check this" nudges.
  for (const app of signals.marketingApps) {
    const label = `${app} detected, verify its checkout tracking moved to a Web Pixel`;
    issues.push({
      area: "Apps", text: label, kind: "suggestion",
      impact: "medium", impactRank: IMPACT_RANK.medium,
      why: whyFor(app), fix: fixFor(app),
    });
  }
  issues.sort((a, b) => a.impactRank - b.impactRank || (a.kind === b.kind ? 0 : a.kind === "fact" ? -1 : 1));

  // Informational lines (never scored) — positive confirmations + low-confidence
  // context that make the result store-specific instead of generic.
  const infoLines = [];
  if (signals.ga4ViaPixel) infoLines.push({ tone: "ok", text: "GA4 is present and running through the Shopify Web Pixel (the migrated path), not an inline snippet. That's what you want." });
  if (signals.themeNeglect) infoLines.push({ tone: "warn", text: `Your live theme is named "${signals.themeName}", which looks like a working copy. Confirm this is the theme you actually maintain before the checkout auto-upgrade lands.` });
  const otherHost = canonicalStoreHost($, html, url);
  if (otherHost) infoLines.push({ tone: "info", text: `This is the same store as ${otherHost} (a custom domain and its .myshopify.com address scan identically).` });

  // Verdict — the honesty layer. Even a perfect tracking score isn't "you're safe":
  // the checkout version + Scripts live in admin, which we can't read.
  const verdict = trackingScore >= 100
    ? "No legacy tracking in your storefront, the best result we can measure from outside. But that's the ONLY part we can see. Whether you're still on the legacy checkout and whether Shopify Scripts are live are admin-only. Work the checklist below to confirm you're actually migrated before the deadline."
    : trackingScore >= 55
    ? "Some legacy tracking is still on your storefront (see below). Fix that, then work the admin checklist. The checkout version and Scripts are admin-only and this scan can't see them."
    : "Legacy tracking is still active on your storefront, so conversions are likely under-reporting now. Fix the items below, then confirm the admin-only checklist. Those are the parts no external tool can read.";

  return {
    ok: true,
    url,
    finalUrl: res.url || url,
    isShopify: true,
    shopifySignals: shop.signals,
    overall: trackingScore,
    scoreLabel: "Tracking",
    verdict,
    categories,
    signals,
    issues,
    infoLines,
    adminChecklist: adminChecklist(),
    deadlines: DEADLINES,
    recommendedApps: recommendApps(signals),
  };
}

module.exports = { validateUrl, checkCheckout, DEADLINES };
