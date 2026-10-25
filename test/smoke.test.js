// Offline tests: no network calls. Run with `npm test`.
const { test } = require("node:test");
const assert = require("node:assert/strict");
const { spawn, spawnSync } = require("node:child_process");
const path = require("node:path");
const lib = require("..");

const ROOT = path.join(__dirname, "..");

test("gtinValid accepts a correct check digit and rejects a wrong one", () => {
  // GS1's worked GTIN-13 example: 629104150021 + check digit 3
  assert.equal(lib.gtinValid("6291041500213"), true);
  assert.equal(lib.gtinValid("6291041500214"), false);
});

test("validateUrl refuses localhost and non-web schemes", async () => {
  await assert.rejects(lib.validateUrl("http://localhost:3000/"), /Localhost/);
  await assert.rejects(lib.validateUrl("ftp://example.com/file"), /HTTP/);
  await assert.rejects(lib.validateUrl("not a url"), /Invalid URL/);
});

test("the CLI prints usage", () => {
  const ok = spawnSync(process.execPath, [path.join(ROOT, "bin/cli.js"), "--help"], { encoding: "utf8" });
  assert.equal(ok.status, 0);
  assert.match(ok.stdout, /Usage: storefront-checks <command> <url>/);
  const bad = spawnSync(process.execPath, [path.join(ROOT, "bin/cli.js"), "nope", "https://example.com"], { encoding: "utf8" });
  assert.equal(bad.status, 1);
});

test("the MCP server answers initialize and lists its four tools", async () => {
  const child = spawn(process.execPath, [path.join(ROOT, "bin/mcp.mjs")], { stdio: ["pipe", "pipe", "inherit"] });
  const replies = [];
  let buf = "";
  child.stdout.on("data", (d) => {
    buf += d;
    let i;
    while ((i = buf.indexOf("\n")) >= 0) {
      const line = buf.slice(0, i).trim();
      buf = buf.slice(i + 1);
      if (line) replies.push(JSON.parse(line));
    }
  });
  const send = (msg) => child.stdin.write(JSON.stringify(msg) + "\n");
  const waitFor = async (id) => {
    for (let t = 0; t < 100; t++) {
      const r = replies.find((x) => x.id === id);
      if (r) return r;
      await new Promise((res) => setTimeout(res, 50));
    }
    throw new Error(`no reply to ${id}`);
  };
  try {
    send({ jsonrpc: "2.0", id: 1, method: "initialize", params: { protocolVersion: "2025-06-18", capabilities: {}, clientInfo: { name: "test", version: "0" } } });
    const init = await waitFor(1);
    assert.equal(init.result.serverInfo.name, "storefront-checks");
    send({ jsonrpc: "2.0", method: "notifications/initialized" });
    send({ jsonrpc: "2.0", id: 2, method: "tools/list" });
    const list = await waitFor(2);
    const names = list.result.tools.map((t) => t.name).sort();
    assert.deepEqual(names, ["audit_store", "check_ai_shopping_readiness", "check_merchant_center", "check_shopify_checkout"]);
    for (const t of list.result.tools) assert.ok(t.inputSchema.properties.url, `${t.name} takes a url`);
  } finally {
    child.kill();
  }
});
