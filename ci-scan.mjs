#!/usr/bin/env node
import { chromium } from "@playwright/test";
import { createServer } from "node:http";
import { readFile, stat } from "node:fs/promises";
import { existsSync, writeFileSync } from "node:fs";
import { extname, join, resolve, normalize } from "node:path";
import { spawnSync } from "node:child_process";

function arg(name, fallback = "") {
  const i = process.argv.indexOf(`--${name}`);
  return i >= 0 ? process.argv[i + 1] : fallback;
}
const appRoot = resolve(arg("app", process.cwd()));
const repoRoot = resolve(arg("repo", process.cwd()));
const failOn = (arg("fail-on", process.env.PIPELINE_GUARD_FAIL_ON || "high") || "high").toLowerCase();
const out = resolve(arg("sarif", join(repoRoot, "pipeline-guard.sarif")));
const port = Number(arg("port", "4173"));
const threshold = { none: 99, critical: 4, high: 3, medium: 2, low: 1, info: 0 }[failOn];
if (threshold === undefined) {
  console.error(`Invalid --fail-on "${failOn}". Use none, critical, high, medium, low, or info.`);
  process.exit(2);
}

const work = join(repoRoot, ".pipelineguard");
const zipPath = join(work, "repository.zip");
spawnSync("mkdir", ["-p", work], { stdio: "inherit" });
const archive = spawnSync("git", ["archive", "--format=zip", "-o", zipPath, "HEAD"], { cwd: repoRoot, stdio: "inherit" });
if (archive.status !== 0 || !existsSync(zipPath)) {
  console.error("Pipeline Guard could not create a repository ZIP with git archive.");
  process.exit(2);
}

const mime = { ".html":"text/html", ".js":"text/javascript", ".css":"text/css", ".json":"application/json", ".png":"image/png", ".svg":"image/svg+xml" };
const server = createServer(async (req, res) => {
  try {
    const rel = req.url === "/" ? "index.html" : decodeURIComponent(req.url.split("?")[0]).replace(/^\/+/, "");
    const file = normalize(join(appRoot, rel));
    if (!file.startsWith(appRoot)) throw new Error("bad path");
    const s = await stat(file);
    if (!s.isFile()) throw new Error("not file");
    res.writeHead(200, { "content-type": mime[extname(file)] || "application/octet-stream", "cache-control":"no-store" });
    res.end(await readFile(file));
  } catch {
    res.writeHead(404); res.end("Not found");
  }
});
await new Promise(resolveReady => server.listen(port, "127.0.0.1", resolveReady));

let browser;
try {
  browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  await page.goto(`http://127.0.0.1:${port}/`, { waitUntil: "networkidle" });
  await page.setInputFiles("#fileInput", zipPath);
  await page.waitForFunction(() => !document.querySelector("#scanBtn")?.disabled, null, { timeout: 30000 });
  await page.click("#scanBtn");
  await page.waitForFunction(() => !!window.PipelineGuard070 && document.querySelector("#scoreValue")?.textContent !== "—", null, { timeout: 60000 });

  const findings = await page.evaluate(() => window.PipelineGuard070.collectFindings().filter(f => !f.suppressed));
  const sarif = await page.evaluate(f => window.PipelineGuard070.sarifFromFindings(f, "GitHub Actions repository scan"), findings);
  writeFileSync(out, JSON.stringify(sarif, null, 2));

  const rank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const counts = { critical:0, high:0, medium:0, low:0, info:0 };
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
    const esc = v => String(v || "").replace(/%/g,"%25").replace(/\r/g,"%0D").replace(/\n/g,"%0A").replace(/:/g,"%3A").replace(/,/g,"%2C");
    const level = rank[f.severity] >= 3 ? "error" : rank[f.severity] >= 2 ? "warning" : "notice";
    const loc = f.file && !/\.zip$/i.test(f.file) ? ` file=${esc(f.file)}${f.line ? `,line=${f.line}` : ""},` : "";
    console.log(`::${level}${loc}title=${esc(`Pipeline Guard: ${f.severity.toUpperCase()} · ${f.rule}`)}::${esc(`${f.title} — ${f.remediation || f.description}`)}`);
  }

  const summary = `Pipeline Guard v0.7.0: ${findings.length} active finding(s) — ${counts.critical} critical, ${counts.high} high, ${counts.medium} medium, ${counts.low} low, ${counts.info} info. Gate: ${failOn}.`;
  console.log(summary);
  if (process.env.GITHUB_STEP_SUMMARY) {
    writeFileSync(process.env.GITHUB_STEP_SUMMARY,
      `## Pipeline Guard v0.7.0\n\n${summary}\n\nSARIF artifact: \`pipeline-guard.sarif\`\n`,
      { flag: "a" });
  }

  const blocking = findings.filter(f => rank[f.severity] >= threshold);
  process.exitCode = blocking.length ? 1 : 0;
  if (blocking.length) console.error(`Severity gate failed: ${blocking.length} finding(s) at or above ${failOn}.`);
} finally {
  if (browser) await browser.close();
  server.close();
}