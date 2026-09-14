/** CLI: npx tsx src/cli.ts <url> [--deep --token <challenge-token>] */
/**      npx tsx src/cli.ts check-deps <requirements.txt|pyproject.toml> [--strict] */
import { readFileSync } from "node:fs";
import { runScan, createChallenge, verifyOwnership } from "./engine";
import { scanDependencyManifest, exitCodeForFindings } from "./rules/settle-gating-deps";

const [url, ...flags] = process.argv.slice(2);

// Static dependency check: flag x402 Python pins in the settle-gating
// affected range (artifact-locked, see src/rules/settle-gating-deps.ts).
if (url === "check-deps") {
  const file = flags[0];
  if (!file) {
    console.error("usage: tsx src/cli.ts check-deps <requirements.txt|pyproject.toml> [--strict]");
    process.exit(1);
  }
  const findings = scanDependencyManifest(readFileSync(file, "utf8"));
  console.log(JSON.stringify({ file, findings }, null, 2));
  // Exit code maps to severity, not presence: critical -> 2, warning -> 0
  // (or 1 under --strict), info -> 0. A manifest-only conditional warning
  // whose own text exempts an adapter must not red that adapter's CI.
  const strict = flags.includes("--strict");
  process.exit(exitCodeForFindings(findings, strict));
}

if (!url) {
  console.error("usage: tsx src/cli.ts <url> [--deep --token <token>] [--challenge]");
  console.error("       tsx src/cli.ts check-deps <requirements.txt|pyproject.toml>");
  process.exit(1);
}

const deep = flags.includes("--deep");
const tokenIdx = flags.indexOf("--token");
const token = tokenIdx >= 0 ? flags[tokenIdx + 1] : undefined;

async function main() {
  if (flags.includes("--challenge")) {
    console.log(JSON.stringify(createChallenge(url), null, 2));
    return;
  }
  if (deep) {
    if (!token) {
      console.error("deep scan requires --token (get one with --challenge, then publish it at /.well-known/settle-verify.txt)");
      process.exit(1);
    }
    const ok = await verifyOwnership(url, token);
    if (!ok) {
      console.error("ownership not verified — publish the challenge token and retry within 30 minutes");
      process.exit(1);
    }
  }
  const report = await runScan(url, deep ? "deep" : "passive");
  console.log(JSON.stringify(report, null, 2));
}

main();
