/** CLI: npx tsx src/cli.ts <url> [--deep --token <challenge-token>] */
import { runScan, createChallenge, verifyOwnership } from "./engine";

const [url, ...flags] = process.argv.slice(2);
if (!url) {
  console.error("usage: tsx src/cli.ts <url> [--deep --token <token>] [--challenge]");
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
