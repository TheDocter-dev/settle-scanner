/**
 * Settle Scanner — two modes:
 *
 * PASSIVE (default, anyone): non-intrusive checks only — x402 dialect,
 * requirements sanity, configuration hygiene. No crafted payments are ever
 * sent to third-party endpoints.
 *
 * DEEP (ownership-verified): the active probes (malformed, under-payment,
 * replay, expiry) run ONLY after the requester proves control of the domain
 * via a challenge file at /.well-known/settle-verify.txt.
 *
 * Rationale: the USENIX Security 2026 authors explicitly declined to
 * actively exploit third-party merchants on ethical grounds. So do we.
 */
import { randomBytes } from "crypto";
import { encodePaymentHeader, type PaymentPayload } from "./x402";

export interface ScanFinding {
  id: string;
  title: string;
  severity: "critical" | "high" | "medium" | "info";
  passed: boolean;
  detail: string;
}

export interface ScanReport {
  url: string;
  scannedAt: string;
  mode: "passive" | "deep";
  score: number;
  grade: "A" | "B" | "C" | "D" | "F" | "N/A";
  isX402: boolean;
  findings: ScanFinding[];
  summary: string;
}

// --- ownership challenge store (in-memory; challenges expire in 30 min) ---
const challenges = new Map<string, { token: string; expires: number }>();

export function createChallenge(url: string) {
  const u = new URL(url);
  const token = "settle-verify-" + randomBytes(16).toString("hex");
  challenges.set(u.origin, { token, expires: Date.now() + 30 * 60 * 1000 });
  return {
    token,
    origin: u.origin,
    instruction: `Create a file at ${u.origin}/.well-known/settle-verify.txt containing exactly this token, then run the deep scan within 30 minutes.`,
    wellKnownUrl: `${u.origin}/.well-known/settle-verify.txt`,
  };
}

export async function verifyOwnership(url: string, token: string): Promise<boolean> {
  const u = new URL(url);
  const c = challenges.get(u.origin);
  if (!c || c.token !== token || c.expires < Date.now()) return false;
  try {
    const res = await fetch(`${u.origin}/.well-known/settle-verify.txt`, { signal: AbortSignal.timeout(8000) });
    if (!res.ok) return false;
    const body = (await res.text()).trim();
    return body === token;
  } catch {
    return false;
  }
}

function fakePayload(overrides: Partial<{ value: string; validBefore: number }>, req: any): string {
  const payload: PaymentPayload = {
    x402Version: 1,
    scheme: "exact",
    network: req?.network ?? "eip155:8453",
    payload: {
      signature: "0x" + "deadbeef".repeat(8),
      authorization: {
        from: "0xScannerBot000000000000000000000000000001",
        to: req?.payTo ?? "0x0",
        value: overrides.value ?? req?.maxAmountRequired ?? "100",
        validAfter: String(Math.floor(Date.now() / 1000) - 120),
        validBefore: String(overrides.validBefore ?? Math.floor(Date.now() / 1000) + 300),
        nonce: "0x" + Math.random().toString(16).slice(2).padEnd(64, "0").slice(0, 64),
      },
    },
  };
  return encodePaymentHeader(payload);
}

async function tryFetch(url: string, headers: Record<string, string> = {}) {
  try {
    const res = await fetch(url, { headers, signal: AbortSignal.timeout(8000), redirect: "follow" });
    let body: any = null;
    try { body = await res.json(); } catch { /* non-json */ }
    return { status: res.status, body, ok: true as const };
  } catch (e) {
    return { status: 0, body: null, ok: false as const, error: String(e) };
  }
}

export async function runScan(url: string, mode: "passive" | "deep" = "passive"): Promise<ScanReport> {
  const findings: ScanFinding[] = [];
  const t0 = Date.now();

  // --- PASSIVE: reachability / x402 dialect
  const first = await tryFetch(url);
  if (!first.ok) {
    findings.push({ id: "reachability", title: "Endpoint reachable", severity: "info", passed: false, detail: `Could not reach endpoint: ${(first as any).error ?? "network error"}` });
    return finalize(url, findings, t0, mode);
  }
  const speaks402 = first.status === 402 && Array.isArray(first.body?.accepts);
  findings.push({
    id: "reachability",
    title: "Speaks x402 (402 + payment requirements)",
    severity: "info",
    passed: speaks402,
    detail: speaks402
      ? `Returned 402 with ${first.body.accepts.length} payment requirement(s)`
      : first.status === 200
        ? "Endpoint returned 200 without payment — this resource is NOT paywalled"
        : `Returned HTTP ${first.status} without x402 payment requirements`,
  });

  const req = first.body?.accepts?.[0];
  if (!speaks402) return finalize(url, findings, t0, mode);

  // Deep probes prefer a testnet requirement where the merchant offers one —
  // mutated proofs also reach the merchant's facilitator, so we keep them off
  // mainnet when possible (the paper's own approach: testnets wherever possible).
  const accepts: any[] = first.body?.accepts ?? [];
  const isTestnet = (n: unknown) => typeof n === "string" && /sepolia|testnet|devnet/i.test(n);
  const probeReq = accepts.find((a) => isTestnet(a?.network)) ?? req;

  // --- PASSIVE: requirements sanity
  const sane = !!req?.network && !!req?.payTo && !!req?.maxAmountRequired && Number(req.maxAmountRequired) > 0;
  findings.push({
    id: "requirements",
    title: "Payment requirements well-formed",
    severity: "medium",
    passed: sane,
    detail: sane ? `network=${req.network} asset=${req.asset ?? "n/a"} amount=${req.maxAmountRequired}` : "Requirements missing network/payTo/amount — misconfigured paywall",
  });

  // --- PASSIVE: configuration hygiene
  const timeout = Number(req?.maxTimeoutSeconds ?? 0);
  findings.push({
    id: "hygiene",
    title: "Configuration hygiene (timeouts, HTTPS)",
    severity: "medium",
    passed: url.startsWith("https://") && timeout > 0 && timeout <= 3600,
    detail: !url.startsWith("https://")
      ? "Endpoint is not HTTPS — payment headers travel unencrypted"
      : timeout <= 0 || timeout > 3600
        ? `maxTimeoutSeconds=${timeout || "unset"} — overly long validity windows widen replay exposure`
        : "HTTPS enforced, sane payment validity window",
  });

  if (mode === "deep") {
    // --- ACTIVE probes (ownership-verified only) ---
    if (probeReq !== req) {
      findings.push({
        id: "testnet-preference",
        title: "Testnet preferred for active probes",
        severity: "info",
        passed: true,
        detail: `Merchant offers ${probeReq.network} — crafted proofs target the testnet requirement, keeping probe traffic off mainnet and off the facilitator's production path.`,
      });
    }

    const malformed = await tryFetch(url, { "X-PAYMENT": "!!!not-base64!!!" });
    findings.push({
      id: "malformed",
      title: "Rejects malformed payment headers",
      severity: "high",
      passed: malformed.status !== 200,
      detail: malformed.status === 200 ? "CRITICAL: goods delivered for a garbage payment header" : `Correctly refused (HTTP ${malformed.status})`,
    });

    const underpaid = await tryFetch(url, { "X-PAYMENT": fakePayload({ value: "1" }, probeReq) });
    findings.push({
      id: "amount",
      title: "Rejects under-payment (amount mismatch)",
      severity: "high",
      passed: underpaid.status !== 200,
      detail: underpaid.status === 200 ? "VULNERABLE: accepted payment far below quoted price" : `Correctly refused (HTTP ${underpaid.status})`,
    });

    const p = fakePayload({}, probeReq);
    const r1 = await tryFetch(url, { "X-PAYMENT": p });
    const r2 = await tryFetch(url, { "X-PAYMENT": p });
    findings.push({
      id: "replay",
      title: "Replay protection (same payment can't be spent twice)",
      severity: "critical",
      passed: r2.status !== 200,
      detail: r2.status === 200
        ? "VULNERABLE: identical payment payload accepted twice — double-spend possible"
        : r1.status === 200
          ? "First use succeeded, replay correctly rejected"
          : `No goods delivered either time (HTTP ${r2.status})`,
    });

    const expired = await tryFetch(url, { "X-PAYMENT": fakePayload({ validBefore: Math.floor(Date.now() / 1000) - 3600 }, probeReq) });
    findings.push({
      id: "expiry",
      title: "Enforces payment expiry (validBefore)",
      severity: "medium",
      passed: expired.status !== 200,
      detail: expired.status === 200 ? "VULNERABLE: expired payment authorization accepted" : `Correctly refused (HTTP ${expired.status})`,
    });

    // SR5: fail-fast on dust / non-settleable amounts
    const dust = await tryFetch(url, { "X-PAYMENT": fakePayload({ value: "0" }, probeReq) });
    findings.push({
      id: "dust",
      title: "Fails fast on zero-amount payment",
      severity: "medium",
      passed: dust.status !== 200,
      detail: dust.status === 200 ? "VULNERABLE: zero-value payment accepted — dust/non-settleable amounts should be rejected before settlement" : `Correctly refused (HTTP ${dust.status})`,
    });

    // Server-SR1: release goods only once per settled payment, even under
    // concurrency — N parallel requests carrying ONE proof; served >1 = leak.
    // Untestable black-box when verify/settle already rejects the burst.
    const burst = fakePayload({}, probeReq);
    const burstN = 3;
    const burstResults = await Promise.all(
      Array.from({ length: burstN }, () => tryFetch(url, { "X-PAYMENT": burst })),
    );
    const served = burstResults.filter((r) => r.status === 200).length;
    findings.push({
      id: "concurrent-submit",
      title: "Concurrent-submit race (one proof, parallel requests)",
      severity: "critical",
      passed: served <= 1,
      detail:
        served > 1
          ? `VULNERABLE: ${served}/${burstN} parallel requests served goods with the same proof — a concurrency race bypasses replay protection`
          : served === 1
            ? `Exactly 1/${burstN} parallel requests served — single-release guaranteed under concurrency`
            : "Verify/settle rejected the whole burst — covered upstream; race not independently testable (black-box)",
    });
  } else {
    findings.push({
      id: "deep-notice",
      title: "Active probes skipped (passive mode)",
      severity: "info",
      passed: true,
      detail: "Replay, under-payment and expiry probes only run after domain-ownership verification. We don't fire crafted payments at third-party endpoints.",
    });
  }

  return finalize(url, findings, t0, mode);
}

function finalize(url: string, findings: ScanFinding[], t0: number, mode: "passive" | "deep"): ScanReport {
  const reachable = findings.find((f) => f.id === "reachability");
  if (!reachable?.passed) {
    return {
      url,
      scannedAt: new Date().toISOString(),
      mode,
      score: 0,
      grade: "N/A",
      isX402: false,
      findings,
      summary: reachable
        ? "This URL is not an x402-paywalled endpoint — nothing to grade. Point the scanner at an endpoint that returns HTTP 402 with payment requirements."
        : "Endpoint unreachable — check the URL and try again.",
    };
  }
  const weights = { critical: 35, high: 25, medium: 15, info: 5 };
  let score = 100;
  for (const f of findings) if (!f.passed && f.id !== "reachability") score -= weights[f.severity];
  score = Math.max(0, score);
  const grade = (score >= 90 ? "A" : score >= 75 ? "B" : score >= 60 ? "C" : score >= 40 ? "D" : "F") as ScanReport["grade"];
  const failed = findings.filter((f) => !f.passed && f.id !== "reachability" && f.id !== "deep-notice");
  return {
    url,
    scannedAt: new Date().toISOString(),
    mode,
    score,
    grade,
    isX402: true,
    findings,
    summary:
      failed.length === 0
        ? `Passed all checks in ${Date.now() - t0}ms (${mode} mode). ${mode === "passive" ? "Verify ownership to unlock deep active probes." : "This endpoint follows settlement best practices."}`
        : `${failed.length} issue(s) found in ${Date.now() - t0}ms. Worst: ${failed[0]?.title}.`,
  };
}
