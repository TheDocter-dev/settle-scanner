/**
 * Settle-gating dependency rule v0.3 (artifact-locked, see x402-foundation/x402#3465).
 *
 * v0.3 changelog (user-facing): v2 Flask range corrected from `< 2.15.0` to
 * `< 2.11.0`; 2.11.0-2.14.0 no longer flagged.
 *
 * Correction (4 Oct 2026): the v2 Flask settlement gate widened from 2xx-only to
 * <400 at release 2.11.0 (PR #2388, merged 20 May 2026), not at 2.15.0 as
 * previously stated; PR #2826 (2.15.0) fixed a main-branch regression of the same
 * guard that did not reach a shipped release. Affected range for the 2xx-only
 * Flask gate: >= 2.0.0, < 2.11.0. Verified wheel-by-wheel; see Ledger rows
 * 2.11.0-2.15.0.
 *
 * Gate predicate table — generated from verified Settle Ledger rows
 * (TheDocter-dev/settle-ledger, releases/), direct wheel reads 2026-10-03/04:
 *   - x402 == 1.0.0, Flask AND FastAPI -> 2xx-only gate, BOTH affected
 *   - x402 2.0.0 - 2.10.x, FLASK ONLY  -> 2xx-only gate, Flask affected;
 *     FastAPI settles < 400 from 2.0.0, NOT affected at any v2 release
 *   - x402 >= 2.11.0                   -> both adapters settle < 400
 *     (2.11.0 also added cancellation of the settlement dispatch on >=400,
 *      PR #2388); PR #2826 (2.15.0) fixed a main-only guard regression
 *   - x402 0.x                         -> no x402/http/middleware adapters;
 *     settle gate N/A
 *
 * Severity model: a v1 pin is critical outright (both adapters affected).
 * A v2 in-range pin is a WARNING naming the Flask condition unless source
 * access confirms the Flask middleware import — then it upgrades to critical.
 */

export interface DepFinding {
  id: string;
  title: string;
  severity: "critical" | "warning" | "info";
  spec: string;
  fixedIn: string;
  reference: string;
  detail: string;
}

export function parseVersion(v: string): [number, number, number] | null {
  const m = v.trim().match(/^(\d+)\.(\d+)\.(\d+)/);
  return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
}

function lt(a: [number, number, number], b: [number, number, number]): boolean {
  for (let i = 0; i < 3; i++) {
    if (a[i] !== b[i]) return a[i] < b[i];
  }
  return false;
}

/**
 * Gate predicate table consumed by checkX402PythonPin.
 * Source of truth: verified Ledger rows (wheel sha256 = PyPI index digest = row).
 * Regenerate from the Ledger when new rows verify; do not hand-edit predicates.
 */
export const GATE_TABLE = [
  { range: "1.0.0",           flask: "2xx-only", fastapi: "2xx-only", flaskAffected: true,  fastapiAffected: true  },
  { range: "2.0.0 - 2.10.x",  flask: "2xx-only", fastapi: "<400",     flaskAffected: true,  fastapiAffected: false },
  { range: ">= 2.11.0",       flask: "<400",     fastapi: "<400",     flaskAffected: false, fastapiAffected: false },
] as const;

const FIXED: [number, number, number] = [2, 11, 0];
const REFERENCE = "https://github.com/x402-foundation/x402/issues/3465";
const LEDGER = "https://github.com/TheDocter-dev/settle-ledger/tree/main/releases";
const SELF_CHECK =
  "Exposure requires a handler on a paid path that can return 3xx (redirects, " +
  "conditional GET/ETag) — audit paid paths and upgrade to x402>=2.11.0.";

/** Evaluate a pinned x402 Python version. Null if not in any affected range. */
export function checkX402PythonPin(version: string): DepFinding | null {
  const v = parseVersion(version);
  if (!v) return null;
  if (v[0] === 1) {
    return {
      id: "settle-gating-3xx",
      title: "Paid 3xx responses delivered without settlement (settle-gating)",
      severity: "critical",
      spec: `x402==${version}`,
      fixedIn: "2.11.0",
      reference: REFERENCE,
      detail:
        `x402==${version} (v1, deprecated) settles payment only for 2xx responses in ` +
        `BOTH its Flask and FastAPI middlewares. A paid route returning 3xx (redirect, ` +
        `304 Not Modified) is delivered to the client without settlement. ${SELF_CHECK}`,
    };
  }
  if (v[0] === 2 && lt(v, FIXED)) {
    return {
      id: "settle-gating-3xx",
      title: "Paid 3xx responses delivered without settlement (settle-gating, Flask only)",
      severity: "warning",
      spec: `x402==${version}`,
      fixedIn: "2.11.0",
      reference: REFERENCE,
      detail:
        `x402==${version}: the v2 FLASK middleware settles only for 2xx responses ` +
        `(flask.py gate; widened to <400 at 2.11.0, PR #2388 — correction 4 Oct 2026, ` +
        `verified wheel-by-wheel: ${LEDGER}). The v2 FastAPI middleware settled ` +
        `< 400 from 2.0.0 and is NOT affected. AFFECTED ONLY IF this service uses the ` +
        `Flask middleware (x402.http.middleware.flask / x402.flask). ${SELF_CHECK}`,
    };
  }
  return null;
}

/** Detect which x402 Python middleware a source tree uses. */
export function detectAdapterUsage(sourceText: string): {
  flask: boolean;
  fastapi: boolean;
} {
  return {
    flask: /x402\.flask|x402\.http\.middleware\.flask|PaymentMiddleware/.test(sourceText),
    fastapi: /x402\.fastapi|x402\.http\.middleware\.fastapi|require_payment/.test(sourceText),
  };
}

/**
 * Scan dependency-manifest text (requirements.txt or pyproject.toml) for an
 * x402 Python pin in an affected range. At most one finding per distinct pin.
 */
export function scanDependencyManifest(text: string): DepFinding[] {
  const findings: DepFinding[] = [];
  const patterns = [/^x402==([0-9][^\s;#]*)/gm, /["']x402==([0-9][^"']*)["']/g];
  for (const re of patterns) {
    for (const m of text.matchAll(re)) {
      const f = checkX402PythonPin(m[1]);
      if (f && !findings.some((x) => x.spec === f.spec)) findings.push(f);
    }
  }
  return findings;
}

/**
 * Refine manifest findings with source access: a v2 in-range finding upgrades
 * to critical if the Flask middleware is imported, and is dropped to info if
 * ONLY FastAPI usage is found (never affected at any v2 release).
 */
export function refineWithSource(findings: DepFinding[], sourceText: string): DepFinding[] {
  const usage = detectAdapterUsage(sourceText);
  return findings
    .map((f) => {
      if (!f.spec.startsWith("x402==2.")) return f; // v1: both adapters affected
      if (usage.flask) {
        return {
          ...f,
          severity: "critical" as const,
          detail:
            `CONFIRMED: this source tree imports the x402 Flask middleware, which on ` +
            `${f.spec} settles only for 2xx responses. A paid route returning 3xx is ` +
            `delivered without settlement. Widened to <400 at 2.11.0 (PR #2388). ${SELF_CHECK}`,
        };
      }
      if (usage.fastapi && !usage.flask) {
        return {
          ...f,
          severity: "info" as const,
          title: "Settle-gating range pin, but only FastAPI usage detected (not affected)",
          detail:
            `${f.spec} is in the v2 Flask-affected range, but this source tree only ` +
            `imports the FastAPI middleware, which settled < 400 from 2.0.0 and is not ` +
            `affected. Still recommend upgrading to >= 2.11.0.`,
        };
      }
      return f; // no adapter usage found: keep the conditional warning
    });
}

/**
 * Map findings to a process exit code by severity, not presence:
 * critical -> 2, warning -> 0 (1 under --strict), info -> 0.
 * A manifest-only conditional warning whose own text exempts an adapter
 * must not red that adapter's CI.
 */
export function exitCodeForFindings(findings: DepFinding[], strict = false): 0 | 1 | 2 {
  if (findings.some((f) => f.severity === "critical")) return 2;
  if (strict && findings.some((f) => f.severity === "warning")) return 1;
  return 0;
}
