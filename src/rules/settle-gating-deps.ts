/**
 * Settle-gating dependency rule (artifact-locked, see x402-foundation/x402#3465).
 *
 * Affected middlewares settle payment only for 2xx responses: paid 3xx/304
 * responses are delivered WITHOUT settlement.
 *
 * Version boundary verified wheel-by-wheel against published PyPI artifacts
 * on 2026-09-14 (sha256 in advisory; v2 ships exactly two middleware adapters):
 *   - x402 == 1.0.0, Flask AND FastAPI -> AFFECTED (2xx-only gate)
 *   - x402 >= 2.0.0 < 2.15.0, FLASK ONLY -> AFFECTED (flask.py:414 / :438-439)
 *   - x402 v2 FastAPI                   -> NOT affected (settles < 400 from 2.0.0)
 *   - x402 >= 2.15.0                    -> FIXED (PR #2826)
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

const FIXED: [number, number, number] = [2, 15, 0];
const REFERENCE = "https://github.com/x402-foundation/x402/issues/3465";
const SELF_CHECK =
  "Exposure requires a handler on a paid path that can return 3xx (redirects, " +
  "conditional GET/ETag) — audit paid paths and upgrade to x402>=2.15.0.";

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
      fixedIn: "2.15.0",
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
      fixedIn: "2.15.0",
      reference: REFERENCE,
      detail:
        `x402==${version}: the v2 FLASK middleware settles only for 2xx responses ` +
        `(flask.py gate; fixed in 2.15.0, PR #2826). The v2 FastAPI middleware settled ` +
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
            `delivered without settlement. Fixed in 2.15.0 (PR #2826). ${SELF_CHECK}`,
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
            `affected. Still recommend upgrading to >= 2.15.0.`,
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
