import { describe, it, expect } from "vitest";
import {
  parseVersion,
  checkX402PythonPin,
  scanDependencyManifest,
  detectAdapterUsage,
  refineWithSource,
  exitCodeForFindings,
} from "../src/rules/settle-gating-deps";

describe("parseVersion", () => {
  it("parses semver triples", () => {
    expect(parseVersion("1.0.0")).toEqual([1, 0, 0]);
    expect(parseVersion("2.15.0")).toEqual([2, 15, 0]);
    expect(parseVersion("2.10.0.post1")).toEqual([2, 10, 0]);
  });
  it("rejects junk", () => {
    expect(parseVersion("latest")).toBeNull();
    expect(parseVersion("2.x")).toBeNull();
  });
});

describe("checkX402PythonPin (wheel-verified boundary, 2026-09-14)", () => {
  it("flags v1 as critical (both adapters affected)", () => {
    const f = checkX402PythonPin("1.0.0");
    expect(f).not.toBeNull();
    expect(f!.severity).toBe("critical");
    expect(f!.fixedIn).toBe("2.15.0");
  });
  it("flags v2 in-range as a Flask-conditional warning, not critical", () => {
    for (const v of ["2.0.0", "2.10.0", "2.14.9"]) {
      const f = checkX402PythonPin(v);
      expect(f).not.toBeNull();
      expect(f!.severity).toBe("warning");
      expect(f!.detail).toContain("Flask");
      expect(f!.detail).toContain("FastAPI");
    }
  });
  it("passes the fixed boundary and later", () => {
    expect(checkX402PythonPin("2.15.0")).toBeNull();
    expect(checkX402PythonPin("2.16.1")).toBeNull();
    expect(checkX402PythonPin("3.0.0")).toBeNull();
  });
});

describe("detectAdapterUsage", () => {
  it("detects v1-style imports", () => {
    expect(detectAdapterUsage("from x402.flask.middleware import PaymentMiddleware").flask).toBe(true);
    expect(detectAdapterUsage("from x402.fastapi.middleware import require_payment").fastapi).toBe(true);
  });
  it("detects v2-style imports", () => {
    expect(detectAdapterUsage("from x402.http.middleware.flask import ...").flask).toBe(true);
    expect(detectAdapterUsage("x402.http.middleware.fastapi").fastapi).toBe(true);
  });
});

describe("refineWithSource", () => {
  it("upgrades a v2 in-range finding to critical when Flask is imported", () => {
    const f = scanDependencyManifest("x402==2.10.0\n");
    const refined = refineWithSource(f, "from x402.http.middleware.flask import foo");
    expect(refined[0].severity).toBe("critical");
    expect(refined[0].detail).toContain("CONFIRMED");
  });
  it("downgrades to info when only FastAPI usage is found (never affected in v2)", () => {
    const f = scanDependencyManifest("x402==2.10.0\n");
    const refined = refineWithSource(f, "from x402.fastapi.middleware import require_payment");
    expect(refined[0].severity).toBe("info");
  });
  it("never downgrades v1 (both adapters affected)", () => {
    const f = scanDependencyManifest("x402==1.0.0\n");
    const refined = refineWithSource(f, "from x402.fastapi.middleware import require_payment");
    expect(refined[0].severity).toBe("critical");
  });
  it("keeps the conditional warning when no adapter usage is found", () => {
    const f = scanDependencyManifest("x402==2.10.0\n");
    const refined = refineWithSource(f, "import requests");
    expect(refined[0].severity).toBe("warning");
  });
});

describe("scanDependencyManifest", () => {
  it("catches requirements.txt pins", () => {
    const findings = scanDependencyManifest("flask==3.0.0\nx402==1.0.0\n");
    expect(findings).toHaveLength(1);
    expect(findings[0].spec).toBe("x402==1.0.0");
  });
  it("catches pyproject-style pins", () => {
    expect(scanDependencyManifest('dependencies = ["fastapi>=0.110", "x402==2.10.0"]')).toHaveLength(1);
  });
  it("ignores fixed versions and unrelated packages", () => {
    expect(scanDependencyManifest("x402==2.15.0\nx402-fastapi==1.0.0\n")).toHaveLength(0);
  });
  it("does not double-report the same pin", () => {
    expect(scanDependencyManifest('x402==1.0.0\n"x402==1.0.0"')).toHaveLength(1);
  });
});

describe("exitCodeForFindings (severity maps to exit code, not presence)", () => {
  const crit = checkX402PythonPin("1.0.0")!;          // critical
  const warn = checkX402PythonPin("2.10.0")!;         // conditional warning
  const info = { ...warn, severity: "info" as const };

  it("critical finding exits 2", () => {
    expect(exitCodeForFindings([crit])).toBe(2);
    expect(exitCodeForFindings([warn, crit])).toBe(2);
  });
  it("warning-only findings exit 0 by default (FastAPI shop's CI stays green)", () => {
    expect(exitCodeForFindings([warn])).toBe(0);
  });
  it("warning exits 1 under --strict", () => {
    expect(exitCodeForFindings([warn], true)).toBe(1);
  });
  it("info and empty findings exit 0, even under --strict", () => {
    expect(exitCodeForFindings([info])).toBe(0);
    expect(exitCodeForFindings([info], true)).toBe(0);
    expect(exitCodeForFindings([], true)).toBe(0);
  });
});
