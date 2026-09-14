# settle-scanner

Security testing harness for x402 merchant endpoints. Implements the merchant-side checks from the USENIX Security 2026 x402 facilitator study (Wang, Yang et al.), with strict ethical limits on active testing.

## Modes

**Passive (default — anyone, any URL).** Non-intrusive: x402 dialect, payment-requirements sanity, configuration hygiene. No crafted payment is ever sent to a third-party endpoint.

**Deep (ownership-verified only).** Active probes — malformed headers, under-payment, replay/double-spend, expiry, zero-amount dust, concurrent-submit — run only after the operator proves control of the domain by publishing a challenge token at `/.well-known/settle-verify.txt`. When the merchant advertises a testnet requirement (Sepolia, devnet, …), all probes target that one, since crafted proofs also reach the merchant's facilitator.

Rationale: the USENIX study's authors declined to actively exploit third-party merchants on ethical grounds. So do we. Consent is a precondition, not an afterthought — and merchant consent isn't facilitator consent, so we prefer testnets wherever possible, as the paper did.

## What it maps to (paper rules)

| Paper rule | Probe | Coverage |
|---|---|---|
| Server-SR1: release only after settlement | `replay`, `concurrent-submit` | Covered (merchant-side; race untestable black-box when verify rejects the burst) |
| SR1 requirements binding | `underpaid`, `malformed` | Partial (via merchant's facilitator) |
| SR2 signature authenticity | `malformed` | Partial |
| SR3 expiry | `expiry` | Partial |
| SR5 fail-fast / idempotency | `replay`, `dust` | Partial |
| SR4, SR6–SR8, Server-SR2 | — | Not covered: facilitator-side or not black-box observable |

## Usage

```bash
npm install
npm test

# passive scan
npx tsx src/cli.ts https://example.com/api/paid-endpoint

# deep scan (your own domain only)
npx tsx src/cli.ts https://your-domain.com/api/paid --challenge
# publish the printed token at https://your-domain.com/.well-known/settle-verify.txt
npx tsx src/cli.ts https://your-domain.com/api/paid --deep --token <token>
```

### check-deps — x402 settle-gating dependency check

Static scan of a Python dependency manifest (`requirements.txt` or `pyproject.toml`) for x402 pins in the settle-gating affected range (paid 3xx responses delivered without settlement — affected versions per [x402#3465](https://github.com/x402-foundation/x402/issues/3465); fixed in 2.15.0, [PR #2826](https://github.com/x402-foundation/x402/pull/2826)).

```bash
npx tsx src/cli.ts check-deps <requirements.txt|pyproject.toml> [--strict]
```

Exit codes map to severity: critical → 2, warning → 0 (1 with `--strict`), info → 0. A manifest-only v2 in-range pin is a conditional **warning** — affected ONLY if the service uses the Flask middleware (the v2 FastAPI middleware settled `< 400` from 2.0.0 and is never affected). `x402 == 1.0.0` is critical outright (both adapters).

## Grading

Start at 100. Failed checks deduct by severity (critical −40, high −25, medium −15; info never deducts). A ≥90, B ≥75, C ≥60, D ≥40, F <40. Non-x402 endpoints get N/A. A passive A means "no publicly observable misconfiguration" — not a security certification.

## Verification standard

Every claim this project publishes — a scan finding, an upstream issue, a report — is reproduced against the **published artifact at a recorded version**: the PyPI/npm wheel, the tagged release, or the deployed contract. Never a mirror, never an untracked checkout, never "latest main." Each finding states the exact artifact and version it was proven against.

This rule was adopted after our first upstream report reproduced a genuine bug against a stale pre-transfer mirror — right bug, wrong environment. It is now the standing control.

## A note on AI assistance

Design decisions, threat model, test cases, and every merged change are authored and reviewed by the maintainer. AI tooling was used during implementation as an assistant (code drafting, refactoring, documentation), consistent with the disclosure practices adopted by projects such as the Linux kernel ("Assisted-by:" trailers), Fedora, Electron, and ESLint.

## License

MIT
