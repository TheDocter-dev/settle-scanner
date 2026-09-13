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

## Grading

Start at 100. Failed checks deduct by severity (critical −40, high −25, medium −15; info never deducts). A ≥90, B ≥75, C ≥60, D ≥40, F <40. Non-x402 endpoints get N/A. A passive A means "no publicly observable misconfiguration" — not a security certification.

## A note on AI assistance

This codebase was developed with AI assistance (design and implementation), with human review and testing of every committed change. Disclosed per the norms of the x402 ecosystem's contribution policies.

## License

MIT
