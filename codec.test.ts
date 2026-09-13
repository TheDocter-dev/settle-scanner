import { describe, it, expect } from "vitest";
import { encodePaymentHeader, decodePaymentHeader, type PaymentPayload } from "../src/x402";
import { createChallenge } from "../src/engine";

const sample: PaymentPayload = {
  x402Version: 1,
  scheme: "exact",
  network: "eip155:8453",
  payload: {
    signature: "0xdeadbeef",
    authorization: {
      from: "0xA", to: "0xB", value: "100",
      validAfter: "1000", validBefore: "2000", nonce: "0x1",
    },
  },
};

describe("payment header codec", () => {
  it("round-trips a payload", () => {
    expect(decodePaymentHeader(encodePaymentHeader(sample))).toEqual(sample);
  });

  it("rejects garbage headers", () => {
    expect(decodePaymentHeader("!!!not-base64!!!")).toBeNull();
    expect(decodePaymentHeader(Buffer.from("{}").toString("base64"))).toBeNull();
  });
});

describe("ownership challenge", () => {
  it("issues a well-formed challenge for the origin", () => {
    const c = createChallenge("https://example.com/api/paid");
    expect(c.token).toMatch(/^settle-verify-[0-9a-f]{32}$/);
    expect(c.origin).toBe("https://example.com");
    expect(c.wellKnownUrl).toBe("https://example.com/.well-known/settle-verify.txt");
    expect(c.instruction).toContain("settle-verify.txt");
  });
});
