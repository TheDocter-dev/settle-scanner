/** Minimal x402 wire types + header codec used by the scanner probes. */

export interface PaymentPayload {
  x402Version: number;
  scheme: string;
  network: string;
  payload: {
    signature?: string;
    authorization?: {
      from: string;
      to: string;
      value: string;
      validAfter?: string;
      validBefore?: string;
      nonce?: string;
    };
    [k: string]: unknown;
  };
}

export function decodePaymentHeader(header: string): PaymentPayload | null {
  try {
    const obj = JSON.parse(Buffer.from(header, "base64").toString("utf8"));
    if (!obj || typeof obj !== "object" || !obj.payload || !obj.network) return null;
    return obj as PaymentPayload;
  } catch {
    return null;
  }
}

export function encodePaymentHeader(payload: PaymentPayload): string {
  return Buffer.from(JSON.stringify(payload), "utf8").toString("base64");
}
