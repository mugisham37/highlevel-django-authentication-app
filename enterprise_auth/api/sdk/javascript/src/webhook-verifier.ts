/**
 * Webhook Signature Verifier
 *
 * Utility for verifying webhook signatures from EnterpriseAuth.
 */

import * as CryptoJS from "crypto-js";
import { WebhookError } from "./exceptions";

export class WebhookVerifier {
  private secretKey: string;

  constructor(secretKey: string) {
    this.secretKey = secretKey;
  }

  /**
   * Verify webhook signature
   *
   * @param payload Raw webhook payload
   * @param signature Signature from X-Webhook-Signature header
   * @param timestamp Optional timestamp for replay protection
   * @returns True if signature is valid
   */
  verifySignature(
    payload: string | Buffer,
    signature: string,
    timestamp?: string
  ): boolean {
    try {
      // Parse signature header
      const sigParts: Record<string, string> = {};
      signature.split(",").forEach((part) => {
        const [key, value] = part.split("=", 2);
        if (key && value) {
          sigParts[key] = value;
        }
      });

      // Get timestamp and signature
      const ts =
        sigParts.t || timestamp || Math.floor(Date.now() / 1000).toString();
      const v1 = sigParts.v1;

      if (!v1) {
        return false;
      }

      // Create expected signature
      const payloadString =
        typeof payload === "string" ? payload : payload.toString("utf8");
      const message = `${ts}.${payloadString}`;
      const expectedSig = CryptoJS.HmacSHA256(message, this.secretKey).toString(
        CryptoJS.enc.Hex
      );

      // Compare signatures using constant-time comparison
      return this.constantTimeCompare(v1, expectedSig);
    } catch (error) {
      return false;
    }
  }

  /**
   * Parse webhook payload
   *
   * @param payload Raw webhook payload
   * @returns Parsed payload data
   */
  parsePayload(payload: string | Buffer): any {
    try {
      const payloadString =
        typeof payload === "string" ? payload : payload.toString("utf8");
      return JSON.parse(payloadString);
    } catch (error) {
      throw new WebhookError(
        `Invalid JSON payload: ${
          error instanceof Error ? error.message : "Unknown error"
        }`
      );
    }
  }

  /**
   * Verify webhook with timestamp validation
   *
   * @param payload Raw webhook payload
   * @param signature Signature from X-Webhook-Signature header
   * @param timestamp Timestamp from X-Webhook-Timestamp header
   * @param toleranceSeconds Tolerance for timestamp validation (default: 300 seconds)
   * @returns True if webhook is valid
   */
  verifyWebhook(
    payload: string | Buffer,
    signature: string,
    timestamp: string,
    toleranceSeconds: number = 300
  ): boolean {
    // Verify timestamp is within tolerance
    const webhookTime = parseInt(timestamp, 10);
    const currentTime = Math.floor(Date.now() / 1000);

    if (Math.abs(currentTime - webhookTime) > toleranceSeconds) {
      throw new WebhookError("Webhook timestamp is outside tolerance window");
    }

    // Verify signature
    return this.verifySignature(payload, signature, timestamp);
  }

  /**
   * Generate signature for testing purposes
   *
   * @param payload Webhook payload
   * @param timestamp Optional timestamp (defaults to current time)
   * @returns Signature string
   */
  generateSignature(payload: string | Buffer, timestamp?: string): string {
    const ts = timestamp || Math.floor(Date.now() / 1000).toString();
    const payloadString =
      typeof payload === "string" ? payload : payload.toString("utf8");
    const message = `${ts}.${payloadString}`;
    const signature = CryptoJS.HmacSHA256(message, this.secretKey).toString(
      CryptoJS.enc.Hex
    );

    return `t=${ts},v1=${signature}`;
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   *
   * @param a First string
   * @param b Second string
   * @returns True if strings are equal
   */
  private constantTimeCompare(a: string, b: string): boolean {
    if (a.length !== b.length) {
      return false;
    }

    let result = 0;
    for (let i = 0; i < a.length; i++) {
      result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }

    return result === 0;
  }

  /**
   * Validate webhook event structure
   *
   * @param event Parsed webhook event
   * @returns True if event structure is valid
   */
  validateEventStructure(event: any): boolean {
    return (
      typeof event === "object" &&
      event !== null &&
      typeof event.event_type === "string" &&
      typeof event.event_id === "string" &&
      typeof event.timestamp === "string" &&
      typeof event.data === "object"
    );
  }

  /**
   * Extract event type from webhook payload
   *
   * @param payload Parsed webhook payload
   * @returns Event type string
   */
  getEventType(payload: any): string {
    if (!this.validateEventStructure(payload)) {
      throw new WebhookError("Invalid webhook event structure");
    }
    return payload.event_type;
  }

  /**
   * Check if webhook is a test event
   *
   * @param payload Parsed webhook payload
   * @returns True if this is a test webhook
   */
  isTestWebhook(payload: any): boolean {
    return (
      payload?.data?.test === true || payload?.event_type === "webhook.test"
    );
  }

  /**
   * Check if webhook is a verification event
   *
   * @param payload Parsed webhook payload
   * @returns True if this is a verification webhook
   */
  isVerificationWebhook(payload: any): boolean {
    return payload?.event_type === "webhook.verification";
  }

  /**
   * Get verification token from verification webhook
   *
   * @param payload Parsed webhook payload
   * @returns Verification token or null
   */
  getVerificationToken(payload: any): string | null {
    if (!this.isVerificationWebhook(payload)) {
      return null;
    }
    return payload?.verification_token || null;
  }
}

/**
 * Convenience function to create a webhook verifier
 *
 * @param secretKey Webhook secret key
 * @returns WebhookVerifier instance
 */
export function createWebhookVerifier(secretKey: string): WebhookVerifier {
  return new WebhookVerifier(secretKey);
}

/**
 * Convenience function to verify a webhook signature
 *
 * @param payload Raw webhook payload
 * @param signature Signature from header
 * @param secretKey Webhook secret key
 * @param timestamp Optional timestamp
 * @returns True if signature is valid
 */
export function verifyWebhookSignature(
  payload: string | Buffer,
  signature: string,
  secretKey: string,
  timestamp?: string
): boolean {
  const verifier = new WebhookVerifier(secretKey);
  return verifier.verifySignature(payload, signature, timestamp);
}
