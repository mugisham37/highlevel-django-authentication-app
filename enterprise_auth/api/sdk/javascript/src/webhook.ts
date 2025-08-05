/**
 * Webhook signature verification utilities
 */

import * as crypto from "crypto-js";

export class WebhookVerifier {
  /**
   * Verify webhook signature using HMAC-SHA256
   *
   * @param payload - Raw webhook payload as string
   * @param signature - Webhook signature header
   * @param secret - Webhook secret key
   * @param timestamp - Optional timestamp for additional security
   * @returns True if signature is valid
   */
  static verifySignature(
    payload: string,
    signature: string,
    secret: string,
    timestamp?: string
  ): boolean {
    try {
      let message = payload;

      // If timestamp is provided, include it in the message
      if (timestamp) {
        message = `${timestamp}.${payload}`;
      }

      // Calculate expected signature
      const expectedSignature = crypto.HmacSHA256(message, secret).toString();

      // Handle signature header format (t=timestamp,v1=signature)
      if (signature.includes(",")) {
        const parts = signature.split(",");
        for (const part of parts) {
          if (part.startsWith("v1=")) {
            const providedSignature = part.substring(3);
            return this.constantTimeCompare(
              expectedSignature,
              providedSignature
            );
          }
        }
        return false;
      }

      // Direct signature comparison
      return this.constantTimeCompare(expectedSignature, signature);
    } catch (error) {
      return false;
    }
  }

  /**
   * Extract timestamp from webhook signature header
   *
   * @param signature - Webhook signature header
   * @returns Timestamp string or null if not found
   */
  static extractTimestamp(signature: string): string | null {
    if (!signature.includes(",")) {
      return null;
    }

    const parts = signature.split(",");
    for (const part of parts) {
      if (part.startsWith("t=")) {
        return part.substring(2);
      }
    }

    return null;
  }

  /**
   * Verify webhook timestamp is within tolerance
   *
   * @param timestamp - Timestamp from webhook header
   * @param toleranceSeconds - Maximum age in seconds (default: 300 = 5 minutes)
   * @returns True if timestamp is within tolerance
   */
  static verifyTimestamp(
    timestamp: string,
    toleranceSeconds: number = 300
  ): boolean {
    try {
      const webhookTime = parseInt(timestamp, 10);
      const currentTime = Math.floor(Date.now() / 1000);
      const timeDiff = Math.abs(currentTime - webhookTime);

      return timeDiff <= toleranceSeconds;
    } catch (error) {
      return false;
    }
  }

  /**
   * Comprehensive webhook verification including signature and timestamp
   *
   * @param payload - Raw webhook payload as string
   * @param signature - Webhook signature header
   * @param secret - Webhook secret key
   * @param toleranceSeconds - Maximum timestamp age in seconds
   * @returns True if webhook is valid
   */
  static verifyWebhook(
    payload: string,
    signature: string,
    secret: string,
    toleranceSeconds: number = 300
  ): boolean {
    // Extract timestamp from signature
    const timestamp = this.extractTimestamp(signature);

    // Verify timestamp if present
    if (timestamp && !this.verifyTimestamp(timestamp, toleranceSeconds)) {
      return false;
    }

    // Verify signature
    return this.verifySignature(payload, signature, secret, timestamp);
  }

  /**
   * Constant-time string comparison to prevent timing attacks
   *
   * @param a - First string
   * @param b - Second string
   * @returns True if strings are equal
   */
  private static constantTimeCompare(a: string, b: string): boolean {
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
   * Generate webhook signature for testing purposes
   *
   * @param payload - Webhook payload
   * @param secret - Webhook secret
   * @param timestamp - Optional timestamp
   * @returns Generated signature
   */
  static generateSignature(
    payload: string,
    secret: string,
    timestamp?: string
  ): string {
    let message = payload;

    if (timestamp) {
      message = `${timestamp}.${payload}`;
    }

    const signature = crypto.HmacSHA256(message, secret).toString();

    if (timestamp) {
      return `t=${timestamp},v1=${signature}`;
    }

    return signature;
  }
}

/**
 * Webhook event handler interface
 */
export interface WebhookHandler {
  (eventType: string, data: any): void | Promise<void>;
}

/**
 * Webhook processor for handling incoming webhooks
 */
export class WebhookProcessor {
  private handlers: Map<string, WebhookHandler[]> = new Map();
  private globalHandlers: WebhookHandler[] = [];

  /**
   * Register a handler for specific event type
   *
   * @param eventType - Event type to handle
   * @param handler - Handler function
   */
  on(eventType: string, handler: WebhookHandler): void {
    if (!this.handlers.has(eventType)) {
      this.handlers.set(eventType, []);
    }
    this.handlers.get(eventType)!.push(handler);
  }

  /**
   * Register a global handler for all events
   *
   * @param handler - Handler function
   */
  onAny(handler: WebhookHandler): void {
    this.globalHandlers.push(handler);
  }

  /**
   * Remove handler for specific event type
   *
   * @param eventType - Event type
   * @param handler - Handler function to remove
   */
  off(eventType: string, handler: WebhookHandler): void {
    const handlers = this.handlers.get(eventType);
    if (handlers) {
      const index = handlers.indexOf(handler);
      if (index > -1) {
        handlers.splice(index, 1);
      }
    }
  }

  /**
   * Remove global handler
   *
   * @param handler - Handler function to remove
   */
  offAny(handler: WebhookHandler): void {
    const index = this.globalHandlers.indexOf(handler);
    if (index > -1) {
      this.globalHandlers.splice(index, 1);
    }
  }

  /**
   * Process incoming webhook
   *
   * @param payload - Webhook payload
   * @param signature - Webhook signature
   * @param secret - Webhook secret
   * @param toleranceSeconds - Timestamp tolerance
   * @returns True if webhook was processed successfully
   */
  async processWebhook(
    payload: string,
    signature: string,
    secret: string,
    toleranceSeconds: number = 300
  ): Promise<boolean> {
    // Verify webhook signature
    if (
      !WebhookVerifier.verifyWebhook(
        payload,
        signature,
        secret,
        toleranceSeconds
      )
    ) {
      throw new Error("Invalid webhook signature");
    }

    try {
      // Parse webhook payload
      const webhookData = JSON.parse(payload);
      const eventType = webhookData.event_type;
      const data = webhookData.data;

      // Execute specific handlers
      const specificHandlers = this.handlers.get(eventType) || [];
      for (const handler of specificHandlers) {
        await handler(eventType, data);
      }

      // Execute global handlers
      for (const handler of this.globalHandlers) {
        await handler(eventType, data);
      }

      return true;
    } catch (error) {
      throw new Error(`Failed to process webhook: ${error.message}`);
    }
  }

  /**
   * Get list of registered event types
   *
   * @returns Array of event types
   */
  getRegisteredEvents(): string[] {
    return Array.from(this.handlers.keys());
  }

  /**
   * Get number of handlers for event type
   *
   * @param eventType - Event type
   * @returns Number of handlers
   */
  getHandlerCount(eventType: string): number {
    return this.handlers.get(eventType)?.length || 0;
  }

  /**
   * Clear all handlers
   */
  clearHandlers(): void {
    this.handlers.clear();
    this.globalHandlers = [];
  }
}
