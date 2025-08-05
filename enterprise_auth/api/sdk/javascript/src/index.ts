/**
 * EnterpriseAuth JavaScript/TypeScript SDK
 *
 * A comprehensive SDK for integrating with the EnterpriseAuth API.
 */

export { EnterpriseAuthClient } from "./client";
export { WebhookVerifier } from "./webhook";
export * from "./types";
export * from "./errors";

// Default export
export { EnterpriseAuthClient as default } from "./client";
