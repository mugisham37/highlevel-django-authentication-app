/**
 * Error classes for EnterpriseAuth SDK
 */

export class EnterpriseAuthError extends Error {
  public details?: Record<string, any>;
  public requestId?: string;

  constructor(
    message: string,
    details?: Record<string, any>,
    requestId?: string
  ) {
    super(message);
    this.name = "EnterpriseAuthError";
    this.details = details;
    this.requestId = requestId;
  }
}

export class AuthenticationError extends EnterpriseAuthError {
  constructor(
    message: string,
    details?: Record<string, any>,
    requestId?: string
  ) {
    super(message, details, requestId);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends EnterpriseAuthError {
  constructor(
    message: string,
    details?: Record<string, any>,
    requestId?: string
  ) {
    super(message, details, requestId);
    this.name = "AuthorizationError";
  }
}

export class RateLimitError extends EnterpriseAuthError {
  public retryAfter: number;

  constructor(
    message: string,
    retryAfter: number = 60,
    details?: Record<string, any>,
    requestId?: string
  ) {
    super(message, details, requestId);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }
}

export class ValidationError extends EnterpriseAuthError {
  public validationErrors: Record<string, any>;

  constructor(
    message: string,
    validationErrors: Record<string, any> = {},
    requestId?: string
  ) {
    super(message, validationErrors, requestId);
    this.name = "ValidationError";
    this.validationErrors = validationErrors;
  }
}

export class WebhookError extends EnterpriseAuthError {
  constructor(
    message: string,
    details?: Record<string, any>,
    requestId?: string
  ) {
    super(message, details, requestId);
    this.name = "WebhookError";
  }
}

export class NetworkError extends EnterpriseAuthError {
  constructor(message: string, details?: Record<string, any>) {
    super(message, details);
    this.name = "NetworkError";
  }
}

export class TimeoutError extends EnterpriseAuthError {
  constructor(message: string = "Request timeout") {
    super(message);
    this.name = "TimeoutError";
  }
}
