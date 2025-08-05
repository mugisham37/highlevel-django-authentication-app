/**
 * EnterpriseAuth SDK Exceptions
 *
 * Custom exception classes for the JavaScript SDK.
 */

export class EnterpriseAuthError extends Error {
  public code?: string;
  public details?: Record<string, any>;

  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message);
    this.name = "EnterpriseAuthError";
    this.code = code;
    this.details = details;

    // Maintains proper stack trace for where our error was thrown (only available on V8)
    if (Error.captureStackTrace) {
      Error.captureStackTrace(this, EnterpriseAuthError);
    }
  }

  toString(): string {
    if (this.code) {
      return `[${this.code}] ${this.message}`;
    }
    return this.message;
  }

  toJSON(): Record<string, any> {
    return {
      name: this.name,
      message: this.message,
      code: this.code,
      details: this.details,
      stack: this.stack,
    };
  }
}

export class AuthenticationError extends EnterpriseAuthError {
  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message, code, details);
    this.name = "AuthenticationError";
  }
}

export class AuthorizationError extends EnterpriseAuthError {
  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message, code, details);
    this.name = "AuthorizationError";
  }
}

export class RateLimitError extends EnterpriseAuthError {
  public retryAfter?: number;

  constructor(
    message: string,
    retryAfter?: number,
    code?: string,
    details?: Record<string, any>
  ) {
    super(message, code, details);
    this.name = "RateLimitError";
    this.retryAfter = retryAfter;
  }

  toJSON(): Record<string, any> {
    return {
      ...super.toJSON(),
      retryAfter: this.retryAfter,
    };
  }
}

export class ValidationError extends EnterpriseAuthError {
  public fieldErrors?: Record<string, string[]>;

  constructor(
    message: string,
    fieldErrors?: Record<string, string[]>,
    code?: string,
    details?: Record<string, any>
  ) {
    super(message, code, details);
    this.name = "ValidationError";
    this.fieldErrors = fieldErrors;
  }

  toJSON(): Record<string, any> {
    return {
      ...super.toJSON(),
      fieldErrors: this.fieldErrors,
    };
  }
}

export class WebhookError extends EnterpriseAuthError {
  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message, code, details);
    this.name = "WebhookError";
  }
}

export class TokenError extends EnterpriseAuthError {
  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message, code, details);
    this.name = "TokenError";
  }
}

export class NetworkError extends EnterpriseAuthError {
  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message, code, details);
    this.name = "NetworkError";
  }
}

export class ConfigurationError extends EnterpriseAuthError {
  constructor(message: string, code?: string, details?: Record<string, any>) {
    super(message, code, details);
    this.name = "ConfigurationError";
  }
}
