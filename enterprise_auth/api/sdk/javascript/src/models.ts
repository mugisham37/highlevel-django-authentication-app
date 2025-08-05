/**
 * EnterpriseAuth SDK Models
 *
 * Data models for the JavaScript SDK.
 */

export class User {
  public id: string;
  public email: string;
  public firstName: string;
  public lastName: string;
  public isActive: boolean;
  public isEmailVerified: boolean;
  public organization: string;
  public department: string;
  public employeeId: string;
  public createdAt?: Date;
  public updatedAt?: Date;
  public lastLogin?: Date;

  constructor(data: Partial<User>) {
    this.id = data.id || "";
    this.email = data.email || "";
    this.firstName = data.firstName || "";
    this.lastName = data.lastName || "";
    this.isActive = data.isActive ?? true;
    this.isEmailVerified = data.isEmailVerified ?? false;
    this.organization = data.organization || "";
    this.department = data.department || "";
    this.employeeId = data.employeeId || "";
    this.createdAt = data.createdAt;
    this.updatedAt = data.updatedAt;
    this.lastLogin = data.lastLogin;
  }

  static fromJSON(data: any): User {
    return new User({
      id: data.id,
      email: data.email,
      firstName: data.first_name,
      lastName: data.last_name,
      isActive: data.is_active,
      isEmailVerified: data.is_email_verified,
      organization: data.organization,
      department: data.department,
      employeeId: data.employee_id,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
      updatedAt: data.updated_at ? new Date(data.updated_at) : undefined,
      lastLogin: data.last_login ? new Date(data.last_login) : undefined,
    });
  }

  toJSON(): Record<string, any> {
    return {
      id: this.id,
      email: this.email,
      first_name: this.firstName,
      last_name: this.lastName,
      is_active: this.isActive,
      is_email_verified: this.isEmailVerified,
      organization: this.organization,
      department: this.department,
      employee_id: this.employeeId,
      created_at: this.createdAt?.toISOString(),
      updated_at: this.updatedAt?.toISOString(),
      last_login: this.lastLogin?.toISOString(),
    };
  }

  get fullName(): string {
    return `${this.firstName} ${this.lastName}`.trim();
  }
}

export class APIKey {
  public id: string;
  public name: string;
  public keyPrefix: string;
  public scopes: string[];
  public tier: string;
  public isActive: boolean;
  public description: string;
  public organization: string;
  public allowedIPs: string[];
  public expiresAt?: Date;
  public lastUsedAt?: Date;
  public usageCount: number;
  public rateLimitPerMinute: number;
  public rateLimitPerHour: number;
  public rateLimitPerDay: number;
  public createdAt?: Date;
  public updatedAt?: Date;
  public generatedKey?: string; // Only available on creation

  constructor(data: Partial<APIKey>) {
    this.id = data.id || "";
    this.name = data.name || "";
    this.keyPrefix = data.keyPrefix || "";
    this.scopes = data.scopes || [];
    this.tier = data.tier || "basic";
    this.isActive = data.isActive ?? true;
    this.description = data.description || "";
    this.organization = data.organization || "";
    this.allowedIPs = data.allowedIPs || [];
    this.expiresAt = data.expiresAt;
    this.lastUsedAt = data.lastUsedAt;
    this.usageCount = data.usageCount || 0;
    this.rateLimitPerMinute = data.rateLimitPerMinute || 60;
    this.rateLimitPerHour = data.rateLimitPerHour || 1000;
    this.rateLimitPerDay = data.rateLimitPerDay || 10000;
    this.createdAt = data.createdAt;
    this.updatedAt = data.updatedAt;
    this.generatedKey = data.generatedKey;
  }

  static fromJSON(data: any): APIKey {
    return new APIKey({
      id: data.id,
      name: data.name,
      keyPrefix: data.key_prefix,
      scopes: data.scopes,
      tier: data.tier,
      isActive: data.is_active,
      description: data.description,
      organization: data.organization,
      allowedIPs: data.allowed_ips,
      expiresAt: data.expires_at ? new Date(data.expires_at) : undefined,
      lastUsedAt: data.last_used_at ? new Date(data.last_used_at) : undefined,
      usageCount: data.usage_count,
      rateLimitPerMinute: data.rate_limit_per_minute,
      rateLimitPerHour: data.rate_limit_per_hour,
      rateLimitPerDay: data.rate_limit_per_day,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
      updatedAt: data.updated_at ? new Date(data.updated_at) : undefined,
      generatedKey: data.generated_key,
    });
  }

  toJSON(): Record<string, any> {
    return {
      id: this.id,
      name: this.name,
      key_prefix: this.keyPrefix,
      scopes: this.scopes,
      tier: this.tier,
      is_active: this.isActive,
      description: this.description,
      organization: this.organization,
      allowed_ips: this.allowedIPs,
      expires_at: this.expiresAt?.toISOString(),
      last_used_at: this.lastUsedAt?.toISOString(),
      usage_count: this.usageCount,
      rate_limit_per_minute: this.rateLimitPerMinute,
      rate_limit_per_hour: this.rateLimitPerHour,
      rate_limit_per_day: this.rateLimitPerDay,
      created_at: this.createdAt?.toISOString(),
      updated_at: this.updatedAt?.toISOString(),
      generated_key: this.generatedKey,
    };
  }

  get isExpired(): boolean {
    if (!this.expiresAt) return false;
    return new Date() > this.expiresAt;
  }

  get maskedKey(): string {
    return `${this.keyPrefix}...`;
  }
}

export class WebhookEndpoint {
  public id: string;
  public name: string;
  public url: string;
  public subscribedEvents: string[];
  public isActive: boolean;
  public isVerified: boolean;
  public description: string;
  public organization: string;
  public headers: Record<string, string>;
  public timeoutSeconds: number;
  public maxRetries: number;
  public totalDeliveries: number;
  public successfulDeliveries: number;
  public failedDeliveries: number;
  public successRate: number;
  public lastDeliveryAt?: Date;
  public createdAt?: Date;
  public updatedAt?: Date;
  public secretKey?: string; // Only available on creation/retrieval

  constructor(data: Partial<WebhookEndpoint>) {
    this.id = data.id || "";
    this.name = data.name || "";
    this.url = data.url || "";
    this.subscribedEvents = data.subscribedEvents || [];
    this.isActive = data.isActive ?? true;
    this.isVerified = data.isVerified ?? false;
    this.description = data.description || "";
    this.organization = data.organization || "";
    this.headers = data.headers || {};
    this.timeoutSeconds = data.timeoutSeconds || 30;
    this.maxRetries = data.maxRetries || 3;
    this.totalDeliveries = data.totalDeliveries || 0;
    this.successfulDeliveries = data.successfulDeliveries || 0;
    this.failedDeliveries = data.failedDeliveries || 0;
    this.successRate = data.successRate || 0;
    this.lastDeliveryAt = data.lastDeliveryAt;
    this.createdAt = data.createdAt;
    this.updatedAt = data.updatedAt;
    this.secretKey = data.secretKey;
  }

  static fromJSON(data: any): WebhookEndpoint {
    return new WebhookEndpoint({
      id: data.id,
      name: data.name,
      url: data.url,
      subscribedEvents: data.subscribed_events,
      isActive: data.is_active,
      isVerified: data.is_verified,
      description: data.description,
      organization: data.organization,
      headers: data.headers,
      timeoutSeconds: data.timeout_seconds,
      maxRetries: data.max_retries,
      totalDeliveries: data.total_deliveries,
      successfulDeliveries: data.successful_deliveries,
      failedDeliveries: data.failed_deliveries,
      successRate: data.success_rate,
      lastDeliveryAt: data.last_delivery_at
        ? new Date(data.last_delivery_at)
        : undefined,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
      updatedAt: data.updated_at ? new Date(data.updated_at) : undefined,
      secretKey: data.secret_key,
    });
  }

  toJSON(): Record<string, any> {
    return {
      id: this.id,
      name: this.name,
      url: this.url,
      subscribed_events: this.subscribedEvents,
      is_active: this.isActive,
      is_verified: this.isVerified,
      description: this.description,
      organization: this.organization,
      headers: this.headers,
      timeout_seconds: this.timeoutSeconds,
      max_retries: this.maxRetries,
      total_deliveries: this.totalDeliveries,
      successful_deliveries: this.successfulDeliveries,
      failed_deliveries: this.failedDeliveries,
      success_rate: this.successRate,
      last_delivery_at: this.lastDeliveryAt?.toISOString(),
      created_at: this.createdAt?.toISOString(),
      updated_at: this.updatedAt?.toISOString(),
      secret_key: this.secretKey,
    };
  }

  get eventCount(): number {
    return this.subscribedEvents.length;
  }
}

export class WebhookDelivery {
  public id: string;
  public eventType: string;
  public eventId: string;
  public status: string;
  public attemptCount: number;
  public maxAttempts: number;
  public endpointName: string;
  public endpointUrl: string;
  public responseStatusCode?: number;
  public responseHeaders: Record<string, string>;
  public responseBody: string;
  public errorMessage: string;
  public durationMs?: number;
  public isRetryable: boolean;
  public scheduledAt?: Date;
  public firstAttemptedAt?: Date;
  public lastAttemptedAt?: Date;
  public deliveredAt?: Date;
  public nextRetryAt?: Date;
  public createdAt?: Date;

  constructor(data: Partial<WebhookDelivery>) {
    this.id = data.id || "";
    this.eventType = data.eventType || "";
    this.eventId = data.eventId || "";
    this.status = data.status || "pending";
    this.attemptCount = data.attemptCount || 0;
    this.maxAttempts = data.maxAttempts || 3;
    this.endpointName = data.endpointName || "";
    this.endpointUrl = data.endpointUrl || "";
    this.responseStatusCode = data.responseStatusCode;
    this.responseHeaders = data.responseHeaders || {};
    this.responseBody = data.responseBody || "";
    this.errorMessage = data.errorMessage || "";
    this.durationMs = data.durationMs;
    this.isRetryable = data.isRetryable ?? false;
    this.scheduledAt = data.scheduledAt;
    this.firstAttemptedAt = data.firstAttemptedAt;
    this.lastAttemptedAt = data.lastAttemptedAt;
    this.deliveredAt = data.deliveredAt;
    this.nextRetryAt = data.nextRetryAt;
    this.createdAt = data.createdAt;
  }

  static fromJSON(data: any): WebhookDelivery {
    return new WebhookDelivery({
      id: data.id,
      eventType: data.event_type,
      eventId: data.event_id,
      status: data.status,
      attemptCount: data.attempt_count,
      maxAttempts: data.max_attempts,
      endpointName: data.endpoint_name,
      endpointUrl: data.endpoint_url,
      responseStatusCode: data.response_status_code,
      responseHeaders: data.response_headers,
      responseBody: data.response_body,
      errorMessage: data.error_message,
      durationMs: data.duration_ms,
      isRetryable: data.is_retryable,
      scheduledAt: data.scheduled_at ? new Date(data.scheduled_at) : undefined,
      firstAttemptedAt: data.first_attempted_at
        ? new Date(data.first_attempted_at)
        : undefined,
      lastAttemptedAt: data.last_attempted_at
        ? new Date(data.last_attempted_at)
        : undefined,
      deliveredAt: data.delivered_at ? new Date(data.delivered_at) : undefined,
      nextRetryAt: data.next_retry_at
        ? new Date(data.next_retry_at)
        : undefined,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
    });
  }

  toJSON(): Record<string, any> {
    return {
      id: this.id,
      event_type: this.eventType,
      event_id: this.eventId,
      status: this.status,
      attempt_count: this.attemptCount,
      max_attempts: this.maxAttempts,
      endpoint_name: this.endpointName,
      endpoint_url: this.endpointUrl,
      response_status_code: this.responseStatusCode,
      response_headers: this.responseHeaders,
      response_body: this.responseBody,
      error_message: this.errorMessage,
      duration_ms: this.durationMs,
      is_retryable: this.isRetryable,
      scheduled_at: this.scheduledAt?.toISOString(),
      first_attempted_at: this.firstAttemptedAt?.toISOString(),
      last_attempted_at: this.lastAttemptedAt?.toISOString(),
      delivered_at: this.deliveredAt?.toISOString(),
      next_retry_at: this.nextRetryAt?.toISOString(),
      created_at: this.createdAt?.toISOString(),
    };
  }

  get isSuccessful(): boolean {
    return this.status === "delivered";
  }

  get isFailed(): boolean {
    return ["failed", "abandoned"].includes(this.status);
  }

  get isPending(): boolean {
    return ["pending", "retrying"].includes(this.status);
  }
}

export class Session {
  public id: string;
  public userId: string;
  public sessionId: string;
  public deviceFingerprint: string;
  public ipAddress: string;
  public userAgent: string;
  public deviceType: string;
  public browser: string;
  public operatingSystem: string;
  public country: string;
  public city: string;
  public status: string;
  public riskScore: number;
  public isTrustedDevice: boolean;
  public loginMethod: string;
  public createdAt?: Date;
  public lastActivity?: Date;
  public expiresAt?: Date;

  constructor(data: Partial<Session>) {
    this.id = data.id || "";
    this.userId = data.userId || "";
    this.sessionId = data.sessionId || "";
    this.deviceFingerprint = data.deviceFingerprint || "";
    this.ipAddress = data.ipAddress || "";
    this.userAgent = data.userAgent || "";
    this.deviceType = data.deviceType || "";
    this.browser = data.browser || "";
    this.operatingSystem = data.operatingSystem || "";
    this.country = data.country || "";
    this.city = data.city || "";
    this.status = data.status || "active";
    this.riskScore = data.riskScore || 0;
    this.isTrustedDevice = data.isTrustedDevice ?? false;
    this.loginMethod = data.loginMethod || "";
    this.createdAt = data.createdAt;
    this.lastActivity = data.lastActivity;
    this.expiresAt = data.expiresAt;
  }

  static fromJSON(data: any): Session {
    return new Session({
      id: data.id,
      userId: data.user_id,
      sessionId: data.session_id,
      deviceFingerprint: data.device_fingerprint,
      ipAddress: data.ip_address,
      userAgent: data.user_agent,
      deviceType: data.device_type,
      browser: data.browser,
      operatingSystem: data.operating_system,
      country: data.country,
      city: data.city,
      status: data.status,
      riskScore: data.risk_score,
      isTrustedDevice: data.is_trusted_device,
      loginMethod: data.login_method,
      createdAt: data.created_at ? new Date(data.created_at) : undefined,
      lastActivity: data.last_activity
        ? new Date(data.last_activity)
        : undefined,
      expiresAt: data.expires_at ? new Date(data.expires_at) : undefined,
    });
  }

  toJSON(): Record<string, any> {
    return {
      id: this.id,
      user_id: this.userId,
      session_id: this.sessionId,
      device_fingerprint: this.deviceFingerprint,
      ip_address: this.ipAddress,
      user_agent: this.userAgent,
      device_type: this.deviceType,
      browser: this.browser,
      operating_system: this.operatingSystem,
      country: this.country,
      city: this.city,
      status: this.status,
      risk_score: this.riskScore,
      is_trusted_device: this.isTrustedDevice,
      login_method: this.loginMethod,
      created_at: this.createdAt?.toISOString(),
      last_activity: this.lastActivity?.toISOString(),
      expires_at: this.expiresAt?.toISOString(),
    };
  }

  get isActive(): boolean {
    return this.status === "active";
  }

  get isExpired(): boolean {
    if (!this.expiresAt) return false;
    return new Date() > this.expiresAt;
  }
}

export class APIAnalytics {
  public period: string;
  public startDate: Date;
  public endDate: Date;
  public totalRequests: number;
  public successfulRequests: number;
  public errorRequests: number;
  public successRate: number;
  public averageResponseTimeMs: number;
  public topEndpoints: Array<{ path: string; count: number }>;
  public statusCodeDistribution: Array<{ status_code: number; count: number }>;

  constructor(data: Partial<APIAnalytics>) {
    this.period = data.period || "";
    this.startDate = data.startDate || new Date();
    this.endDate = data.endDate || new Date();
    this.totalRequests = data.totalRequests || 0;
    this.successfulRequests = data.successfulRequests || 0;
    this.errorRequests = data.errorRequests || 0;
    this.successRate = data.successRate || 0;
    this.averageResponseTimeMs = data.averageResponseTimeMs || 0;
    this.topEndpoints = data.topEndpoints || [];
    this.statusCodeDistribution = data.statusCodeDistribution || [];
  }

  static fromJSON(data: any): APIAnalytics {
    return new APIAnalytics({
      period: data.period,
      startDate: new Date(data.start_date),
      endDate: new Date(data.end_date),
      totalRequests: data.total_requests,
      successfulRequests: data.successful_requests,
      errorRequests: data.error_requests,
      successRate: data.success_rate,
      averageResponseTimeMs: data.average_response_time_ms,
      topEndpoints: data.top_endpoints,
      statusCodeDistribution: data.status_code_distribution,
    });
  }

  toJSON(): Record<string, any> {
    return {
      period: this.period,
      start_date: this.startDate.toISOString(),
      end_date: this.endDate.toISOString(),
      total_requests: this.totalRequests,
      successful_requests: this.successfulRequests,
      error_requests: this.errorRequests,
      success_rate: this.successRate,
      average_response_time_ms: this.averageResponseTimeMs,
      top_endpoints: this.topEndpoints,
      status_code_distribution: this.statusCodeDistribution,
    };
  }
}
