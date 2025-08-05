/**
 * TypeScript type definitions for EnterpriseAuth API
 */

export interface APIVersion {
  version: string;
  supported_versions: string[];
  deprecated_versions: string[];
  documentation_url: string;
  changelog_url: string;
}

export interface APIHealth {
  status: "healthy" | "unhealthy";
  version: string;
  timestamp: string;
  checks: {
    database: "healthy" | "unhealthy";
    cache: "healthy" | "unhealthy";
  };
  uptime_seconds: number;
}

export interface APIKey {
  id: string;
  name: string;
  description?: string;
  key_id: string;
  key_prefix: string;
  generated_key?: string; // Only returned on creation
  created_by: string;
  organization?: string;
  scopes: APIKeyScope[];
  tier: APIKeyTier;
  allowed_ips: string[];
  is_active: boolean;
  expires_at?: string;
  last_used_at?: string;
  usage_count: number;
  rate_limit_per_minute: number;
  rate_limit_per_hour: number;
  rate_limit_per_day: number;
  created_at: string;
  updated_at: string;
}

export interface APIKeyList {
  id: string;
  name: string;
  key_prefix: string;
  created_by: string;
  organization?: string;
  tier: APIKeyTier;
  is_active: boolean;
  is_expired: boolean;
  expires_at?: string;
  last_used_at?: string;
  usage_count: number;
  created_at: string;
}

export interface CreateAPIKeyRequest {
  name: string;
  description?: string;
  organization?: string;
  scopes: APIKeyScope[];
  tier?: APIKeyTier;
  allowed_ips?: string[];
  expires_at?: string;
  rate_limit_per_minute?: number;
  rate_limit_per_hour?: number;
  rate_limit_per_day?: number;
}

export interface UpdateAPIKeyRequest {
  name?: string;
  description?: string;
  organization?: string;
  scopes?: APIKeyScope[];
  tier?: APIKeyTier;
  allowed_ips?: string[];
  is_active?: boolean;
  expires_at?: string;
  rate_limit_per_minute?: number;
  rate_limit_per_hour?: number;
  rate_limit_per_day?: number;
}

export interface WebhookEndpoint {
  id: string;
  name: string;
  description?: string;
  url: string;
  secret_key: string;
  verification_token: string;
  created_by: string;
  organization?: string;
  subscribed_events: WebhookEventType[];
  headers: Record<string, string>;
  timeout_seconds: number;
  max_retries: number;
  is_active: boolean;
  is_verified: boolean;
  total_deliveries: number;
  successful_deliveries: number;
  failed_deliveries: number;
  success_rate: number;
  last_delivery_at?: string;
  created_at: string;
  updated_at: string;
}

export interface WebhookEndpointList {
  id: string;
  name: string;
  url: string;
  created_by: string;
  organization?: string;
  is_active: boolean;
  is_verified: boolean;
  event_count: number;
  total_deliveries: number;
  success_rate: number;
  last_delivery_at?: string;
  created_at: string;
}

export interface CreateWebhookRequest {
  name: string;
  description?: string;
  url: string;
  organization?: string;
  subscribed_events: WebhookEventType[];
  headers?: Record<string, string>;
  timeout_seconds?: number;
  max_retries?: number;
}

export interface UpdateWebhookRequest {
  name?: string;
  description?: string;
  url?: string;
  organization?: string;
  subscribed_events?: WebhookEventType[];
  headers?: Record<string, string>;
  timeout_seconds?: number;
  max_retries?: number;
  is_active?: boolean;
}

export interface WebhookDelivery {
  id: string;
  endpoint_name: string;
  endpoint_url: string;
  event_type: WebhookEventType;
  event_id: string;
  status: WebhookDeliveryStatus;
  attempt_count: number;
  max_attempts: number;
  response_status_code?: number;
  response_headers: Record<string, string>;
  response_body: string;
  error_message: string;
  duration_ms?: number;
  is_retryable: boolean;
  scheduled_at: string;
  first_attempted_at?: string;
  last_attempted_at?: string;
  delivered_at?: string;
  next_retry_at?: string;
  created_at: string;
}

export interface APIRequestLog {
  id: string;
  request_id: string;
  api_key_name?: string;
  user_email?: string;
  method: string;
  path: string;
  query_params: Record<string, any>;
  ip_address: string;
  user_agent: string;
  status_code: number;
  response_size: number;
  response_time_ms: number;
  error_type: string;
  error_message: string;
  created_at: string;
}

export interface APIAnalytics {
  period: "day" | "week" | "month";
  start_date: string;
  end_date: string;
  total_requests: number;
  successful_requests: number;
  error_requests: number;
  success_rate: number;
  average_response_time_ms: number;
  top_endpoints: Array<{
    path: string;
    count: number;
  }>;
  status_code_distribution: Array<{
    status_code: number;
    count: number;
  }>;
}

export interface PaginatedResponse<T> {
  pagination: {
    count: number;
    next?: string;
    previous?: string;
    page_size: number;
    total_pages: number;
    current_page: number;
  };
  results: T[];
}

export interface BulkOperationRequest {
  ids: string[];
  action: "activate" | "deactivate" | "delete";
}

export interface BulkOperationResponse {
  message: string;
  affected_count: number;
}

export interface WebhookTestResponse {
  message: string;
  task_id: string;
}

export interface APIError {
  error: {
    code: string;
    message: string;
    details?: Record<string, any>;
    request_id?: string;
    timestamp: string;
  };
}

// Enums
export enum APIKeyScope {
  READ_ONLY = "read_only",
  READ_WRITE = "read_write",
  ADMIN = "admin",
  WEBHOOK_ONLY = "webhook_only",
}

export enum APIKeyTier {
  BASIC = "basic",
  PREMIUM = "premium",
  ENTERPRISE = "enterprise",
}

export enum WebhookEventType {
  USER_CREATED = "user.created",
  USER_UPDATED = "user.updated",
  USER_DELETED = "user.deleted",
  USER_LOGIN = "user.login",
  USER_LOGOUT = "user.logout",
  USER_PASSWORD_CHANGED = "user.password_changed",
  USER_EMAIL_VERIFIED = "user.email_verified",
  USER_MFA_ENABLED = "user.mfa_enabled",
  USER_MFA_DISABLED = "user.mfa_disabled",
  SESSION_CREATED = "session.created",
  SESSION_TERMINATED = "session.terminated",
  SECURITY_ALERT = "security.alert",
  ROLE_ASSIGNED = "role.assigned",
  ROLE_REVOKED = "role.revoked",
}

export enum WebhookDeliveryStatus {
  PENDING = "pending",
  DELIVERED = "delivered",
  FAILED = "failed",
  RETRYING = "retrying",
  ABANDONED = "abandoned",
}

// Client configuration
export interface ClientConfig {
  apiKey?: string;
  jwtToken?: string;
  baseUrl?: string;
  timeout?: number;
  maxRetries?: number;
  retryDelay?: number;
}

// Request options
export interface RequestOptions {
  timeout?: number;
  headers?: Record<string, string>;
}

// List options
export interface ListOptions {
  page?: number;
  page_size?: number;
  [key: string]: any;
}
