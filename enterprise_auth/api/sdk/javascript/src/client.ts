/**
 * EnterpriseAuth JavaScript/TypeScript SDK Client
 */

import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import {
  ClientConfig,
  RequestOptions,
  ListOptions,
  APIVersion,
  APIHealth,
  APIKey,
  APIKeyList,
  CreateAPIKeyRequest,
  UpdateAPIKeyRequest,
  WebhookEndpoint,
  WebhookEndpointList,
  CreateWebhookRequest,
  UpdateWebhookRequest,
  WebhookDelivery,
  APIRequestLog,
  APIAnalytics,
  PaginatedResponse,
  BulkOperationRequest,
  BulkOperationResponse,
  WebhookTestResponse,
  APIError,
} from "./types";
import {
  EnterpriseAuthError,
  AuthenticationError,
  AuthorizationError,
  RateLimitError,
  ValidationError,
  NetworkError,
  TimeoutError,
} from "./errors";

export class EnterpriseAuthClient {
  private client: AxiosInstance;
  private baseUrl: string;

  constructor(config: ClientConfig = {}) {
    const {
      apiKey,
      jwtToken,
      baseUrl = "https://api.enterpriseauth.com/v1",
      timeout = 30000,
      maxRetries = 3,
      retryDelay = 1000,
    } = config;

    if (apiKey && jwtToken) {
      throw new Error("Cannot specify both apiKey and jwtToken");
    }

    this.baseUrl = baseUrl.replace(/\/$/, "");

    // Create axios instance
    this.client = axios.create({
      baseURL: this.baseUrl,
      timeout,
      headers: {
        "Content-Type": "application/json",
        Accept: "application/json",
        "User-Agent": "EnterpriseAuth-JS-SDK/1.0.0",
      },
    });

    // Set authentication header
    if (apiKey) {
      this.client.defaults.headers.common["Authorization"] = `Bearer ${apiKey}`;
    } else if (jwtToken) {
      this.client.defaults.headers.common[
        "Authorization"
      ] = `Bearer ${jwtToken}`;
    }

    // Add request interceptor for retry logic
    this.client.interceptors.request.use(
      (config) => config,
      (error) => Promise.reject(error)
    );

    // Add response interceptor for error handling
    this.client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response) {
          this.handleErrorResponse(error.response);
        } else if (error.code === "ECONNABORTED") {
          throw new TimeoutError();
        } else {
          throw new NetworkError(error.message);
        }
      }
    );
  }

  private handleErrorResponse(response: AxiosResponse): never {
    const data: APIError = response.data;
    const errorInfo = data.error || {};
    const message = errorInfo.message || "Unknown error occurred";
    const details = errorInfo.details;
    const requestId = errorInfo.request_id;

    switch (response.status) {
      case 401:
        throw new AuthenticationError(message, details, requestId);
      case 403:
        throw new AuthorizationError(message, details, requestId);
      case 400:
        throw new ValidationError(message, details, requestId);
      case 429:
        const retryAfter = parseInt(response.headers["retry-after"] || "60");
        throw new RateLimitError(message, retryAfter, details, requestId);
      default:
        throw new EnterpriseAuthError(message, details, requestId);
    }
  }

  private async makeRequest<T>(
    method: string,
    endpoint: string,
    options: RequestOptions & { params?: any; data?: any } = {}
  ): Promise<T> {
    const { timeout, headers, params, data } = options;

    const config: AxiosRequestConfig = {
      method,
      url: endpoint,
      params,
      data,
      headers,
    };

    if (timeout) {
      config.timeout = timeout;
    }

    const response = await this.client.request<T>(config);
    return response.data;
  }

  // API Information Methods

  async getApiInfo(): Promise<APIVersion> {
    return this.makeRequest<APIVersion>("GET", "/");
  }

  async getHealthStatus(): Promise<APIHealth> {
    return this.makeRequest<APIHealth>("GET", "/health/");
  }

  // API Key Management Methods

  async listApiKeys(
    options: ListOptions & {
      is_active?: boolean;
      tier?: string;
    } = {}
  ): Promise<PaginatedResponse<APIKeyList>> {
    return this.makeRequest<PaginatedResponse<APIKeyList>>("GET", "/keys/", {
      params: options,
    });
  }

  async createApiKey(request: CreateAPIKeyRequest): Promise<APIKey> {
    return this.makeRequest<APIKey>("POST", "/keys/", { data: request });
  }

  async getApiKey(keyId: string): Promise<APIKey> {
    return this.makeRequest<APIKey>("GET", `/keys/${keyId}/`);
  }

  async updateApiKey(
    keyId: string,
    request: UpdateAPIKeyRequest
  ): Promise<APIKey> {
    return this.makeRequest<APIKey>("PUT", `/keys/${keyId}/`, {
      data: request,
    });
  }

  async deleteApiKey(keyId: string): Promise<void> {
    await this.makeRequest<void>("DELETE", `/keys/${keyId}/`);
  }

  async bulkApiKeyOperation(
    request: BulkOperationRequest
  ): Promise<BulkOperationResponse> {
    return this.makeRequest<BulkOperationResponse>("POST", "/keys/bulk/", {
      data: request,
    });
  }

  // Webhook Management Methods

  async listWebhooks(
    options: ListOptions & {
      is_active?: boolean;
    } = {}
  ): Promise<PaginatedResponse<WebhookEndpointList>> {
    return this.makeRequest<PaginatedResponse<WebhookEndpointList>>(
      "GET",
      "/webhooks/",
      {
        params: options,
      }
    );
  }

  async createWebhook(request: CreateWebhookRequest): Promise<WebhookEndpoint> {
    return this.makeRequest<WebhookEndpoint>("POST", "/webhooks/", {
      data: request,
    });
  }

  async getWebhook(webhookId: string): Promise<WebhookEndpoint> {
    return this.makeRequest<WebhookEndpoint>("GET", `/webhooks/${webhookId}/`);
  }

  async updateWebhook(
    webhookId: string,
    request: UpdateWebhookRequest
  ): Promise<WebhookEndpoint> {
    return this.makeRequest<WebhookEndpoint>("PUT", `/webhooks/${webhookId}/`, {
      data: request,
    });
  }

  async deleteWebhook(webhookId: string): Promise<void> {
    await this.makeRequest<void>("DELETE", `/webhooks/${webhookId}/`);
  }

  async testWebhook(webhookId: string): Promise<WebhookTestResponse> {
    return this.makeRequest<WebhookTestResponse>(
      "POST",
      `/webhooks/${webhookId}/test/`
    );
  }

  async listWebhookDeliveries(
    options: ListOptions & {
      endpoint_id?: string;
      status?: string;
      event_type?: string;
    } = {}
  ): Promise<PaginatedResponse<WebhookDelivery>> {
    return this.makeRequest<PaginatedResponse<WebhookDelivery>>(
      "GET",
      "/webhook-deliveries/",
      {
        params: options,
      }
    );
  }

  // Analytics Methods

  async getAnalytics(
    options: {
      period?: "day" | "week" | "month";
      api_key_id?: string;
    } = {}
  ): Promise<APIAnalytics> {
    return this.makeRequest<APIAnalytics>("GET", "/analytics/", {
      params: options,
    });
  }

  async listApiLogs(
    options: ListOptions & {
      api_key_id?: string;
      status_code?: number;
      start_date?: string;
      end_date?: string;
    } = {}
  ): Promise<PaginatedResponse<APIRequestLog>> {
    return this.makeRequest<PaginatedResponse<APIRequestLog>>("GET", "/logs/", {
      params: options,
    });
  }

  // Utility Methods

  setApiKey(apiKey: string): void {
    this.client.defaults.headers.common["Authorization"] = `Bearer ${apiKey}`;
  }

  setJwtToken(jwtToken: string): void {
    this.client.defaults.headers.common["Authorization"] = `Bearer ${jwtToken}`;
  }

  clearAuthentication(): void {
    delete this.client.defaults.headers.common["Authorization"];
  }

  setTimeout(timeout: number): void {
    this.client.defaults.timeout = timeout;
  }

  setBaseUrl(baseUrl: string): void {
    this.baseUrl = baseUrl.replace(/\/$/, "");
    this.client.defaults.baseURL = this.baseUrl;
  }
}
