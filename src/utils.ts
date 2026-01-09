/**
 * AWS Pentest MCP Server - Utility Module
 * 
 * Features:
 * - Caching for repeated API calls
 * - Rate limiting protection
 * - Retry logic with exponential backoff
 * - Error handling utilities
 */

// ============================================
// CACHING
// ============================================

interface CacheEntry<T> {
  data: T;
  timestamp: number;
  ttl: number;
}

class Cache {
  private store: Map<string, CacheEntry<any>> = new Map();
  private defaultTTL: number = 300000; // 5 minutes in milliseconds

  /**
   * Get cached value or undefined if expired/missing
   */
  get<T>(key: string): T | undefined {
    const entry = this.store.get(key);
    if (!entry) return undefined;
    
    if (Date.now() - entry.timestamp > entry.ttl) {
      this.store.delete(key);
      return undefined;
    }
    
    return entry.data as T;
  }

  /**
   * Set value in cache with optional TTL
   */
  set<T>(key: string, data: T, ttl?: number): void {
    this.store.set(key, {
      data,
      timestamp: Date.now(),
      ttl: ttl || this.defaultTTL,
    });
  }

  /**
   * Check if key exists and is not expired
   */
  has(key: string): boolean {
    return this.get(key) !== undefined;
  }

  /**
   * Clear specific key or all cache
   */
  clear(key?: string): void {
    if (key) {
      this.store.delete(key);
    } else {
      this.store.clear();
    }
  }

  /**
   * Get cache stats
   */
  stats(): { size: number; keys: string[] } {
    return {
      size: this.store.size,
      keys: Array.from(this.store.keys()),
    };
  }
}

// Global cache instance
export const cache = new Cache();

/**
 * Cache decorator for async functions
 * @param keyPrefix - Prefix for cache key
 * @param ttl - Time to live in milliseconds
 */
export function withCache<T>(
  keyPrefix: string,
  fn: (...args: any[]) => Promise<T>,
  ttl?: number
): (...args: any[]) => Promise<T> {
  return async (...args: any[]): Promise<T> => {
    const cacheKey = `${keyPrefix}:${JSON.stringify(args)}`;
    
    const cached = cache.get<T>(cacheKey);
    if (cached !== undefined) {
      return cached;
    }
    
    const result = await fn(...args);
    cache.set(cacheKey, result, ttl);
    return result;
  };
}

// ============================================
// RATE LIMITING
// ============================================

interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
}

class RateLimiter {
  private requests: Map<string, number[]> = new Map();
  private config: RateLimitConfig;

  constructor(config: RateLimitConfig = { maxRequests: 100, windowMs: 60000 }) {
    this.config = config;
  }

  /**
   * Check if request is allowed under rate limit
   */
  isAllowed(key: string = 'default'): boolean {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    
    let timestamps = this.requests.get(key) || [];
    timestamps = timestamps.filter(t => t > windowStart);
    
    if (timestamps.length >= this.config.maxRequests) {
      return false;
    }
    
    timestamps.push(now);
    this.requests.set(key, timestamps);
    return true;
  }

  /**
   * Wait until request is allowed
   */
  async waitForSlot(key: string = 'default'): Promise<void> {
    while (!this.isAllowed(key)) {
      await sleep(100);
    }
  }

  /**
   * Get remaining requests in current window
   */
  remaining(key: string = 'default'): number {
    const now = Date.now();
    const windowStart = now - this.config.windowMs;
    const timestamps = (this.requests.get(key) || []).filter(t => t > windowStart);
    return Math.max(0, this.config.maxRequests - timestamps.length);
  }

  /**
   * Reset rate limiter
   */
  reset(key?: string): void {
    if (key) {
      this.requests.delete(key);
    } else {
      this.requests.clear();
    }
  }
}

// Global rate limiter instances for different services
export const rateLimiters = {
  ec2: new RateLimiter({ maxRequests: 50, windowMs: 60000 }),
  iam: new RateLimiter({ maxRequests: 30, windowMs: 60000 }),
  s3: new RateLimiter({ maxRequests: 50, windowMs: 60000 }),
  lambda: new RateLimiter({ maxRequests: 30, windowMs: 60000 }),
  rds: new RateLimiter({ maxRequests: 20, windowMs: 60000 }),
  default: new RateLimiter({ maxRequests: 100, windowMs: 60000 }),
};

// ============================================
// RETRY LOGIC WITH EXPONENTIAL BACKOFF
// ============================================

interface RetryConfig {
  maxRetries: number;
  baseDelayMs: number;
  maxDelayMs: number;
  retryableErrors: string[];
}

const DEFAULT_RETRY_CONFIG: RetryConfig = {
  maxRetries: 3,
  baseDelayMs: 1000,
  maxDelayMs: 30000,
  retryableErrors: [
    'ThrottlingException',
    'TooManyRequestsException',
    'ServiceUnavailable',
    'RequestLimitExceeded',
    'ProvisionedThroughputExceededException',
    'Throttling',
    'ECONNRESET',
    'ETIMEDOUT',
    'ENOTFOUND',
    'NetworkingError',
  ],
};

/**
 * Sleep for specified milliseconds
 */
export function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Calculate exponential backoff delay with jitter
 */
function calculateBackoff(attempt: number, config: RetryConfig): number {
  const exponentialDelay = config.baseDelayMs * Math.pow(2, attempt);
  const jitter = Math.random() * 1000;
  return Math.min(exponentialDelay + jitter, config.maxDelayMs);
}

/**
 * Check if error is retryable
 */
function isRetryableError(error: any, config: RetryConfig): boolean {
  if (!error) return false;
  
  const errorName = error.name || error.code || '';
  const errorMessage = error.message || '';
  
  return config.retryableErrors.some(
    retryable => 
      errorName.includes(retryable) || 
      errorMessage.includes(retryable)
  );
}

/**
 * Execute function with retry logic
 */
export async function withRetry<T>(
  fn: () => Promise<T>,
  config: Partial<RetryConfig> = {}
): Promise<T> {
  const fullConfig = { ...DEFAULT_RETRY_CONFIG, ...config };
  let lastError: any;
  
  for (let attempt = 0; attempt <= fullConfig.maxRetries; attempt++) {
    try {
      return await fn();
    } catch (error: any) {
      lastError = error;
      
      if (attempt === fullConfig.maxRetries || !isRetryableError(error, fullConfig)) {
        throw error;
      }
      
      const delay = calculateBackoff(attempt, fullConfig);
      console.error(`Retry attempt ${attempt + 1}/${fullConfig.maxRetries} after ${delay}ms: ${error.message}`);
      await sleep(delay);
    }
  }
  
  throw lastError;
}

/**
 * Wrapper that combines rate limiting and retry logic
 */
export async function safeApiCall<T>(
  fn: () => Promise<T>,
  options: {
    service?: keyof typeof rateLimiters;
    cacheKey?: string;
    cacheTTL?: number;
    retryConfig?: Partial<RetryConfig>;
  } = {}
): Promise<T> {
  // Check cache first
  if (options.cacheKey) {
    const cached = cache.get<T>(options.cacheKey);
    if (cached !== undefined) {
      return cached;
    }
  }
  
  // Wait for rate limit slot
  const limiter = rateLimiters[options.service || 'default'];
  await limiter.waitForSlot();
  
  // Execute with retry
  const result = await withRetry(fn, options.retryConfig);
  
  // Cache result
  if (options.cacheKey) {
    cache.set(options.cacheKey, result, options.cacheTTL);
  }
  
  return result;
}

// ============================================
// ERROR HANDLING UTILITIES
// ============================================

export interface ApiError {
  code: string;
  message: string;
  service: string;
  retryable: boolean;
  details?: any;
}

/**
 * Parse AWS SDK errors into standardized format
 */
export function parseAWSError(error: any, service: string = 'AWS'): ApiError {
  return {
    code: error.name || error.code || 'UnknownError',
    message: error.message || 'An unknown error occurred',
    service,
    retryable: isRetryableError(error, DEFAULT_RETRY_CONFIG),
    details: {
      requestId: error.$metadata?.requestId,
      httpStatusCode: error.$metadata?.httpStatusCode,
    },
  };
}

/**
 * Format error for user-friendly output
 */
export function formatError(error: ApiError): string {
  let message = `❌ ${error.service} Error: ${error.message}`;
  
  if (error.code !== 'UnknownError') {
    message += ` (${error.code})`;
  }
  
  if (error.retryable) {
    message += '\n💡 This error is retryable - the operation was automatically retried.';
  }
  
  return message;
}

/**
 * Safe execution wrapper with error formatting
 */
export async function safeExecute<T>(
  fn: () => Promise<T>,
  options: {
    service?: string;
    errorPrefix?: string;
    defaultValue?: T;
  } = {}
): Promise<{ success: boolean; data?: T; error?: string }> {
  try {
    const data = await fn();
    return { success: true, data };
  } catch (error: any) {
    const parsedError = parseAWSError(error, options.service);
    const errorMessage = options.errorPrefix 
      ? `${options.errorPrefix}: ${parsedError.message}`
      : parsedError.message;
    
    if (options.defaultValue !== undefined) {
      return { success: false, data: options.defaultValue, error: errorMessage };
    }
    
    return { success: false, error: errorMessage };
  }
}

// ============================================
// BATCH PROCESSING UTILITIES
// ============================================

/**
 * Process items in batches with rate limiting
 */
export async function batchProcess<T, R>(
  items: T[],
  processor: (item: T) => Promise<R>,
  options: {
    batchSize?: number;
    delayBetweenBatches?: number;
    service?: keyof typeof rateLimiters;
  } = {}
): Promise<{ results: R[]; errors: Array<{ item: T; error: string }> }> {
  const batchSize = options.batchSize || 10;
  const delay = options.delayBetweenBatches || 1000;
  
  const results: R[] = [];
  const errors: Array<{ item: T; error: string }> = [];
  
  for (let i = 0; i < items.length; i += batchSize) {
    const batch = items.slice(i, i + batchSize);
    
    const batchResults = await Promise.allSettled(
      batch.map(item => safeApiCall(() => processor(item), { service: options.service }))
    );
    
    batchResults.forEach((result, index) => {
      if (result.status === 'fulfilled') {
        results.push(result.value);
      } else {
        errors.push({ item: batch[index], error: result.reason?.message || 'Unknown error' });
      }
    });
    
    // Delay between batches
    if (i + batchSize < items.length) {
      await sleep(delay);
    }
  }
  
  return { results, errors };
}

// ============================================
// EXPORTS
// ============================================

export { Cache, RateLimiter };
