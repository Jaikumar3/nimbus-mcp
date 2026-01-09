/**
 * AWS Pentest MCP Server - Unit Tests
 */

import { describe, it, expect, beforeEach, jest } from '@jest/globals';
import { cache, withCache, withRetry, safeApiCall, safeExecute, batchProcess, rateLimiters, sleep } from '../src/utils';

// ============================================
// CACHE TESTS
// ============================================

describe('Cache', () => {
  beforeEach(() => {
    cache.clear();
  });

  it('should store and retrieve values', () => {
    cache.set('test-key', { data: 'test-value' });
    const result = cache.get<{ data: string }>('test-key');
    expect(result).toEqual({ data: 'test-value' });
  });

  it('should return undefined for missing keys', () => {
    const result = cache.get('non-existent');
    expect(result).toBeUndefined();
  });

  it('should expire values after TTL', async () => {
    cache.set('expire-key', 'value', 100); // 100ms TTL
    expect(cache.get('expire-key')).toBe('value');
    
    await sleep(150);
    expect(cache.get('expire-key')).toBeUndefined();
  });

  it('should clear specific key', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    
    cache.clear('key1');
    
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key2')).toBe('value2');
  });

  it('should clear all keys', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    
    cache.clear();
    
    expect(cache.get('key1')).toBeUndefined();
    expect(cache.get('key2')).toBeUndefined();
  });

  it('should report stats correctly', () => {
    cache.set('key1', 'value1');
    cache.set('key2', 'value2');
    
    const stats = cache.stats();
    expect(stats.size).toBe(2);
    expect(stats.keys).toContain('key1');
    expect(stats.keys).toContain('key2');
  });
});

describe('withCache', () => {
  beforeEach(() => {
    cache.clear();
  });

  it('should cache function results', async () => {
    let callCount = 0;
    const fn = async (x: number) => {
      callCount++;
      return x * 2;
    };

    const cachedFn = withCache('test', fn);
    
    const result1 = await cachedFn(5);
    const result2 = await cachedFn(5);
    
    expect(result1).toBe(10);
    expect(result2).toBe(10);
    expect(callCount).toBe(1); // Function called only once
  });

  it('should use different cache keys for different args', async () => {
    let callCount = 0;
    const fn = async (x: number) => {
      callCount++;
      return x * 2;
    };

    const cachedFn = withCache('test', fn);
    
    await cachedFn(5);
    await cachedFn(10);
    
    expect(callCount).toBe(2); // Different args = different calls
  });
});

// ============================================
// RATE LIMITER TESTS
// ============================================

describe('RateLimiter', () => {
  beforeEach(() => {
    rateLimiters.default.reset();
  });

  it('should allow requests within limit', () => {
    for (let i = 0; i < 10; i++) {
      expect(rateLimiters.default.isAllowed()).toBe(true);
    }
  });

  it('should report remaining requests', () => {
    const initial = rateLimiters.default.remaining();
    rateLimiters.default.isAllowed();
    expect(rateLimiters.default.remaining()).toBe(initial - 1);
  });

  it('should reset correctly', () => {
    for (let i = 0; i < 50; i++) {
      rateLimiters.default.isAllowed();
    }
    
    rateLimiters.default.reset();
    expect(rateLimiters.default.remaining()).toBe(100);
  });
});

// ============================================
// RETRY LOGIC TESTS
// ============================================

describe('withRetry', () => {
  it('should return result on first success', async () => {
    const fn = jest.fn().mockResolvedValue('success');
    
    const result = await withRetry(fn as any);
    
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(1);
  });

  it('should retry on retryable errors', async () => {
    const fn = jest.fn()
      .mockRejectedValueOnce({ name: 'ThrottlingException', message: 'Rate exceeded' })
      .mockResolvedValue('success');
    
    const result = await withRetry(fn as any, { baseDelayMs: 10 });
    
    expect(result).toBe('success');
    expect(fn).toHaveBeenCalledTimes(2);
  });

  it('should throw after max retries', async () => {
    const fn = jest.fn().mockRejectedValue({ name: 'ThrottlingException', message: 'Rate exceeded' });
    
    await expect(withRetry(fn as any, { maxRetries: 2, baseDelayMs: 10 }))
      .rejects.toMatchObject({ name: 'ThrottlingException' });
    
    expect(fn).toHaveBeenCalledTimes(3); // Initial + 2 retries
  });

  it('should not retry non-retryable errors', async () => {
    const fn = jest.fn().mockRejectedValue({ name: 'AccessDeniedException', message: 'Access denied' });
    
    await expect(withRetry(fn as any))
      .rejects.toMatchObject({ name: 'AccessDeniedException' });
    
    expect(fn).toHaveBeenCalledTimes(1);
  });
});

// ============================================
// SAFE API CALL TESTS
// ============================================

describe('safeApiCall', () => {
  beforeEach(() => {
    cache.clear();
    rateLimiters.default.reset();
  });

  it('should cache results when cacheKey provided', async () => {
    let callCount = 0;
    const fn = async () => {
      callCount++;
      return 'result';
    };

    await safeApiCall(fn, { cacheKey: 'api-test' });
    await safeApiCall(fn, { cacheKey: 'api-test' });
    
    expect(callCount).toBe(1);
  });

  it('should respect rate limits', async () => {
    const fn = jest.fn().mockResolvedValue('result');
    
    // Should not throw even with many calls due to waiting
    for (let i = 0; i < 5; i++) {
      await safeApiCall(fn as any, { service: 'ec2' });
    }
    
    expect(fn).toHaveBeenCalledTimes(5);
  });
});

// ============================================
// SAFE EXECUTE TESTS
// ============================================

describe('safeExecute', () => {
  it('should return success result', async () => {
    const result = await safeExecute(async () => 'data');
    
    expect(result.success).toBe(true);
    expect(result.data).toBe('data');
    expect(result.error).toBeUndefined();
  });

  it('should handle errors gracefully', async () => {
    const result = await safeExecute(
      async () => { throw new Error('Test error'); },
      { service: 'TestService' }
    );
    
    expect(result.success).toBe(false);
    expect(result.error).toContain('Test error');
  });

  it('should return default value on error', async () => {
    const result = await safeExecute(
      async () => { throw new Error('Test error'); },
      { defaultValue: 'default' }
    );
    
    expect(result.success).toBe(false);
    expect(result.data).toBe('default');
  });
});

// ============================================
// BATCH PROCESSING TESTS
// ============================================

describe('batchProcess', () => {
  beforeEach(() => {
    rateLimiters.default.reset();
  });

  it('should process all items successfully', async () => {
    const items = [1, 2, 3, 4, 5];
    const processor = async (x: number) => x * 2;
    
    const { results, errors } = await batchProcess(items, processor, { batchSize: 2, delayBetweenBatches: 10 });
    
    expect(results).toEqual([2, 4, 6, 8, 10]);
    expect(errors).toHaveLength(0);
  });

  it('should collect errors without failing entire batch', async () => {
    const items = [1, 2, 3];
    const processor = async (x: number) => {
      if (x === 2) throw new Error('Failed for 2');
      return x * 2;
    };
    
    const { results, errors } = await batchProcess(items, processor, { batchSize: 5, delayBetweenBatches: 10 });
    
    expect(results).toContain(2);
    expect(results).toContain(6);
    expect(errors).toHaveLength(1);
    expect(errors[0].item).toBe(2);
  });
});

// ============================================
// SLEEP UTILITY TEST
// ============================================

describe('sleep', () => {
  it('should delay for specified time', async () => {
    const start = Date.now();
    await sleep(100);
    const elapsed = Date.now() - start;
    
    expect(elapsed).toBeGreaterThanOrEqual(90);
    expect(elapsed).toBeLessThan(200);
  });
});
