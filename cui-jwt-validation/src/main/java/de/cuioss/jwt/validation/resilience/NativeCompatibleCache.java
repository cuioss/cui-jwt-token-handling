/**
 * Copyright © 2025 CUI-OpenSource-Software (info@cuioss.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.validation.resilience;

import de.cuioss.tools.logging.CuiLogger;
import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

import java.time.Duration;
import java.time.Instant;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import java.util.function.Function;

/**
 * Native-image compatible cache implementation that replaces Caffeine cache.
 * <p>
 * This cache provides:
 * <ul>
 *   <li>Size-based eviction with LRU policy</li>
 *   <li>Time-based expiration (TTL and TTI)</li>
 *   <li>Loading cache functionality</li>
 *   <li>Thread-safe operations</li>
 *   <li>Statistics tracking</li>
 *   <li>Adaptive expiry based on access patterns</li>
 * </ul>
 * <p>
 * The implementation is designed to be compatible with GraalVM native image
 * compilation, avoiding reflection and dynamic class generation.
 *
 * @param <K> the type of keys maintained by this cache
 * @param <V> the type of mapped values
 * @author Oliver Wolff
 * @since 1.0
 */
public class NativeCompatibleCache<K, V> implements AutoCloseable {

    private static final CuiLogger LOGGER = new CuiLogger(NativeCompatibleCache.class);

    private final ConcurrentMap<K, CacheEntry<V>> storage = new ConcurrentHashMap<>();
    private final CacheConfig config;
    private final Function<K, V> loader;
    private final CacheStatistics statistics = new CacheStatistics();
    private final ReentrantReadWriteLock lock = new ReentrantReadWriteLock();
    private final ScheduledExecutorService cleanupExecutor;

    /**
     * Creates a new cache with the specified configuration.
     *
     * @param config the cache configuration
     * @param loader the cache loader function
     */
    public NativeCompatibleCache(@NonNull CacheConfig config, Function<K, V> loader) {
        this.config = config;
        this.loader = loader;
        this.cleanupExecutor = config.isCleanupEnabled() ? 
                Executors.newSingleThreadScheduledExecutor(r -> {
                    Thread t = new Thread(r, "NativeCache-Cleanup");
                    t.setDaemon(true);
                    return t;
                }) : null;

        if (cleanupExecutor != null) {
            cleanupExecutor.scheduleAtFixedRate(this::performCleanup, 
                    config.getCleanupInterval().toSeconds(),
                    config.getCleanupInterval().toSeconds(),
                    TimeUnit.SECONDS);
        }
    }

    /**
     * Cache configuration.
     */
    @Value
    @Builder
    public static class CacheConfig {
        @Builder.Default
        int maximumSize = 100;

        @Builder.Default
        Duration expireAfterWrite = Duration.ofMinutes(30);

        @Builder.Default
        Duration expireAfterAccess = Duration.ofMinutes(15);

        @Builder.Default
        Duration cleanupInterval = Duration.ofMinutes(5);

        @Builder.Default
        boolean cleanupEnabled = true;

        @Builder.Default
        boolean recordStats = true;

        @Builder.Default
        boolean adaptiveExpiry = true;

        public static CacheConfig defaultConfig() {
            return CacheConfig.builder().build();
        }
    }

    /**
     * Cache entry wrapper with metadata.
     */
    @Value
    private static class CacheEntry<V> {
        V value;
        Instant createdAt;
        AtomicLong lastAccessTime;
        AtomicInteger accessCount;

        public CacheEntry(V value) {
            this.value = value;
            this.createdAt = Instant.now();
            this.lastAccessTime = new AtomicLong(System.currentTimeMillis());
            this.accessCount = new AtomicInteger(1);
        }

        public void recordAccess() {
            lastAccessTime.set(System.currentTimeMillis());
            accessCount.incrementAndGet();
        }

        public boolean isExpired(Duration expireAfterWrite, Duration expireAfterAccess) {
            Instant now = Instant.now();
            
            // Check write-based expiration
            if (expireAfterWrite != null && !expireAfterWrite.isZero()) {
                if (now.isAfter(createdAt.plus(expireAfterWrite))) {
                    return true;
                }
            }
            
            // Check access-based expiration
            if (expireAfterAccess != null && !expireAfterAccess.isZero()) {
                Instant lastAccess = Instant.ofEpochMilli(lastAccessTime.get());
                if (now.isAfter(lastAccess.plus(expireAfterAccess))) {
                    return true;
                }
            }
            
            return false;
        }

        public Duration getAdaptiveExpiry(CacheConfig config) {
            if (!config.isAdaptiveExpiry()) {
                return config.getExpireAfterAccess();
            }

            // Adaptive expiry based on access patterns
            int accesses = accessCount.get();
            Duration baseExpiry = config.getExpireAfterAccess();
            
            if (accesses > 10) {
                // Frequently accessed items live longer
                return baseExpiry.multipliedBy(2);
            } else if (accesses < 3) {
                // Infrequently accessed items expire sooner
                return baseExpiry.dividedBy(2);
            }
            
            return baseExpiry;
        }
    }

    /**
     * Cache statistics tracking.
     */
    public static class CacheStatistics {
        private final AtomicLong hitCount = new AtomicLong(0);
        private final AtomicLong missCount = new AtomicLong(0);
        private final AtomicLong loadCount = new AtomicLong(0);
        private final AtomicLong evictionCount = new AtomicLong(0);

        public void recordHit() {
            hitCount.incrementAndGet();
        }

        public void recordMiss() {
            missCount.incrementAndGet();
        }

        public void recordLoad() {
            loadCount.incrementAndGet();
        }

        public void recordEviction() {
            evictionCount.incrementAndGet();
        }

        public long getHitCount() {
            return hitCount.get();
        }

        public long getMissCount() {
            return missCount.get();
        }

        public long getLoadCount() {
            return loadCount.get();
        }

        public long getEvictionCount() {
            return evictionCount.get();
        }

        public double getHitRate() {
            long totalRequests = hitCount.get() + missCount.get();
            return totalRequests == 0 ? 0.0 : (double) hitCount.get() / totalRequests;
        }
    }

    /**
     * Gets a value from the cache, loading it if necessary.
     *
     * @param key the key
     * @return the value, never null
     * @throws RuntimeException if the loader fails
     */
    public V get(@NonNull K key) {
        CacheEntry<V> entry = storage.get(key);
        
        if (entry != null && !entry.isExpired(config.getExpireAfterWrite(), config.getExpireAfterAccess())) {
            entry.recordAccess();
            if (config.isRecordStats()) {
                statistics.recordHit();
            }
            return entry.getValue();
        }

        // Cache miss or expired entry
        if (config.isRecordStats()) {
            statistics.recordMiss();
        }

        // Remove expired entry
        if (entry != null) {
            storage.remove(key);
        }

        // Load new value
        return loadValue(key);
    }

    /**
     * Gets a value if present and not expired.
     *
     * @param key the key
     * @return the value if present and valid, null otherwise
     */
    public V getIfPresent(@NonNull K key) {
        CacheEntry<V> entry = storage.get(key);
        
        if (entry != null && !entry.isExpired(config.getExpireAfterWrite(), config.getExpireAfterAccess())) {
            entry.recordAccess();
            if (config.isRecordStats()) {
                statistics.recordHit();
            }
            return entry.getValue();
        }

        if (config.isRecordStats()) {
            statistics.recordMiss();
        }

        // Remove expired entry
        if (entry != null) {
            storage.remove(key);
        }

        return null;
    }

    /**
     * Puts a value in the cache.
     *
     * @param key the key
     * @param value the value
     */
    public void put(@NonNull K key, @NonNull V value) {
        CacheEntry<V> entry = new CacheEntry<>(value);
        storage.put(key, entry);
        
        // Check if we need to evict
        if (storage.size() > config.getMaximumSize()) {
            evictLeastRecentlyUsed();
        }
    }

    /**
     * Invalidates a cache entry.
     *
     * @param key the key to invalidate
     */
    public void invalidate(@NonNull K key) {
        storage.remove(key);
    }

    /**
     * Invalidates all cache entries.
     */
    public void invalidateAll() {
        storage.clear();
    }

    /**
     * Gets the current cache size.
     *
     * @return the number of entries in the cache
     */
    public long size() {
        return storage.size();
    }

    /**
     * Gets cache statistics.
     *
     * @return the cache statistics
     */
    public CacheStatistics getStatistics() {
        return statistics;
    }

    private V loadValue(K key) {
        if (loader == null) {
            throw new IllegalStateException("No loader configured for cache");
        }

        lock.writeLock().lock();
        try {
            // Double-check after acquiring write lock
            CacheEntry<V> entry = storage.get(key);
            if (entry != null && !entry.isExpired(config.getExpireAfterWrite(), config.getExpireAfterAccess())) {
                entry.recordAccess();
                return entry.getValue();
            }

            V value = loader.apply(key);
            if (value != null) {
                put(key, value);
                if (config.isRecordStats()) {
                    statistics.recordLoad();
                }
            }
            return value;
        } finally {
            lock.writeLock().unlock();
        }
    }

    private void evictLeastRecentlyUsed() {
        if (storage.isEmpty()) {
            return;
        }

        K oldestKey = null;
        long oldestAccess = Long.MAX_VALUE;

        for (var entry : storage.entrySet()) {
            long lastAccess = entry.getValue().lastAccessTime.get();
            if (lastAccess < oldestAccess) {
                oldestAccess = lastAccess;
                oldestKey = entry.getKey();
            }
        }

        if (oldestKey != null) {
            storage.remove(oldestKey);
            if (config.isRecordStats()) {
                statistics.recordEviction();
            }
            LOGGER.debug("Evicted entry with key: %s", oldestKey);
        }
    }

    private void performCleanup() {
        LOGGER.debug("Performing cache cleanup");
        int removedCount = 0;
        
        for (var iterator = storage.entrySet().iterator(); iterator.hasNext(); ) {
            var entry = iterator.next();
            CacheEntry<V> cacheEntry = entry.getValue();
            
            Duration adaptiveExpiry = cacheEntry.getAdaptiveExpiry(config);
            if (cacheEntry.isExpired(config.getExpireAfterWrite(), adaptiveExpiry)) {
                iterator.remove();
                removedCount++;
                if (config.isRecordStats()) {
                    statistics.recordEviction();
                }
            }
        }
        
        if (removedCount > 0) {
            LOGGER.debug("Cache cleanup removed %d expired entries", removedCount);
        }
    }

    @Override
    public void close() {
        if (cleanupExecutor != null) {
            cleanupExecutor.shutdown();
            try {
                if (!cleanupExecutor.awaitTermination(5, TimeUnit.SECONDS)) {
                    cleanupExecutor.shutdownNow();
                }
            } catch (InterruptedException e) {
                cleanupExecutor.shutdownNow();
                Thread.currentThread().interrupt();
            }
        }
        storage.clear();
        LOGGER.debug("Cache closed and cleared");
    }
}