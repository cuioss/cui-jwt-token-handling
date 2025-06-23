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
package de.cuioss.jwt.validation.jwks.http;

import com.github.benmanes.caffeine.cache.Expiry;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Adaptive cache expiry policy for JWKS caching.
 * <p>
 * This policy implements adaptive caching behavior where frequently accessed keys
 * have their expiration time extended to improve cache efficiency.
 * <p>
 * The policy tracks access patterns and extends cache expiration times when
 * the hit ratio exceeds a configurable threshold.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@RequiredArgsConstructor
public class AdaptiveCacheExpiryPolicy implements Expiry<String, JWKSKeyLoader> {

    private static final double HIGH_HIT_RATIO_THRESHOLD = 0.8;
    private static final int EXPIRATION_MULTIPLIER = 2;

    @NonNull
    private final HttpJwksLoaderConfig config;
    @NonNull
    private final AtomicInteger accessCount;
    @NonNull
    private final AtomicInteger hitCount;

    @Override
    public long expireAfterCreate(@NonNull String key, @NonNull JWKSKeyLoader value, long currentTime) {
        return TimeUnit.SECONDS.toNanos(config.getRefreshIntervalSeconds());
    }

    @Override
    public long expireAfterUpdate(@NonNull String key, @NonNull JWKSKeyLoader value, long currentTime, long currentDuration) {
        return currentDuration;
    }

    @Override
    public long expireAfterRead(@NonNull String key, @NonNull JWKSKeyLoader value, long currentTime, long currentDuration) {
        int localAccessCount = accessCount.get();
        int localHitCount = hitCount.get();

        resetCountersIfNeeded(localAccessCount);

        if (shouldExtendExpiration(localAccessCount, localHitCount)) {
            return TimeUnit.SECONDS.toNanos((long) config.getRefreshIntervalSeconds() * EXPIRATION_MULTIPLIER);
        }
        return currentDuration;
    }

    private void resetCountersIfNeeded(int localAccessCount) {
        if (localAccessCount >= config.getAdaptiveWindowSize()) {
            accessCount.set(0);
            hitCount.set(0);
        }
    }

    private boolean shouldExtendExpiration(int localAccessCount, int localHitCount) {
        return localAccessCount > 0 && calculateHitRatio(localAccessCount, localHitCount) > HIGH_HIT_RATIO_THRESHOLD;
    }

    private double calculateHitRatio(int accessCount, int hitCount) {
        return (double) hitCount / accessCount;
    }
}