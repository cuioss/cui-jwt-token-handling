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

import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.URI;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.Executors;
import java.util.concurrent.ScheduledExecutorService;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests HttpJwksLoaderConfig")
@SuppressWarnings("java:S5778")
// owolff: Suppressing because for a builder this is not a problem
class HttpJwksLoaderConfigTest {

    private static final String VALID_URL = "https://example.com/.well-known/jwks.json";
    private static final int REFRESH_INTERVAL = 60;

    @Test
    @DisplayName("Should create config with default values")
    void shouldCreateConfigWithDefaultValues() {
        // Given
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        // Then
        assertEquals(URI.create(VALID_URL), config.getHttpHandler().getUri());
        assertEquals(REFRESH_INTERVAL, config.getRefreshIntervalSeconds());
        assertNotNull(config.getHttpHandler().getSslContext());
        assertEquals(100, config.getMaxCacheSize()); // Default value
        assertEquals(10, config.getAdaptiveWindowSize()); // Default value
        assertEquals(10, config.getHttpHandler().getRequestTimeoutSeconds()); // Default value
        assertEquals(80, config.getBackgroundRefreshPercentage()); // Default value
    }

    @Test
    @DisplayName("Should create config with custom values")
    void shouldCreateConfigWithCustomValues() throws NoSuchAlgorithmException {
        // Given
        SSLContext sslContext = SSLContext.getDefault();
        int maxCacheSize = 200;
        int adaptiveWindowSize = 20;
        int requestTimeoutSeconds = 15;
        int backgroundRefreshPercentage = 70;

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .sslContext(sslContext)
                .maxCacheSize(maxCacheSize)
                .adaptiveWindowSize(adaptiveWindowSize)
                .requestTimeoutSeconds(requestTimeoutSeconds)
                .backgroundRefreshPercentage(backgroundRefreshPercentage)
                .build();

        // Then
        assertEquals(URI.create(VALID_URL), config.getHttpHandler().getUri());
        assertEquals(REFRESH_INTERVAL, config.getRefreshIntervalSeconds());
        assertNotNull(config.getHttpHandler().getSslContext());
        assertEquals(maxCacheSize, config.getMaxCacheSize());
        assertEquals(adaptiveWindowSize, config.getAdaptiveWindowSize());
        assertEquals(requestTimeoutSeconds, config.getHttpHandler().getRequestTimeoutSeconds());
        assertEquals(backgroundRefreshPercentage, config.getBackgroundRefreshPercentage());
    }

    @Test
    @DisplayName("Should handle URL without scheme")
    void shouldHandleUrlWithoutScheme() {
        // Given
        String urlWithoutScheme = "example.com/jwks.json";

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(urlWithoutScheme)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build();

        // Then
        assertEquals(URI.create("https://" + urlWithoutScheme), config.getHttpHandler().getUri());
    }

    @Test
    @DisplayName("Should use SecureSSLContextProvider")
    void shouldUseSecureSSLContextProvider() {
        // Given
        SecureSSLContextProvider secureProvider = new SecureSSLContextProvider();

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .tlsVersions(secureProvider)
                .build();

        // Then
        assertNotNull(config.getHttpHandler().getSslContext());
    }

    @Test
    @DisplayName("Should throw exception for negative refresh interval")
    void shouldThrowExceptionForNegativeRefreshInterval() {
        // Given
        int negativeRefreshInterval = -1;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(negativeRefreshInterval)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for negative max cache size")
    void shouldThrowExceptionForNegativeMaxCacheSize() {
        // Given
        int negativeMaxCacheSize = -1;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .maxCacheSize(negativeMaxCacheSize)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for negative adaptive window size")
    void shouldThrowExceptionForNegativeAdaptiveWindowSize() {
        // Given
        int negativeAdaptiveWindowSize = -1;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .adaptiveWindowSize(negativeAdaptiveWindowSize)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for negative request timeout")
    void shouldThrowExceptionForNegativeRequestTimeout() {
        // Given
        int negativeRequestTimeout = -1;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .requestTimeoutSeconds(negativeRequestTimeout)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for negative background refresh percentage")
    void shouldThrowExceptionForNegativeBackgroundRefreshPercentage() {
        // Given
        int negativePercentage = -1;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .backgroundRefreshPercentage(negativePercentage)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for zero background refresh percentage")
    void shouldThrowExceptionForZeroBackgroundRefreshPercentage() {
        // Given
        int zeroPercentage = 0;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .backgroundRefreshPercentage(zeroPercentage)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for too high background refresh percentage")
    void shouldThrowExceptionForTooHighBackgroundRefreshPercentage() {
        // Given
        int tooHighPercentage = 101;

        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .backgroundRefreshPercentage(tooHighPercentage)
                .build());
    }

    @Test
    @DisplayName("Should throw exception for missing JWKS URL")
    void shouldThrowExceptionForMissingJwksUrl() {
        // When/Then
        assertThrows(IllegalArgumentException.class, () -> HttpJwksLoaderConfig.builder()
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .build());
    }

    @Test
    @DisplayName("Should use custom ScheduledExecutorService")
    void shouldUseCustomScheduledExecutorService() {
        // Given
        ScheduledExecutorService customExecutorService = Executors.newScheduledThreadPool(2);

        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL)
                .scheduledExecutorService(customExecutorService)
                .build();

        // Then
        assertSame(customExecutorService, config.getScheduledExecutorService(),
                "Custom executor service should be used");

        // Clean up
        customExecutorService.shutdown();
    }

    @Test
    @DisplayName("Should create default ScheduledExecutorService when refresh interval is positive")
    void shouldCreateDefaultScheduledExecutorServiceWhenRefreshIntervalPositive() {
        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(REFRESH_INTERVAL) // Positive refresh interval
                .build();

        // Then
        assertNotNull(config.getScheduledExecutorService(),
                "Default executor service should be created for positive refresh interval");
    }

    @Test
    @DisplayName("Should not create ScheduledExecutorService when refresh interval is zero")
    void shouldNotCreateScheduledExecutorServiceWhenRefreshIntervalZero() {
        // When
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(VALID_URL)
                .refreshIntervalSeconds(0) // Zero refresh interval
                .build();

        // Then
        assertNull(config.getScheduledExecutorService(),
                "No executor service should be created for zero refresh interval");
    }
}
