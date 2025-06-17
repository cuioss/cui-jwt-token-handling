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
package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksLoaderFactory;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import okhttp3.Headers;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.io.IOException;
import java.security.Key;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class JwksClientBenchmark {

    private static final String DEFAULT_JWKS_CONTENT = InMemoryJWKSFactory.createDefaultJwks();
    private static final String DEFAULT_KEY_ID = InMemoryJWKSFactory.DEFAULT_KEY_ID;

    @State(Scope.Benchmark)
    public static class InMemoryState {
        JwksLoader jwksClient;
        String keyId;
        SecurityEventCounter securityEventCounter;

        @Setup(Level.Trial)
        public void setup() {
            keyId = DEFAULT_KEY_ID;
            securityEventCounter = new SecurityEventCounter();
            jwksClient = JwksLoaderFactory.createInMemoryLoader(DEFAULT_JWKS_CONTENT, securityEventCounter);
        }
    }

    @State(Scope.Benchmark)
    public static class HttpBenchmarkState {
        JwksLoader jwksClient;
        String keyId;
        SecurityEventCounter securityEventCounter;
        MockWebServer mockWebServer;
        HttpJwksLoaderConfig httpConfig;

        @Setup(Level.Trial)
        public void setupTrial() throws IOException {
            mockWebServer = new MockWebServer();
            mockWebServer.start();

            keyId = DEFAULT_KEY_ID;
            securityEventCounter = new SecurityEventCounter();
            httpConfig = HttpJwksLoaderConfig.builder()
                    .url(mockWebServer.url("/jwks.json").toString())
                    .refreshIntervalSeconds(60) // Default cache duration for this loader
                    .build();
            jwksClient = JwksLoaderFactory.createHttpLoader(httpConfig, securityEventCounter);

            // Enqueue initial response for setup and first non-cached calls in iterations
            mockWebServer.enqueue(new MockResponse(200, Headers.of("Content-Type", "application/json"), DEFAULT_JWKS_CONTENT));
        }

        @TearDown(Level.Trial)
        public void teardownTrial() throws IOException {
            mockWebServer.shutdown();
        }

        // For a true non-cached, we'd re-init client or clear cache if possible.
        // Here, we ensure a response is available for each invocation if we want to simulate miss.
        // However, for Invocation setup, it's better to setup the client itself.
        // For simplicity, we will rely on JMH iterations: first calls in an iteration might be non-cached.
        @Setup(Level.Iteration)
        public void setupIteration() {
            // For cached scenario, we want the cache to be hit.
            // For non-cached, we would ideally clear cache or use a new client.
            // This setup ensures there's always a response if the client decides to fetch.
            // If cache is hit, this response won't be used.
             if (mockWebServer != null && mockWebServer.getRequestCount() < 200) { // Limit enqueues
                mockWebServer.enqueue(new MockResponse(200, Headers.of("Content-Type", "application/json"), DEFAULT_JWKS_CONTENT));
            }
        }
    }

    @State(Scope.Thread) // To simulate non-cached access more reliably by having a fresh loader per thread per iteration
    public static class HttpNonCachedState {
        JwksLoader jwksClient;
        String keyId;
        SecurityEventCounter securityEventCounter;
        MockWebServer mockWebServer; // Shared web server from HttpBenchmarkState
        HttpJwksLoaderConfig httpConfig;


        @Setup(Level.Invocation)
        public void setupInvocation(HttpBenchmarkState benchmarkState) {
            // This state creates a new JwksLoader for each invocation, ensuring no caching from previous invocations.
            // It uses the MockWebServer instance from the Benchmark-scoped state.
            this.mockWebServer = benchmarkState.mockWebServer;
            this.keyId = benchmarkState.keyId;
            this.securityEventCounter = new SecurityEventCounter(); // Fresh counter
            this.httpConfig = benchmarkState.httpConfig; // Reuse config

            // Create a new loader instance for each invocation to bypass caching
            jwksClient = JwksLoaderFactory.createHttpLoader(httpConfig, securityEventCounter);

            // Ensure a response is available for this specific call
            if (mockWebServer != null && mockWebServer.getRequestCount() < 200) { // Limit enqueues
                mockWebServer.enqueue(new MockResponse(200, Headers.of("Content-Type", "application/json"), DEFAULT_JWKS_CONTENT));
            }
        }
    }

    @Benchmark
    public Optional<Key> retrieveKey_InMemoryLoader(InMemoryState state) {
        Optional<KeyInfo> keyInfoOpt = state.jwksClient.getKeyInfo(state.keyId);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    @Benchmark
    public Optional<Key> retrieveKey_HttpLoader_Cached(HttpBenchmarkState state) {
        // First call in an iteration might fill the cache, subsequent calls should hit it.
        Optional<KeyInfo> keyInfoOpt = state.jwksClient.getKeyInfo(state.keyId);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    @Benchmark
    public Optional<Key> retrieveKey_HttpLoader_NonCached(HttpNonCachedState state) {
        // This uses a JwksLoader instance created per invocation.
        Optional<KeyInfo> keyInfoOpt = state.jwksClient.getKeyInfo(state.keyId);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    // Example using Blackhole
    @Benchmark
    public void retrieveKey_InMemoryLoader_AndConsume(InMemoryState state, Blackhole bh) {
        Optional<KeyInfo> keyInfoOpt = state.jwksClient.getKeyInfo(state.keyId);
        if (keyInfoOpt.isPresent()) {
            bh.consume(Optional.of(keyInfoOpt.get().getKey()));
        } else {
            bh.consume(Optional.empty());
        }
    }
}
