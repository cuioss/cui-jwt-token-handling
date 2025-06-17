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
import mockwebserver3.Dispatcher;
import mockwebserver3.MockResponse;
import mockwebserver3.MockWebServer;
import mockwebserver3.RecordedRequest;
import okhttp3.Headers;
import org.jetbrains.annotations.NotNull;
import org.openjdk.jmh.annotations.*;

import java.io.IOException;
import java.security.Key;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class JwksClientFailureBenchmark {

    private static final String DEFAULT_JWKS_CONTENT = InMemoryJWKSFactory.createDefaultJwks();
    private static final String EXISTING_KEY_ID = InMemoryJWKSFactory.DEFAULT_KEY_ID;
    private static final String NON_EXISTENT_KEY_ID = "non-existent-kid";
    private static final String MALFORMED_JSON_CONTENT = "{\"keys\": [{\"kty\":\"RSA\"...this is not valid json";

    @State(Scope.Benchmark)
    public static class BenchmarkSetupState {
        MockWebServer mockWebServer;
        String serverUrl;
        SecurityEventCounter securityEventCounter;

        @Setup(Level.Trial)
        public void setupTrial() throws IOException {
            mockWebServer = new MockWebServer();
            mockWebServer.start();
            serverUrl = mockWebServer.url("/jwks.json").toString();
            securityEventCounter = new SecurityEventCounter();
        }

        @TearDown(Level.Trial)
        public void teardownTrial() throws IOException {
            mockWebServer.shutdown();
        }
    }

    private JwksLoader createLoaderWithDefaultTimeouts(String url, SecurityEventCounter counter) {
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(url)
                .refreshIntervalSeconds(0) // Disable caching for failure tests
                .build();
        return JwksLoaderFactory.createHttpLoader(config, counter);
    }


    @Benchmark
    public Optional<Key> retrieveKey_Http500Error(BenchmarkSetupState serverState) {
        serverState.mockWebServer.enqueue(new MockResponse(500, Headers.of(), ""));
        JwksLoader loader = createLoaderWithDefaultTimeouts(serverState.serverUrl, serverState.securityEventCounter);
        // Expected to result in an empty KeyInfo due to resilient loading
        Optional<KeyInfo> keyInfoOpt = loader.getKeyInfo(EXISTING_KEY_ID);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    @Benchmark
    public Optional<Key> retrieveKey_MalformedResponse(BenchmarkSetupState serverState) {
        serverState.mockWebServer.enqueue(new MockResponse(200, Headers.of("Content-Type", "application/json"), MALFORMED_JSON_CONTENT));
        JwksLoader loader = createLoaderWithDefaultTimeouts(serverState.serverUrl, serverState.securityEventCounter);
        // Expected to result in an empty KeyInfo
        Optional<KeyInfo> keyInfoOpt = loader.getKeyInfo(EXISTING_KEY_ID);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    @Benchmark
    public Optional<Key> retrieveKey_NonExistentKeyId(BenchmarkSetupState serverState) {
        serverState.mockWebServer.enqueue(new MockResponse(200, Headers.of("Content-Type", "application/json"), DEFAULT_JWKS_CONTENT));
        JwksLoader loader = createLoaderWithDefaultTimeouts(serverState.serverUrl, serverState.securityEventCounter);
        // Expected to return Optional.empty()
        Optional<KeyInfo> keyInfoOpt = loader.getKeyInfo(NON_EXISTENT_KEY_ID);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    /**
     * Benchmark for testing timeout handling.
     * This benchmark uses a custom dispatcher to simulate a timeout by delaying the response
     * beyond the client's timeout setting.
     *
     * @param serverState the benchmark setup state
     * @return an Optional containing the key if found, empty otherwise
     */
    @Benchmark
    public Optional<Key> retrieveKey_Timeout(BenchmarkSetupState serverState) {
        // Set a custom dispatcher that simulates a timeout by throwing an IOException
        serverState.mockWebServer.setDispatcher(new TimeoutSimulatingDispatcher());

        // Create a loader with default timeout
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .url(serverState.serverUrl)
                .refreshIntervalSeconds(0) // Disable caching for failure tests
                .build();
        JwksLoader loader = JwksLoaderFactory.createHttpLoader(config, serverState.securityEventCounter);

        // Expected to result in an empty KeyInfo due to timeout
        Optional<KeyInfo> keyInfoOpt = loader.getKeyInfo(EXISTING_KEY_ID);
        return keyInfoOpt.map(KeyInfo::getKey);
    }

    /**
     * A custom dispatcher that simulates a timeout by sleeping longer than the client timeout
     * or by throwing an IOException to simulate a network timeout.
     */
    @SuppressWarnings("java:S2925")
    private static class TimeoutSimulatingDispatcher extends Dispatcher {
        @NotNull
        @Override
        public MockResponse dispatch(@NotNull RecordedRequest request) {
            // Simulate a timeout by sleeping for longer than the client timeout
            try {
                // Sleep for 2 seconds, which is longer than the 1-second client timeout
                Thread.sleep(2000);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }

            // Return a response that will never be received due to the timeout
            return new MockResponse(200, Headers.of("Content-Type", "application/json"), DEFAULT_JWKS_CONTENT);
        }
    }
}
