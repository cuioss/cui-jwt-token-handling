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
package de.cuioss.jwt.quarkus.integration.benchmark;

import de.cuioss.jwt.quarkus.integration.config.BenchmarkConfiguration;
import de.cuioss.jwt.quarkus.integration.token.TokenFetchException;
import de.cuioss.jwt.quarkus.integration.token.TokenRepositoryManager;
import de.cuioss.tools.logging.CuiLogger;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;

import java.util.concurrent.TimeUnit;

import static de.cuioss.jwt.quarkus.integration.benchmark.BenchmarkConstants.*;

/**
 * Performance indicator benchmark for integration testing.
 * This benchmark provides the same performance categories as micro-benchmarks
 * but measures them in an end-to-end integration context.
 *
 * Containers are managed by Maven lifecycle via exec-maven-plugin.
 */
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
public class PerformanceIndicatorBenchmark {

    private static final CuiLogger LOGGER = new CuiLogger(PerformanceIndicatorBenchmark.class);

    private TokenRepositoryManager tokenManager;


    @Setup(Level.Trial)
    @SuppressWarnings("java:S2696") // Static field update is safe in JMH @Setup context
    public void setupEnvironment() throws TokenFetchException {
        String baseUrl;
        LOGGER.info("🚀 Setting up performance indicator benchmark...");

        // Container is already started by Maven exec-maven-plugin
        // Configure REST Assured to use the running application
        baseUrl = BenchmarkConfiguration.getApplicationUrl();

        RestAssured.baseURI = baseUrl;
        RestAssured.useRelaxedHTTPSValidation();

        // Initialize token repository with real Keycloak tokens
        tokenManager = TokenRepositoryManager.getInstance();
        tokenManager.initialize();

        LOGGER.info("✅ Performance indicator benchmark ready");
    }

    @TearDown(Level.Trial)
    public void teardownEnvironment() {
        // Container will be stopped by Maven exec-maven-plugin
        LOGGER.info("🛑 Performance indicator benchmark completed");
    }

    /**
     * Throughput measurement - requests per second.
     * Primary performance indicator for integration scenarios.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Group("throughput")
    public void measureThroughput(Blackhole bh) {
        String token = tokenManager.getValidToken();
        Response response = RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
        bh.consume(response);
    }

    /**
     * Average latency measurement - response time.
     * Critical for user experience in integration scenarios.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Group("latency")
    public void measureAverageLatency(Blackhole bh) {
        String token = tokenManager.getValidToken();
        Response response = RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
        bh.consume(response);
    }

    /**
     * Sample latency measurement - percentile analysis.
     * Provides detailed latency distribution data.
     */
    @Benchmark
    @BenchmarkMode(Mode.SampleTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Group("percentiles")
    public void measureLatencyPercentiles(Blackhole bh) {
        String token = tokenManager.getValidToken();
        Response response = RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
        bh.consume(response);
    }

    /**
     * Resilience measurement - error handling performance.
     * Measures how efficiently the system handles validation failures.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Group("resilience")
    public void measureResilience(Blackhole bh) {
        // Mix of valid and invalid tokens to test error handling (50% error rate)
        String token = tokenManager.getTokenByErrorRate(50);

        Response response = RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
        bh.consume(response);
    }

    /**
     * Single operation timing - baseline measurement.
     * Provides the most accurate single-request timing.
     */
    @Benchmark
    @BenchmarkMode(Mode.SingleShotTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    @Group("single_shot")
    public void measureSingleShot(Blackhole bh) {
        String token = tokenManager.getValidToken();
        Response response = RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
        bh.consume(response);
    }
}