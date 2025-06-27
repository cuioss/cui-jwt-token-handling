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

import java.util.concurrent.TimeUnit;

import static de.cuioss.jwt.quarkus.integration.benchmark.BenchmarkConstants.*;

/**
 * Integration benchmark for JWT token validation using containerized Quarkus application.
 * This benchmark measures end-to-end performance including HTTP communication,
 * container networking, and real JWT validation scenarios.
 *
 * Containers are managed by Maven lifecycle via exec-maven-plugin, similar to integration tests.
 */
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
public class IntegrationTokenValidationBenchmark {

    private static final CuiLogger LOGGER = new CuiLogger(IntegrationTokenValidationBenchmark.class);

    private TokenRepositoryManager tokenManager;


    @Setup(Level.Trial)
    @SuppressWarnings("java:S2696") // Static field update is safe in JMH @Setup context
    public void setupEnvironment() throws TokenFetchException {
        String baseUrl;
        LOGGER.info("🚀 Setting up integration benchmark environment...");

        // Container is already started by Maven exec-maven-plugin
        // Configure REST Assured to use the running application
        baseUrl = BenchmarkConfiguration.getApplicationUrl();

        RestAssured.baseURI = baseUrl;
        RestAssured.useRelaxedHTTPSValidation();

        // Initialize token repository with real Keycloak tokens
        tokenManager = TokenRepositoryManager.getInstance();
        tokenManager.initialize();

        LOGGER.info("📊 %s", tokenManager.getStatistics());

        // Warmup - ensure services are responsive
        warmupServices();

        LOGGER.info("✅ Integration benchmark environment ready");
        LOGGER.info("📱 Application URL: " + baseUrl);
    }

    @TearDown(Level.Trial)
    public void teardownEnvironment() {
        // Container will be stopped by Maven exec-maven-plugin
        LOGGER.info("🛑 Integration benchmark completed");
    }

    private void warmupServices() throws TokenFetchException {
        LOGGER.info("🔥 Warming up services...");

        // Warmup application
        for (int i = 0; i < BenchmarkConfiguration.WARMUP_TOKEN_REQUESTS; i++) {
            try {
                Response response = RestAssured.given()
                        .when()
                        .get("/q/health/live");
                if (response.statusCode() == 200) {
                    break;
                }
            } catch (RuntimeException e) {
                try {
                    Thread.sleep(1000);
                } catch (InterruptedException ie) {
                    Thread.currentThread().interrupt();
                    throw new TokenFetchException("Warmup interrupted", ie);
                }
            }
        }

        // Warmup benchmark endpoint with real tokens
        for (int i = 0; i < 3; i++) {
            try {
                String warmupToken = tokenManager.getValidToken();
                RestAssured.given()
                        .header("Authorization", "Bearer " + warmupToken)
                        .when()
                        .post("/jwt/validate");
            } catch (Exception e) {
                LOGGER.debug("Warmup request failed (expected during startup): %s", e.getMessage());
            }
        }

        LOGGER.info("✅ Services warmed up");
    }

    /**
     * Benchmark valid token validation - primary performance metric.
     * This simulates the most common scenario of validating legitimate tokens.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkValidTokenValidation() {
        String token = tokenManager.getValidToken();
        return RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
    }

    /**
     * Benchmark invalid token handling - error path performance.
     * This measures how efficiently the system handles validation failures.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkInvalidTokenValidation() {
        String token = tokenManager.getInvalidToken();
        return RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
    }

    /**
     * Benchmark expired token handling - time-based validation performance.
     * This measures how efficiently the system handles expired token validation.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkExpiredTokenValidation() {
        String token = tokenManager.getExpiredToken();
        return RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
    }

    /**
     * Benchmark average response time for valid tokens.
     * This measures latency characteristics under normal load.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public Response benchmarkValidTokenLatency() {
        String token = tokenManager.getValidToken();
        return RestAssured.given()
                .header(AUTHORIZATION_HEADER, BEARER_PREFIX + token)
                .when()
                .post(JWT_VALIDATE_PATH);
    }

    /**
     * Benchmark health check endpoint - baseline performance.
     * This provides a reference point for container and network overhead.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkHealthCheck() {
        return RestAssured.given()
                .when()
                .get(HEALTH_CHECK_PATH);
    }

    /**
     * Benchmark missing authorization header handling.
     * This measures error handling performance for malformed requests.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkMissingAuthHeader() {
        return RestAssured.given()
                .when()
                .post(JWT_VALIDATE_PATH);
    }
}