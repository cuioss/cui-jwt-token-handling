package de.cuioss.jwt.quarkus.integration.benchmark;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openjdk.jmh.annotations.*;
import de.cuioss.tools.logging.CuiLogger;

import java.util.concurrent.TimeUnit;

/**
 * Concurrent access benchmark for JWT integration testing.
 * This benchmark measures performance under concurrent load to simulate
 * real-world multi-user scenarios.
 * 
 * Containers are managed by Maven lifecycle via exec-maven-plugin.
 */
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Threads(4) // Simulate concurrent users
public class ConcurrentIntegrationBenchmark {

    private static final CuiLogger log = new CuiLogger(ConcurrentIntegrationBenchmark.class);
    
    private String validToken;
    private String baseUrl;

    @Setup(Level.Trial)
    public void setupEnvironment() throws Exception {
        log.info("🚀 Setting up concurrent integration benchmark...");
        
        // Container is already started by Maven exec-maven-plugin
        // Configure REST Assured to use the running application
        baseUrl = "https://localhost:" + System.getProperty("test.https.port", "11443");
        
        RestAssured.baseURI = baseUrl;
        RestAssured.useRelaxedHTTPSValidation();
        
        // Generate test tokens - simplified for now
        validToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHs3PH-otkHDhFLXLuOa_w7SqDdZz5W4W5Kjb0mNa7g3l7dhfQYGGwR-v1-jQYj0I8v4p1RVCGZc";
        
        log.info("✅ Concurrent integration benchmark ready");
    }

    @TearDown(Level.Trial)
    public void teardownEnvironment() {
        // Container will be stopped by Maven exec-maven-plugin
        log.info("🛑 Concurrent integration benchmark completed");
    }

    /**
     * Benchmark concurrent token validation.
     * This measures throughput under concurrent access patterns.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkConcurrentValidation() {
        return RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
    }

    /**
     * Benchmark concurrent health checks.
     * This provides baseline concurrent performance metrics.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkConcurrentHealthCheck() {
        return RestAssured.given()
                .when()
                .get("/q/health/live");
    }
}