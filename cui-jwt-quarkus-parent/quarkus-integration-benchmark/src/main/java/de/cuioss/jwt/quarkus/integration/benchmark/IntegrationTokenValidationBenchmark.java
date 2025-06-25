package de.cuioss.jwt.quarkus.integration.benchmark;

import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openjdk.jmh.annotations.*;
import de.cuioss.tools.logging.CuiLogger;

import java.util.concurrent.TimeUnit;

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

    private static final CuiLogger log = new CuiLogger(IntegrationTokenValidationBenchmark.class);
    
    private String validToken;
    private String invalidToken;
    private String baseUrl;

    @Setup(Level.Trial)
    public void setupEnvironment() throws Exception {
        log.info("🚀 Setting up integration benchmark environment...");
        
        // Container is already started by Maven exec-maven-plugin
        // Configure REST Assured to use the running application
        baseUrl = "https://localhost:" + System.getProperty("test.https.port", "11443");
        
        RestAssured.baseURI = baseUrl;
        RestAssured.useRelaxedHTTPSValidation();
        
        // Generate test tokens - simplified for now
        validToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHs3PH-otkHDhFLXLuOa_w7SqDdZz5W4W5Kjb0mNa7g3l7dhfQYGGwR-v1-jQYj0I8v4p1RVCGZc";
        invalidToken = "invalid.token.content";
        
        // Warmup - ensure services are responsive
        warmupServices();
        
        log.info("✅ Integration benchmark environment ready");
        log.info("📱 Application URL: " + baseUrl);
    }

    @TearDown(Level.Trial)
    public void teardownEnvironment() {
        // Container will be stopped by Maven exec-maven-plugin
        log.info("🛑 Integration benchmark completed");
    }

    private void warmupServices() throws Exception {
        log.info("🔥 Warming up services...");
        
        // Warmup application
        for (int i = 0; i < 5; i++) {
            try {
                Response response = RestAssured.given()
                        .when()
                        .get("/q/health/live");
                if (response.statusCode() == 200) {
                    break;
                }
            } catch (Exception e) {
                Thread.sleep(1000);
            }
        }
        
        // Warmup benchmark endpoint
        for (int i = 0; i < 3; i++) {
            try {
                RestAssured.given()
                        .header("Authorization", "Bearer " + validToken)
                        .when()
                        .post("/benchmark/validate");
            } catch (Exception e) {
                // Ignore warmup failures
            }
        }
        
        log.info("✅ Services warmed up");
    }

    /**
     * Benchmark valid token validation - primary performance metric.
     * This simulates the most common scenario of validating legitimate tokens.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkValidTokenValidation() {
        return RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
    }

    /**
     * Benchmark invalid token handling - error path performance.
     * This measures how efficiently the system handles validation failures.
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    public Response benchmarkInvalidTokenValidation() {
        return RestAssured.given()
                .header("Authorization", "Bearer " + invalidToken)
                .when()
                .post("/benchmark/validate");
    }

    /**
     * Benchmark average response time for valid tokens.
     * This measures latency characteristics under normal load.
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MILLISECONDS)
    public Response benchmarkValidTokenLatency() {
        return RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
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
                .get("/q/health/live");
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
                .post("/benchmark/validate");
    }
}