package de.cuioss.jwt.quarkus.integration.benchmark;

// import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openjdk.jmh.annotations.*;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.File;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Concurrent access benchmark for JWT integration testing.
 * This benchmark measures performance under concurrent load to simulate
 * real-world multi-user scenarios.
 */
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
@Threads(4) // Simulate concurrent users
public class ConcurrentIntegrationBenchmark {

    private ComposeContainer environment;
    private String validToken;
    private String baseUrl;

    @Setup(Level.Trial)
    public void setupEnvironment() throws Exception {
        System.out.println("🚀 Setting up concurrent integration benchmark...");
        
        // Start Docker Compose environment
        environment = new ComposeContainer(new File("docker-compose.yml"))
                .withExposedService("quarkus-integration-benchmark", 8443,
                        Wait.forHttps("/q/health/live")
                                .withStartupTimeout(Duration.ofMinutes(3)))
                .withExposedService("keycloak", 8080,
                        Wait.forHttp("/auth/health/ready")
                                .withStartupTimeout(Duration.ofMinutes(2)));

        environment.start();

        // Configure REST Assured
        Integer mappedPort = environment.getServicePort("quarkus-integration-benchmark", 8443);
        baseUrl = "https://localhost:" + mappedPort;
        
        RestAssured.baseURI = baseUrl;
        RestAssured.useRelaxedHTTPSValidation();
        
        // Generate test tokens - simplified for now
        validToken = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHs3PH-otkHDhFLXLuOa_w7SqDdZz5W4W5Kjb0mNa7g3l7dhfQYGGwR-v1-jQYj0I8v4p1RVCGZc";
        
        System.out.println("✅ Concurrent integration benchmark ready");
    }

    @TearDown(Level.Trial)
    public void teardownEnvironment() {
        if (environment != null) {
            environment.stop();
        }
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