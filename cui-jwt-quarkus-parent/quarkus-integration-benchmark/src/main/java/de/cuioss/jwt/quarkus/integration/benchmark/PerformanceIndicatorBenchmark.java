package de.cuioss.jwt.quarkus.integration.benchmark;

// import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.Blackhole;
import org.testcontainers.containers.ComposeContainer;
import org.testcontainers.containers.wait.strategy.Wait;

import java.io.File;
import java.time.Duration;
import java.util.concurrent.TimeUnit;

/**
 * Performance indicator benchmark for integration testing.
 * This benchmark provides the same performance categories as micro-benchmarks
 * but measures them in an end-to-end integration context.
 */
@BenchmarkMode(Mode.All)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@State(Scope.Benchmark)
public class PerformanceIndicatorBenchmark {

    private ComposeContainer environment;
    private String validToken;
    private String invalidToken;
    private String baseUrl;

    @Setup(Level.Trial)
    public void setupEnvironment() throws Exception {
        System.out.println("🚀 Setting up performance indicator benchmark...");
        
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
        invalidToken = "invalid.token.content";
        
        System.out.println("✅ Performance indicator benchmark ready");
    }

    @TearDown(Level.Trial)
    public void teardownEnvironment() {
        if (environment != null) {
            environment.stop();
        }
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
        Response response = RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
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
        Response response = RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
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
        Response response = RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
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
        // Mix of valid and invalid tokens to test error handling
        String token = System.nanoTime() % 2 == 0 ? validToken : invalidToken;
        
        Response response = RestAssured.given()
                .header("Authorization", "Bearer " + token)
                .when()
                .post("/benchmark/validate");
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
        Response response = RestAssured.given()
                .header("Authorization", "Bearer " + validToken)
                .when()
                .post("/benchmark/validate");
        bh.consume(response);
    }
}