package de.cuioss.jwt.quarkus.integration.app;

import io.quarkus.runtime.Quarkus;
import io.quarkus.runtime.QuarkusApplication;
import io.quarkus.runtime.annotations.QuarkusMain;
import de.cuioss.tools.logging.CuiLogger;

/**
 * Main application class for JWT integration benchmarks.
 * This application provides endpoints for JWT validation benchmarking
 * in a containerized environment.
 */
@QuarkusMain
public class BenchmarkApplication implements QuarkusApplication {

    private static final CuiLogger log = new CuiLogger(BenchmarkApplication.class);

    @Override
    public int run(String... args) throws Exception {
        log.info("🚀 JWT Integration Benchmark Application Starting");
        Quarkus.waitForExit();
        return 0;
    }

    public static void main(String[] args) {
        Quarkus.run(BenchmarkApplication.class, args);
    }
}