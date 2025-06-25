package de.cuioss.jwt.quarkus.integration.benchmark;

import org.openjdk.jmh.Main;
import org.openjdk.jmh.runner.RunnerException;
import de.cuioss.tools.logging.CuiLogger;

import java.io.IOException;

/**
 * Main entry point for running JMH integration benchmarks.
 * This class provides the entry point for executing all integration benchmarks
 * in a containerized environment with Quarkus native execution.
 */
public class IntegrationBenchmarkRunner {

    private static final CuiLogger log = new CuiLogger(IntegrationBenchmarkRunner.class);

    /**
     * Main method to run all integration benchmarks.
     * 
     * @param args Command line arguments passed to JMH
     * @throws IOException if benchmark execution fails
     * @throws RunnerException if benchmark runner fails
     */
    public static void main(String[] args) throws IOException, RunnerException {
        log.info("🚀 Starting JWT Quarkus Integration Benchmarks");
        log.info("📊 Running in containerized environment with native Quarkus");
        
        // Run all benchmarks in the package
        Main.main(args);
        
        log.info("✅ Integration benchmarks completed");
    }
}