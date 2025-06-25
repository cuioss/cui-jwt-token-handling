package de.cuioss.jwt.quarkus.integration.benchmark;

import org.openjdk.jmh.Main;
import org.openjdk.jmh.runner.RunnerException;

import java.io.IOException;

/**
 * Main entry point for running JMH integration benchmarks.
 * This class provides the entry point for executing all integration benchmarks
 * in a containerized environment with Quarkus native execution.
 */
public class IntegrationBenchmarkRunner {

    /**
     * Main method to run all integration benchmarks.
     * 
     * @param args Command line arguments passed to JMH
     * @throws IOException if benchmark execution fails
     * @throws RunnerException if benchmark runner fails
     */
    public static void main(String[] args) throws IOException, RunnerException {
        System.out.println("🚀 Starting JWT Quarkus Integration Benchmarks");
        System.out.println("📊 Running in containerized environment with native Quarkus");
        
        // Run all benchmarks in the package
        Main.main(args);
        
        System.out.println("✅ Integration benchmarks completed");
    }
}