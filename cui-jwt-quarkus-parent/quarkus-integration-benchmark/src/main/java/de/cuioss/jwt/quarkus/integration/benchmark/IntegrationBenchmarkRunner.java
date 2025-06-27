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

import de.cuioss.tools.logging.CuiLogger;
import org.openjdk.jmh.Main;

import java.io.IOException;

/**
 * Main entry point for running JMH integration benchmarks.
 * This class provides the entry point for executing all integration benchmarks
 * in a containerized environment with Quarkus native execution.
 */
public class IntegrationBenchmarkRunner {

    private static final CuiLogger LOGGER = new CuiLogger(IntegrationBenchmarkRunner.class);

    /**
     * Main method to run all integration benchmarks.
     *
     * @param args Command line arguments passed to JMH
     * @throws IOException if benchmark execution fails
     */
    public static void main(String[] args) throws IOException {
        LOGGER.info("🚀 Starting JWT Quarkus Integration Benchmarks");
        LOGGER.info("📊 Running in containerized environment with native Quarkus");

        // Run all benchmarks in the package
        Main.main(args);

        LOGGER.info("✅ Integration benchmarks completed");
    }
}