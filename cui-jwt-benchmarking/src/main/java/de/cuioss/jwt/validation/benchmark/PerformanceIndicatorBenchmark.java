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
package de.cuioss.jwt.validation.benchmark;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import org.openjdk.jmh.annotations.*;
import org.openjdk.jmh.infra.BenchmarkParams;
import org.openjdk.jmh.results.BenchmarkResult;
import org.openjdk.jmh.results.Result;
import org.openjdk.jmh.results.RunResult;

import java.util.concurrent.TimeUnit;

/**
 * Comprehensive benchmark for measuring key JWT validation performance indicators.
 * <p>
 * This benchmark focuses on the two most important performance metrics:
 * <ul>
 *   <li><strong>Throughput</strong>: Operations per second under concurrent load</li>
 *   <li><strong>Average Validation Time</strong>: Time per operation for single-threaded validation</li>
 * </ul>
 * <p>
 * The results from these benchmarks are used to calculate a weighted performance score
 * that provides a single indicator of overall JWT validation performance.
 */
@State(Scope.Benchmark)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 3, time = 1)
@Measurement(iterations = 5, time = 1)
public class PerformanceIndicatorBenchmark {

    private TokenValidator tokenValidator;
    private String validAccessToken;

    @Setup(Level.Trial)
    public void setup() {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        IssuerConfig issuerConfig = tokenHolder.getIssuerConfig();
        tokenValidator = new TokenValidator(issuerConfig);
        validAccessToken = tokenHolder.getRawToken();
    }

    /**
     * Measures token validation throughput under concurrent load.
     * <p>
     * This benchmark uses maximum available threads to measure how many
     * token validations can be performed per second under high concurrency.
     * Higher values indicate better throughput performance.
     *
     * @return validated access token content
     */
    @Benchmark
    @BenchmarkMode(Mode.Throughput)
    @OutputTimeUnit(TimeUnit.SECONDS)
    @Threads(Threads.MAX)
    public AccessTokenContent measureThroughput() {
        try {
            return tokenValidator.createAccessToken(validAccessToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("Unexpected validation failure during throughput measurement", e);
        }
    }

    /**
     * Measures average validation time for single-threaded token validation.
     * <p>
     * This benchmark measures the average time required to validate a single
     * token without concurrent load. Lower values indicate better latency performance.
     *
     * @return validated access token content
     */
    @Benchmark
    @BenchmarkMode(Mode.AverageTime)
    @OutputTimeUnit(TimeUnit.MICROSECONDS)
    @Threads(1)
    public AccessTokenContent measureAverageTime() {
        try {
            return tokenValidator.createAccessToken(validAccessToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("Unexpected validation failure during average time measurement", e);
        }
    }

    /**
     * Calculates a weighted performance score based on throughput and average time.
     * <p>
     * The performance score is calculated as:
     * <code>Score = (Throughput * 0.6) + ((1000000 / AvgTimeInMicros) * 0.4)</code>
     * <p>
     * This formula weights throughput at 60% and latency (inverted) at 40%,
     * providing a balanced view of overall performance where:
     * <ul>
     *   <li>Higher throughput contributes positively to the score</li>
     *   <li>Lower average time (better latency) contributes positively to the score</li>
     * </ul>
     *
     * @param throughputOpsPerSec Operations per second from throughput benchmark
     * @param avgTimeInMicros Average time per operation in microseconds
     * @return Weighted performance score
     */
    public static double calculatePerformanceScore(double throughputOpsPerSec, double avgTimeInMicros) {
        // Convert average time to operations per second (inverted metric)
        double latencyOpsPerSec = 1_000_000.0 / avgTimeInMicros;
        
        // Weighted score: 60% throughput, 40% latency
        return (throughputOpsPerSec * 0.6) + (latencyOpsPerSec * 0.4);
    }
}