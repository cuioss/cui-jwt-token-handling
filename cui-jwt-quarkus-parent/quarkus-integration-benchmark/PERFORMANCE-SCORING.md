# JWT Integration Benchmark Performance Scoring

This document describes the performance scoring system for JWT integration benchmarks, which uses the same weighted formula as the micro-benchmark module to ensure comparable results.

## Performance Score Formula

The integration benchmark module uses the identical weighted performance score formula as the micro-benchmark module:

```
Performance Score = (Throughput × 0.57) + (Latency_Inverted × 0.40) + (Error_Resilience × 0.03)
```

### Scoring Components

#### 1. Throughput (57% weight)
- **Measurement**: `PerformanceIndicatorBenchmark.measureThroughput()`
- **Mode**: `@BenchmarkMode(Mode.Throughput)`
- **Threads**: `@Threads(Threads.MAX)` (maximum concurrent load)
- **Unit**: Operations per second (ops/s)
- **Description**: HTTP requests per second under maximum concurrent load

#### 2. Latency (40% weight)
- **Measurement**: `PerformanceIndicatorBenchmark.measureAverageTime()`
- **Mode**: `@BenchmarkMode(Mode.AverageTime)`
- **Threads**: `@Threads(1)` (single-threaded)
- **Unit**: Milliseconds (converted to ops/s via: `1000 / avgTimeInMillis`)
- **Description**: Average HTTP response time converted to operations per second

#### 3. Error Resilience (3% weight)
- **Measurement**: `ErrorLoadBenchmark.validateMixedTokens()` with 0% error rate
- **Mode**: `@BenchmarkMode(Mode.Throughput)`
- **Unit**: Operations per second (ops/s)
- **Description**: Baseline throughput with all valid tokens (optimal conditions)

## Implementation Details

### Benchmark Method Names
The integration benchmark methods are named to match the micro-benchmark module patterns for automated score extraction:

- `measureThroughput()` → matches throughput extraction pattern
- `measureAverageTime()` → matches average time extraction pattern  
- `validateMixedTokens()` → matches error resilience extraction pattern

### Performance Score Calculation

The static method `PerformanceIndicatorBenchmark.calculatePerformanceScore()` implements the exact same formula:

```java
public static double calculatePerformanceScore(double throughputOpsPerSec, double avgTimeInMillis, double errorResilienceOpsPerSec) {
    // Convert average time to operations per second (inverted metric)
    double latencyOpsPerSec = 1_000.0 / avgTimeInMillis;
    
    // Weighted score: 57% throughput, 40% latency, 3% error resilience
    return (throughputOpsPerSec * 0.57) + (latencyOpsPerSec * 0.40) + (errorResilienceOpsPerSec * 0.03);
}
```

### Unit Conversion Notes

**Integration vs Micro-benchmark Scale:**
- **Integration**: Measures in milliseconds (HTTP overhead included)
- **Micro-benchmark**: Measures in microseconds (pure library calls)
- **Conversion**: Integration uses `1000 / milliseconds` vs micro uses `1_000_000 / microseconds`

## Benchmark Classes

### PerformanceIndicatorBenchmark
- **Purpose**: Core scoring metrics (throughput, latency, resilience baseline)
- **Methods**: `measureThroughput()`, `measureAverageTime()`, `measureErrorResilience()`, `measureSampleTime()`, `measureSingleShotTime()`

### ErrorLoadBenchmark  
- **Purpose**: Error resilience testing with various error rates
- **Methods**: `validateMixedTokens()` (0% errors), `validateMixedTokens10PercentError()`, `validateMixedTokens50PercentError()`, `validateMixedTokens90PercentError()`, `validateMixedTokens100PercentError()`

### IntegrationTokenValidationBenchmark
- **Purpose**: Specific token validation scenarios  
- **Methods**: `benchmarkValidTokenValidation()`, `benchmarkInvalidTokenValidation()`, `benchmarkExpiredTokenValidation()`

### ConcurrentIntegrationBenchmark
- **Purpose**: Concurrent access patterns with fixed thread counts
- **Configuration**: `@Threads(4)` for multi-user simulation

## JMH Result Extraction

The scoring system extracts metrics from JMH JSON results using these benchmark names:

```bash
# Throughput extraction
jq -r '.[] | select(.benchmark == "de.cuioss.jwt.quarkus.integration.benchmark.PerformanceIndicatorBenchmark.measureThroughput")'

# Average time extraction  
jq -r '.[] | select(.benchmark == "de.cuioss.jwt.quarkus.integration.benchmark.PerformanceIndicatorBenchmark.measureAverageTime")'

# Error resilience extraction (0% error rate)
jq -r '.[] | select(.benchmark == "de.cuioss.jwt.quarkus.integration.benchmark.ErrorLoadBenchmark.validateMixedTokens")'
```

## Performance Interpretation

The integration benchmark scores should be interpreted in context:

- **Absolute Values**: Will be lower than micro-benchmarks due to HTTP/container overhead
- **Relative Trends**: Should track similarly to micro-benchmark performance changes
- **Scale Difference**: Expect ~1000x difference (milliseconds vs microseconds)
- **Scoring Validity**: The weighted formula remains valid for comparing integration performance across versions

## Usage

To calculate the performance score from JMH results:

1. Extract throughput (ops/s) from `measureThroughput` 
2. Extract average time (ms) from `measureAverageTime`
3. Extract error resilience (ops/s) from `validateMixedTokens`
4. Apply the weighted formula: `(throughput * 0.57) + ((1000/avgTime) * 0.40) + (resilience * 0.03)`

This ensures the integration benchmark module produces scores using the identical methodology as the micro-benchmark module, enabling consistent performance tracking across different testing approaches.