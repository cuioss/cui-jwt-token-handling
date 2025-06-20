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

import java.util.concurrent.TimeUnit;

@State(Scope.Benchmark)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MICROSECONDS)
@Fork(value = 1, warmups = 1)
@Warmup(iterations = 5, time = 1)
@Measurement(iterations = 5, time = 1)
public class TokenValidatorBenchmark {

    private TokenValidator tokenValidator;
    private String accessToken;
    private String idToken;
    private String refreshToken;

    @Setup
    public void setup() {
        // Create token holders using TestTokenGenerators
        TestTokenHolder accessTokenHolder = TestTokenGenerators.accessTokens().next();
        TestTokenHolder idTokenHolder = TestTokenGenerators.idTokens().next();
        TestTokenHolder refreshTokenHolder = TestTokenGenerators.refreshTokens().next();

        // Get the issuer config from the access token holder
        IssuerConfig issuerConfig = accessTokenHolder.getIssuerConfig();

        // Create a token validator with the issuer config
        tokenValidator = new TokenValidator(issuerConfig);

        // Get the raw tokens
        accessToken = accessTokenHolder.getRawToken();
        idToken = idTokenHolder.getRawToken();
        refreshToken = refreshTokenHolder.getRawToken();
    }

    /**
     * Core benchmark method for access token validation performance.
     * This provides the baseline measurement for single-threaded validation performance.
     */
    @Benchmark
    public AccessTokenContent validateAccessToken() {
        try {
            return tokenValidator.createAccessToken(accessToken);
        } catch (TokenValidationException e) {
            throw new RuntimeException("Access token validation failed in benchmark", e);
        }
    }
}