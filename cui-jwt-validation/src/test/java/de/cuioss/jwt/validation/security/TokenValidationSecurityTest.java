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
package de.cuioss.jwt.validation.security;

import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.JwtTokenTamperingUtil;
import de.cuioss.jwt.validation.test.JwtTokenTamperingUtil.TamperingStrategy;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Base64;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for the security aspects of token validation.
 * <p>
 * These tests verify that the token validation library correctly rejects
 * tampered tokens and is resistant to various token cracking attempts.
 * <p>
 * What is tested:
 * <ul>
 *   <li>Rejection of tokens with tampered headers</li>
 *   <li>Rejection of tokens with tampered payloads</li>
 *   <li>Rejection of tokens with tampered signatures</li>
 *   <li>Rejection of tokens with invalid algorithms</li>
 *   <li>Rejection of tokens with missing required claims</li>
 * </ul>
 */
@EnableTestLogger
@DisplayName("Token Validation Security Tests")
class TokenValidationSecurityTest {

    private TokenValidator tokenValidator;

    @BeforeEach
    void setUp() {
        // Create issuer config with JWKS content
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer("Token-Test-testIssuer")
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .jwksContent(InMemoryJWKSFactory.createDefaultJwks())
                .build();

        // Create validation factory
        ParserConfig config = ParserConfig.builder().build();
        tokenValidator = new TokenValidator(config, issuerConfig);
    }

    @Test
    @DisplayName("Should reject tokens with tampered payloads")
    void shouldRejectTokensWithTamperedPayloads() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Decode the payload
        String payload = parts[1];
        byte[] payloadBytes = Base64.getUrlDecoder().decode(payload);
        String payloadJson = new String(payloadBytes);

        // Modify the payload (change the subject)
        String tamperedPayloadJson = payloadJson.replaceAll("\"sub\":\"[^\"]*\"", "\"sub\":\"tampered-subject\"");

        // Encode the tampered payload
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedPayloadJson.getBytes());

        // Reconstruct the token (without signature since it would be invalid)
        String tamperedToken = parts[0] + "." + tamperedPayload + ".";

        // Verify that the tampered token is rejected
        assertThrows(TokenValidationException.class, () ->
                tokenValidator.createAccessToken(tamperedToken));
    }

    @Test
    @DisplayName("Should reject tokens with tampered signatures")
    void shouldRejectTokensWithTamperedSignatures() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Tamper with the signature
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(validToken, TamperingStrategy.MODIFY_SIGNATURE_RANDOM_CHAR);

        // Verify that the tampered token is rejected
        assertThrows(TokenValidationException.class, () ->
                tokenValidator.createAccessToken(tamperedToken));
    }

    @Test
    @DisplayName("Should reject tokens with algorithm 'none'")
    void shouldRejectTokensWithAlgorithmNone() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Tamper with the token by changing the algorithm to 'none'
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(validToken, TamperingStrategy.ALGORITHM_NONE);

        // Verify that the tampered token is rejected
        assertThrows(TokenValidationException.class, () ->
                tokenValidator.createAccessToken(tamperedToken));
    }

    @Test
    @DisplayName("Should reject tokens with missing required claims")
    void shouldRejectTokensWithMissingRequiredClaims() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Decode the payload
        String payload = parts[1];
        byte[] payloadBytes = Base64.getUrlDecoder().decode(payload);
        String payloadJson = new String(payloadBytes);

        // Remove the 'iss' claim
        String tamperedPayloadJson = payloadJson.replaceAll("\"iss\":\"[^\"]*\",?", "");

        // Encode the tampered payload
        String tamperedPayload = Base64.getUrlEncoder().withoutPadding().encodeToString(tamperedPayloadJson.getBytes());

        // Reconstruct the token (without signature since it would be invalid)
        String tamperedToken = parts[0] + "." + tamperedPayload + ".";

        // Verify that the tampered token is rejected
        assertThrows(TokenValidationException.class, () ->
                tokenValidator.createAccessToken(tamperedToken));
    }

    @Test
    @DisplayName("Should accept valid tokens")
    void shouldAcceptValidTokens() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Verify that the valid token is accepted
        AccessTokenContent tokenContent = tokenValidator.createAccessToken(validToken);

        // Verify that the token content is not null
        assertNotNull(tokenContent);

        // Verify that the token content has the expected issuer
        assertEquals("Token-Test-testIssuer", tokenContent.getIssuer());
    }

    @Test
    @DisplayName("Should reject tokens with algorithm downgrade")
    void shouldRejectTokensWithAlgorithmDowngrade() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Tamper with the token by downgrading the algorithm
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(validToken, TamperingStrategy.ALGORITHM_DOWNGRADE);

        // Verify that the tampered token is rejected
        assertThrows(TokenValidationException.class, () ->
                tokenValidator.createAccessToken(tamperedToken));
    }

    @Test
    @DisplayName("Should reject tokens with invalid key ID")
    void shouldRejectTokensWithInvalidKeyId() {
        // Generate a valid token
        String validToken = TestTokenGenerators.accessTokens().next().getRawToken();

        // Tamper with the token by changing the key ID
        String tamperedToken = JwtTokenTamperingUtil.applyTamperingStrategy(validToken, TamperingStrategy.INVALID_KID);

        // Verify that the tampered token is rejected
        assertThrows(TokenValidationException.class, () ->
                tokenValidator.createAccessToken(tamperedToken));
    }
}
