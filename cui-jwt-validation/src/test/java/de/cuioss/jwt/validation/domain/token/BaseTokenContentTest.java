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
package de.cuioss.jwt.validation.domain.token;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.Serial;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BaseTokenContent}.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests BaseTokenContent functionality")
class BaseTokenContentTest {

    private static final String SAMPLE_TOKEN = TestTokenGenerators.accessTokens().next().getRawToken();

    @Test
    @DisplayName("Create BaseTokenContent with valid parameters")
    void shouldCreateBaseTokenContentWithValidParameters() {
        Map<String, ClaimValue> claims = new HashMap<>();
        String rawToken = SAMPLE_TOKEN;
        TokenType tokenType = TokenType.ACCESS_TOKEN;

        var baseTokenContent = new TestBaseTokenContent(claims, rawToken, tokenType);

        assertNotNull(baseTokenContent, "BaseTokenContent should not be null");
        assertEquals(claims, baseTokenContent.getClaims(), "Claims should match");
        assertEquals(rawToken, baseTokenContent.getRawToken(), "Raw token should match");
        assertEquals(tokenType, baseTokenContent.getTokenType(), "Token type should match");
    }

    @Test
    @DisplayName("Throw NullPointerException when claims is null")
    void shouldThrowExceptionWhenClaimsIsNull() {
        assertThrows(NullPointerException.class,
                () -> new TestBaseTokenContent(null, SAMPLE_TOKEN, TokenType.ACCESS_TOKEN),
                "Should throw NullPointerException for null claims");
    }

    @Test
    @DisplayName("Return claim option correctly")
    void shouldReturnClaimOptionCorrectly() {
        Map<String, ClaimValue> claims = new HashMap<>();
        ClaimValue claimValue = ClaimValue.forPlainString("test-value");
        claims.put(ClaimName.ISSUER.getName(), claimValue);
        var baseTokenContent = new TestBaseTokenContent(claims, SAMPLE_TOKEN, TokenType.ACCESS_TOKEN);

        Optional<ClaimValue> claimOption = baseTokenContent.getClaimOption(ClaimName.ISSUER);

        assertTrue(claimOption.isPresent(), "Claim option should be present");
        assertEquals(claimValue, claimOption.get(), "Claim value should match");
    }

    @Test
    @DisplayName("Return empty claim option when claim is not present")
    void shouldReturnEmptyClaimOptionWhenClaimIsNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var baseTokenContent = new TestBaseTokenContent(claims, SAMPLE_TOKEN, TokenType.ACCESS_TOKEN);

        Optional<ClaimValue> claimOption = baseTokenContent.getClaimOption(ClaimName.ISSUER);

        assertTrue(claimOption.isEmpty(), "Claim option should be empty");
    }
    /**
     * Concrete implementation of BaseTokenContent for testing.
     */
    static class TestBaseTokenContent extends BaseTokenContent {
        @Serial
        private static final long serialVersionUID = 1L;

        TestBaseTokenContent(Map<String, ClaimValue> claims, String rawToken, TokenType tokenType) {
            super(claims, rawToken, tokenType);
        }
    }
}
