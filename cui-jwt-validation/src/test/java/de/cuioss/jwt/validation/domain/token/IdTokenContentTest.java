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

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link IdTokenContent}.
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("Tests IdTokenContent functionality")
class IdTokenContentTest {

    private static final String SAMPLE_TOKEN = TestTokenGenerators.idTokens().next().getRawToken();
    private static final String TEST_NAME = "Test User";
    private static final String TEST_EMAIL = "test@example.com";
    private static final List<String> TEST_AUDIENCE = List.of("client1", "client2");

    @Test
    @DisplayName("Create IdTokenContent with valid parameters")
    void shouldCreateIdTokenContentWithValidParameters() {
        Map<String, ClaimValue> claims = new HashMap<>();
        String rawToken = SAMPLE_TOKEN;

        var idTokenContent = new IdTokenContent(claims, rawToken);

        assertNotNull(idTokenContent, "IdTokenContent should not be null");
        assertEquals(claims, idTokenContent.getClaims(), "Claims should match");
        assertEquals(rawToken, idTokenContent.getRawToken(), "Raw token should match");
        assertEquals(TokenType.ID_TOKEN, idTokenContent.getTokenType(), "Token type should be ID_TOKEN");
    }

    @Test
    @DisplayName("Return audience correctly when present")
    void shouldReturnAudienceCorrectlyWhenPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.AUDIENCE.getName(), ClaimValue.forList(TEST_AUDIENCE.toString(), TEST_AUDIENCE));
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        List<String> audience = idTokenContent.getAudience();

        assertEquals(TEST_AUDIENCE, audience, "Audience should match");
    }

    @Test
    @DisplayName("Throw exception when audience not present")
    void shouldThrowExceptionWhenAudienceNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        assertThrows(IllegalStateException.class, idTokenContent::getAudience,
                "Should throw IllegalStateException for missing audience claim");
    }

    @Test
    @DisplayName("Return name when present")
    void shouldReturnNameWhenPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.NAME.getName(), ClaimValue.forPlainString(TEST_NAME));
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        Optional<String> name = idTokenContent.getName();

        assertTrue(name.isPresent(), "Name should be present");
        assertEquals(TEST_NAME, name.get(), "Name should match");
    }

    @Test
    @DisplayName("Return empty name when not present")
    void shouldReturnEmptyNameWhenNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        Optional<String> name = idTokenContent.getName();

        assertTrue(name.isEmpty(), "Name should be empty");
    }

    @Test
    @DisplayName("Return email when present")
    void shouldReturnEmailWhenPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(TEST_EMAIL));
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        Optional<String> email = idTokenContent.getEmail();

        assertTrue(email.isPresent(), "Email should be present");
        assertEquals(TEST_EMAIL, email.get(), "Email should match");
    }

    @Test
    @DisplayName("Return empty email when not present")
    void shouldReturnEmptyEmailWhenNotPresent() {
        Map<String, ClaimValue> claims = new HashMap<>();
        var idTokenContent = new IdTokenContent(claims, SAMPLE_TOKEN);

        Optional<String> email = idTokenContent.getEmail();

        assertTrue(email.isEmpty(), "Email should be empty");
    }

}
