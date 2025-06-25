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
package de.cuioss.jwt.validation.well_known;

import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import jakarta.json.JsonObject;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link WellKnownParser}.
 *
 * @author Oliver Wolff
 */
@EnableTestLogger
@EnableGeneratorController
@DisplayName("WellKnownParser")
class WellKnownParserTest {

    private static final String VALID_JSON = """
            {
                "issuer": "https://example.com",
                "jwks_uri": "https://example.com/.well-known/jwks.json",
                "authorization_endpoint": "https://example.com/auth",
                "token_endpoint": "https://example.com/token"
            }
            """;

    private static final String INVALID_JSON = "{ invalid json";

    private WellKnownParser parser;
    private URL wellKnownUrl;

    @BeforeEach
    void setup() throws MalformedURLException {
        parser = new WellKnownParser(ParserConfig.builder().build());
        wellKnownUrl = URI.create("https://example.com/.well-known/openid-configuration").toURL();
    }

    @Test
    @DisplayName("Should parse valid JSON response successfully")
    void shouldParseValidJsonResponseSuccessfully() {
        JsonObject result = parser.parseJsonResponse(VALID_JSON, wellKnownUrl);

        assertNotNull(result);
        assertTrue(result.containsKey("issuer"));
        assertEquals("https://example.com", result.getString("issuer"));
        assertTrue(result.containsKey("jwks_uri"));
        assertEquals("https://example.com/.well-known/jwks.json", result.getString("jwks_uri"));
    }

    @Test
    @DisplayName("Should throw WellKnownDiscoveryException for invalid JSON")
    void shouldThrowWellKnownDiscoveryExceptionForInvalidJson() {
        WellKnownDiscoveryException exception = assertThrows(WellKnownDiscoveryException.class,
                () -> parser.parseJsonResponse(INVALID_JSON, wellKnownUrl));

        assertTrue(exception.getMessage().contains("Failed to parse JSON"));
        assertTrue(exception.getMessage().contains(wellKnownUrl.toString()));
        assertNotNull(exception.getCause());
    }

    @Test
    @DisplayName("Should handle empty JSON response")
    void shouldHandleEmptyJsonResponse() {
        String emptyJson = "{}";
        JsonObject result = parser.parseJsonResponse(emptyJson, wellKnownUrl);

        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @ParameterizedTest
    @DisplayName("Should extract string values from JsonObject correctly")
    @CsvSource({
            "issuer, https://example.com, true",
            "jwks_uri, https://example.com/.well-known/jwks.json, true",
            "non_existent_key, , false"
    })
    void shouldExtractStringValuesFromJsonObject(String key, String expectedValue, boolean shouldBePresent) {
        JsonObject jsonObject = parser.parseJsonResponse(VALID_JSON, wellKnownUrl);
        Optional<String> value = parser.getString(jsonObject, key);

        assertEquals(shouldBePresent, value.isPresent());
        if (shouldBePresent) {
            assertEquals(expectedValue, value.get());
        }
    }

    @Test
    @DisplayName("Should return empty Optional for null value")
    void shouldReturnEmptyOptionalForNullValue() {
        String jsonWithNull = """
                {
                    "issuer": "https://example.com",
                    "nullable_field": null
                }
                """;
        JsonObject jsonObject = parser.parseJsonResponse(jsonWithNull, wellKnownUrl);

        Optional<String> nullValue = parser.getString(jsonObject, "nullable_field");
        assertFalse(nullValue.isPresent());
    }

    @ParameterizedTest
    @DisplayName("Should validate matching issuer successfully")
    @CsvSource({
            "https://example.com, https://example.com/.well-known/openid-configuration",
            "https://example.com/auth/realms/master, https://example.com/auth/realms/master/.well-known/openid-configuration",
            "https://example.com/auth/, https://example.com/auth/.well-known/openid-configuration",
            "https://example.com:443, https://example.com/.well-known/openid-configuration",
            "http://example.com:80, http://example.com/.well-known/openid-configuration"
    })
    void shouldValidateMatchingIssuerSuccessfully(String issuer, String wellKnownUrl) throws MalformedURLException {
        URL wellKnown = URI.create(wellKnownUrl).toURL();
        assertDoesNotThrow(() -> parser.validateIssuer(issuer, wellKnown));
    }

    @Test
    @DisplayName("Should throw exception for malformed issuer URL")
    void shouldThrowExceptionForMalformedIssuerUrl() {
        String malformedIssuer = "not-a-valid-url";

        WellKnownDiscoveryException exception = assertThrows(WellKnownDiscoveryException.class,
                () -> parser.validateIssuer(malformedIssuer, wellKnownUrl));

        assertTrue(exception.getMessage().contains("Issuer URL from discovery document is malformed"));
        assertTrue(exception.getMessage().contains(malformedIssuer));
        assertNotNull(exception.getCause());
    }

    @ParameterizedTest
    @DisplayName("Should throw exception for issuer validation failures")
    @CsvSource({
            "http://example.com, https://example.com/.well-known/openid-configuration",
            "https://different.com, https://example.com/.well-known/openid-configuration",
            "https://example.com:8080, https://example.com:9090/.well-known/openid-configuration",
            "https://example.com/wrong/path, https://example.com/correct/path/.well-known/openid-configuration"
    })
    void shouldThrowExceptionForIssuerValidationFailures(String issuer, String wellKnownUrl) throws MalformedURLException {
        URL wellKnown = URI.create(wellKnownUrl).toURL();

        WellKnownDiscoveryException exception = assertThrows(WellKnownDiscoveryException.class,
                () -> parser.validateIssuer(issuer, wellKnown));

        assertTrue(exception.getMessage().contains("Issuer validation failed"));
        assertTrue(exception.getMessage().contains(issuer));
    }

    @Test
    @DisplayName("Should handle null parser config")
    void shouldHandleNullParserConfig() {
        WellKnownParser parserWithNullConfig = new WellKnownParser(null);

        JsonObject result = parserWithNullConfig.parseJsonResponse(VALID_JSON, wellKnownUrl);

        assertNotNull(result);
        assertTrue(result.containsKey("issuer"));
    }

}
