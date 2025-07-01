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
        WellKnownResult<JsonObject> result = parser.parseJsonResponse(VALID_JSON, wellKnownUrl);

        assertTrue(result.isSuccess());
        assertNotNull(result.value());
        assertTrue(result.value().containsKey("issuer"));
        assertEquals("https://example.com", result.value().getString("issuer"));
        assertTrue(result.value().containsKey("jwks_uri"));
        assertEquals("https://example.com/.well-known/jwks.json", result.value().getString("jwks_uri"));
    }

    @Test
    @DisplayName("Should return error result for invalid JSON")
    void shouldReturnErrorResultForInvalidJson() {
        WellKnownResult<JsonObject> result = parser.parseJsonResponse(INVALID_JSON, wellKnownUrl);

        assertTrue(result.isError());
        assertNull(result.value());
        assertTrue(result.errorMessage().contains("Failed to parse JSON"));
        assertTrue(result.errorMessage().contains(wellKnownUrl.toString()));
    }

    @Test
    @DisplayName("Should handle empty JSON response")
    void shouldHandleEmptyJsonResponse() {
        String emptyJson = "{}";
        WellKnownResult<JsonObject> result = parser.parseJsonResponse(emptyJson, wellKnownUrl);

        assertTrue(result.isSuccess());
        assertNotNull(result.value());
        assertTrue(result.value().isEmpty());
    }

    @ParameterizedTest
    @DisplayName("Should extract string values from JsonObject correctly")
    @CsvSource({
            "issuer, https://example.com, true",
            "jwks_uri, https://example.com/.well-known/jwks.json, true",
            "non_existent_key, , false"
    })
    void shouldExtractStringValuesFromJsonObject(String key, String expectedValue, boolean shouldBePresent) {
        WellKnownResult<JsonObject> result = parser.parseJsonResponse(VALID_JSON, wellKnownUrl);
        assertTrue(result.isSuccess());
        Optional<String> value = parser.getString(result.value(), key);

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
        WellKnownResult<JsonObject> result = parser.parseJsonResponse(jsonWithNull, wellKnownUrl);
        assertTrue(result.isSuccess());

        Optional<String> nullValue = parser.getString(result.value(), "nullable_field");
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
        WellKnownResult<Void> result = parser.validateIssuer(issuer, wellKnown);
        assertTrue(result.isSuccess());
    }

    @Test
    @DisplayName("Should return error for malformed issuer URL")
    void shouldReturnErrorForMalformedIssuerUrl() {
        String malformedIssuer = "not-a-valid-url";

        WellKnownResult<Void> result = parser.validateIssuer(malformedIssuer, wellKnownUrl);

        assertTrue(result.isError());
        assertTrue(result.errorMessage().contains("Issuer URL from discovery document is malformed"));
        assertTrue(result.errorMessage().contains(malformedIssuer));
    }

    @ParameterizedTest
    @DisplayName("Should return error for issuer validation failures")
    @CsvSource({
            "http://example.com, https://example.com/.well-known/openid-configuration",
            "https://different.com, https://example.com/.well-known/openid-configuration",
            "https://example.com:8080, https://example.com:9090/.well-known/openid-configuration",
            "https://example.com/wrong/path, https://example.com/correct/path/.well-known/openid-configuration"
    })
    void shouldReturnErrorForIssuerValidationFailures(String issuer, String wellKnownUrl) throws MalformedURLException {
        URL wellKnown = URI.create(wellKnownUrl).toURL();

        WellKnownResult<Void> result = parser.validateIssuer(issuer, wellKnown);

        assertTrue(result.isError());
        assertTrue(result.errorMessage().contains("Issuer validation failed"));
        assertTrue(result.errorMessage().contains(issuer));
    }

    @Test
    @DisplayName("Should handle null parser config")
    void shouldHandleNullParserConfig() {
        WellKnownParser parserWithNullConfig = new WellKnownParser(null);

        WellKnownResult<JsonObject> result = parserWithNullConfig.parseJsonResponse(VALID_JSON, wellKnownUrl);

        assertTrue(result.isSuccess());
        assertNotNull(result.value());
        assertTrue(result.value().containsKey("issuer"));
    }

}
