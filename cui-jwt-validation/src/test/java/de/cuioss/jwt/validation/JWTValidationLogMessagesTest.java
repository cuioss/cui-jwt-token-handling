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
package de.cuioss.jwt.validation;

import de.cuioss.test.generator.junit.EnableGeneratorController;
import de.cuioss.tools.logging.LogRecord;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit test for {@link JWTValidationLogMessages} utility class.
 * 
 * @author Oliver Wolff
 */
@EnableGeneratorController
class JWTValidationLogMessagesTest {

    @Test
    void shouldProvideDebugLogRecords() {
        assertNotNull(JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME);
        assertLogRecordProperties(JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME,
                "JWTValidation", 1, "JWKS URL '%s' seems to be missing a scheme, prepending 'https://'");

        assertNotNull(JWTValidationLogMessages.DEBUG.JWKS_URI_CREATED);
        assertLogRecordProperties(JWTValidationLogMessages.DEBUG.JWKS_URI_CREATED,
                "JWTValidation", 2, "Created JWKS URI '%s' from URL string '%s'");

        assertNotNull(JWTValidationLogMessages.DEBUG.INITIALIZED_JWKS_LOADER);
        assertLogRecordProperties(JWTValidationLogMessages.DEBUG.INITIALIZED_JWKS_LOADER,
                "JWTValidation", 3, "Initialized HttpJwksLoader with URL: %s, refresh interval: %s seconds");
    }

    @Test
    void shouldProvideErrorLogRecords() {
        assertNotNull(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED);
        assertLogRecordProperties(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED,
                "JWTValidation", 200, "Failed to validate validation signature: %s");

        assertNotNull(JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED);
        assertLogRecordProperties(JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED,
                "JWTValidation", 201, "JWKS content size exceeds maximum allowed size (upperLimit=%s, actual=%s)");

        assertNotNull(JWTValidationLogMessages.ERROR.ISSUER_VALIDATION_FAILED);
        assertLogRecordProperties(JWTValidationLogMessages.ERROR.ISSUER_VALIDATION_FAILED,
                "JWTValidation", 203);
    }

    @Test
    void shouldProvideInfoLogRecords() {
        assertNotNull(JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED);
        assertLogRecordProperties(JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED,
                "JWTValidation", 1, "TokenValidator initialized with %s issuer configurations");

        assertNotNull(JWTValidationLogMessages.INFO.JWKS_LOADED);
        assertLogRecordProperties(JWTValidationLogMessages.INFO.JWKS_LOADED,
                "JWTValidation", 2, "Successfully loaded and parsed JWKS from %s with %s keys");

        assertNotNull(JWTValidationLogMessages.INFO.ISSUER_RECOVERED);
        assertLogRecordProperties(JWTValidationLogMessages.INFO.ISSUER_RECOVERED,
                "JWTValidation", 25, "Issuer %s recovered and moved to healthy state");
    }

    @Test
    void shouldProvideWarnLogRecords() {
        assertNotNull(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED);
        assertLogRecordProperties(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED,
                "JWTValidation", 100, "Token exceeds maximum size limit of %s bytes, validation will be rejected");

        assertNotNull(JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY);
        assertLogRecordProperties(JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY,
                "JWTValidation", 101, "The given validation was empty, request will be rejected");

        assertNotNull(JWTValidationLogMessages.WARN.JWKS_LOADER_NOT_HEALTHY);
        assertLogRecordProperties(JWTValidationLogMessages.WARN.JWKS_LOADER_NOT_HEALTHY,
                "JWTValidation", 151, "Delegate JWKS loader initialized but not healthy for: %s");
    }

    @Test
    void shouldUseConsistentIdentifierRanges() {
        // DEBUG: 1-99
        assertTrue(JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME.getIdentifier() >= 1);
        assertTrue(JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME.getIdentifier() < 100);

        // WARN: 100-199
        assertTrue(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED.getIdentifier() >= 100);
        assertTrue(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED.getIdentifier() < 200);

        // ERROR: 200-299
        assertTrue(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED.getIdentifier() >= 200);
        assertTrue(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED.getIdentifier() < 300);
    }

    @Test
    void shouldHaveConsistentPrefixAcrossAllRecords() {
        assertEquals("JWTValidation", JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME.getPrefix());
        assertEquals("JWTValidation", JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED.getPrefix());
        assertEquals("JWTValidation", JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED.getPrefix());
        assertEquals("JWTValidation", JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED.getPrefix());
    }

    @Test
    void shouldProvideNonEmptyTemplatesForAllRecords() {
        assertFalse(JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME.getTemplate().isEmpty());
        assertFalse(JWTValidationLogMessages.INFO.TOKEN_FACTORY_INITIALIZED.getTemplate().isEmpty());
        assertFalse(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED.getTemplate().isEmpty());
        assertFalse(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED.getTemplate().isEmpty());
    }

    @Test
    void shouldHaveUniqueIdentifiersWithinCategory() {
        // Test a few key identifiers to ensure they're unique within their range
        assertNotEquals(JWTValidationLogMessages.DEBUG.JWKS_URL_MISSING_SCHEME.getIdentifier(),
                JWTValidationLogMessages.DEBUG.JWKS_URI_CREATED.getIdentifier());

        assertNotEquals(JWTValidationLogMessages.WARN.TOKEN_SIZE_EXCEEDED.getIdentifier(),
                JWTValidationLogMessages.WARN.TOKEN_IS_EMPTY.getIdentifier());

        assertNotEquals(JWTValidationLogMessages.ERROR.SIGNATURE_VALIDATION_FAILED.getIdentifier(),
                JWTValidationLogMessages.ERROR.JWKS_CONTENT_SIZE_EXCEEDED.getIdentifier());
    }

    private void assertLogRecordProperties(LogRecord logRecord, String expectedPrefix,
            int expectedIdentifier, String expectedTemplate) {
        assertEquals(expectedPrefix, logRecord.getPrefix());
        assertEquals(expectedIdentifier, logRecord.getIdentifier());
        assertEquals(expectedTemplate, logRecord.getTemplate());
    }

    private void assertLogRecordProperties(LogRecord logRecord, String expectedPrefix,
            int expectedIdentifier) {
        assertEquals(expectedPrefix, logRecord.getPrefix());
        assertEquals(expectedIdentifier, logRecord.getIdentifier());
        assertNotNull(logRecord.getTemplate());
        assertFalse(logRecord.getTemplate().isEmpty());
    }
}