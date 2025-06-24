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
package de.cuioss.jwt.quarkus.producer;

import de.cuioss.jwt.quarkus.config.InvalidIssuerConfigTestProfile;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;

/**
 * Tests for {@link TokenValidatorProducer} with invalid issuer configuration.
 * <p>
 * This test verifies that the producer throws an exception when the issuer configuration
 * is missing required fields (no JWKS configuration and no public key location).
 */
@QuarkusTest
@TestProfile(InvalidIssuerConfigTestProfile.class)
@EnableTestLogger
@DisplayName("Tests TokenValidatorProducer with invalid issuer config")
class InvalidIssuerConfigTokenValidatorProducerTest {

    @Inject
    JwtValidationConfig config;

    /**
     * Test that the producer throws an exception when the issuer configuration
     * is missing required fields.
     * <p>
     * This test verifies that the producer throws an IllegalStateException when
     * initializing the security event counter for an issuer that is missing both
     * JWKS configuration and public key location.
     */
    @Test
    @DisplayName("Should throw exception when issuer config is missing required fields")
    void shouldThrowExceptionWhenIssuerConfigIsMissingRequiredFields() {
        // Arrange
        var producer = new TokenValidatorProducer(config);

        // Act & Assert
        IllegalStateException exception = assertThrows(IllegalStateException.class,
                () -> producer.initialize(),
                "Should throw exception when issuer config is missing required fields");

        // Verify log message
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR, "Failed to initialize security event counter");
    }
}