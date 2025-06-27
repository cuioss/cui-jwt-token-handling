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
package de.cuioss.jwt.quarkus.deployment;

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.test.QuarkusUnitTest;
import jakarta.inject.Inject;
import org.eclipse.microprofile.config.Config;
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Integration test to verify the auto-configuration with different configuration scenarios.
 * <p>
 * This test checks:
 * <ul>
 * <li>Multiple issuers configuration</li>
 * <li>Custom parser settings</li>
 * <li>Overall integration</li>
 * </ul>
 */
@EnableTestLogger
class CuiJwtIntegrationTest {

    /**
     * The Quarkus test framework.
     */
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClasses(JwtValidationConfig.class))
            .withConfigurationResource("application-integration.properties");

    @Inject
    Config config;

    /**
     * Test that the extension correctly configures multiple issuers.
     */
    @Test
    @DisplayName("Should configure multiple issuers correctly")
    void multipleIssuersConfiguration() {
        assertNotNull(config, "Config should be injected");

        // Verify default issuer
        assertTrue(config.getOptionalValue("cui.jwt.issuers.default.enabled", Boolean.class).orElse(false),
                "Default issuer should be enabled");
        assertTrue(config.getOptionalValue("cui.jwt.issuers.default.identifier", String.class).isPresent(),
                "Default issuer should have identifier");

        // Verify keycloak issuer
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.enabled", Boolean.class).orElse(false),
                "Keycloak issuer should be enabled");
        assertTrue(config.getOptionalValue("cui.jwt.issuers.keycloak.identifier", String.class).isPresent(),
                "Keycloak issuer should have identifier");

        // Verify parser configuration
        assertTrue(config.getOptionalValue("cui.jwt.parser.leeway-seconds", Integer.class).isPresent(),
                "Parser config should be present");
    }
}
