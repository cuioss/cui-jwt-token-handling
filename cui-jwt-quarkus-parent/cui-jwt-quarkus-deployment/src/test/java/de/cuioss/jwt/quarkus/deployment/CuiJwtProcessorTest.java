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
import org.jboss.shrinkwrap.api.ShrinkWrap;
import org.jboss.shrinkwrap.api.spec.JavaArchive;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.RegisterExtension;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test for verifying the auto-configuration of the CUI JWT Quarkus extension.
 * <p>
 * This test checks:
 * <ul>
 * <li>The configuration bean is properly registered and available</li>
 * <li>The extension can be deployed and used</li>
 * </ul>
 */
@EnableTestLogger
class CuiJwtProcessorTest {

    /**
     * The Quarkus test framework.
     */
    @RegisterExtension
    static final QuarkusUnitTest unitTest = new QuarkusUnitTest()
            .setArchiveProducer(() -> ShrinkWrap.create(JavaArchive.class)
                    .addClass(JwtValidationConfig.class))
            .withConfigurationResource("application-test.properties");

    private final JwtValidationConfig jwtConfig;

    /**
     * Constructor for CuiJwtProcessorTest.
     *
     * @param jwtConfig the JWT validation configuration
     */
    @Inject
    CuiJwtProcessorTest(JwtValidationConfig jwtConfig) {
        this.jwtConfig = jwtConfig;
    }

    /**
     * Test that verifies the CDI bean is properly registered and available.
     * This indirectly tests that the feature() and registerConfigMapping() build steps
     * work correctly, as they are needed for the configuration to be available.
     */
    @Test
    @DisplayName("Should have JWT configuration available and properly configured")
    void jwtConfigAvailable() {
        assertNotNull(jwtConfig, "JwtValidationConfig should be injected");
        assertNotNull(jwtConfig.issuers(), "Issuers should not be null");
        assertNotNull(jwtConfig.parser(), "Parser config should not be null");

        // Verify the default issuer is configured
        assertTrue(jwtConfig.issuers().containsKey("default"), "Should contain default issuer");
    }

    @Test
    @DisplayName("Should test CuiJwtProcessor instantiation and basic functionality")
    void shouldTestProcessorBasicFunctionality() {
        // Test that processor can be instantiated without issues
        assertDoesNotThrow(CuiJwtProcessor::new,
                "CuiJwtProcessor should be instantiable without exceptions");

        CuiJwtProcessor processor = new CuiJwtProcessor();
        assertNotNull(processor, "Processor should not be null");

        // The actual build step methods are tested indirectly through the Quarkus test framework
        // by verifying that the configuration is properly available and the extension works
    }

}
