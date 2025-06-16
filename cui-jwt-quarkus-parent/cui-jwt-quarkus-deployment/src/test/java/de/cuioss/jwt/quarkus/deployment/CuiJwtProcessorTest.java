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
    @DisplayName("Should test CuiJwtProcessor build step methods")
    void shouldTestBuildStepMethods() {
        // Given
        CuiJwtProcessor processor = new CuiJwtProcessor();

        // Test feature() method
        var featureBuildItem = processor.feature();
        assertNotNull(featureBuildItem, "Feature build item should not be null");
        assertEquals("cui-jwt", featureBuildItem.getName(), "Feature name should be cui-jwt");

        // Test registerConfigForReflection() method
        var configReflectionItem = processor.registerConfigForReflection();
        assertNotNull(configReflectionItem, "Config reflection item should not be null");
        assertTrue(configReflectionItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig"),
                "Should register JwtValidationConfig for reflection");

        // Test registerNestedConfigForReflection() method
        var nestedConfigReflectionItem = processor.registerNestedConfigForReflection();
        assertNotNull(nestedConfigReflectionItem, "Nested config reflection item should not be null");
        assertTrue(nestedConfigReflectionItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig$IssuerConfig"),
                "Should register IssuerConfig for reflection");
        assertTrue(nestedConfigReflectionItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig$ParserConfig"),
                "Should register ParserConfig for reflection");

        // Test registerJwtValidationClassesForReflection() method
        var jwtValidationReflectionItem = processor.registerJwtValidationClassesForReflection();
        assertNotNull(jwtValidationReflectionItem, "JWT validation reflection item should not be null");
        assertTrue(jwtValidationReflectionItem.getClassNames().contains("de.cuioss.jwt.validation.TokenValidator"),
                "Should register TokenValidator for reflection");
        assertTrue(jwtValidationReflectionItem.getClassNames().contains("de.cuioss.jwt.validation.security.SecurityEventCounter"),
                "Should register SecurityEventCounter for reflection");

        // Test runtimeInitializedClasses() method
        var runtimeInitializedItem = processor.runtimeInitializedClasses();
        assertNotNull(runtimeInitializedItem, "Runtime initialized item should not be null");
        assertEquals("de.cuioss.jwt.validation.jwks.http.HttpJwksLoader", runtimeInitializedItem.getClassName(),
                "Should register HttpJwksLoader for runtime initialization");
    }

    @Test
    @DisplayName("Should test DevUI build step methods")
    void shouldTestDevUIBuildStepMethods() {
        // Given
        CuiJwtProcessor processor = new CuiJwtProcessor();

        // Test createJwtDevUICard() method
        var cardPageBuildItem = processor.createJwtDevUICard();
        assertNotNull(cardPageBuildItem, "Card page build item should not be null");

        // Verify that pages are added (we can't easily test the exact content without accessing private fields)
        // But we can verify the method doesn't throw exceptions and returns a valid item
        assertNotNull(cardPageBuildItem.getPages(), "Pages should not be null");

        // Test createJwtDevUIJsonRPCService() method
        var jsonRPCProvidersBuildItem = processor.createJwtDevUIJsonRPCService();
        assertNotNull(jsonRPCProvidersBuildItem, "JSON RPC providers build item should not be null");
    }

    @Test
    @DisplayName("Should test processor instantiation")
    void shouldTestProcessorInstantiation() {
        // Test that processor can be instantiated without issues
        assertDoesNotThrow(CuiJwtProcessor::new,
                "CuiJwtProcessor should be instantiable without exceptions");

        CuiJwtProcessor processor = new CuiJwtProcessor();
        assertNotNull(processor, "Processor should not be null");
    }

    @Test
    @DisplayName("Should test reflection configuration completeness")
    void shouldTestReflectionConfigurationCompleteness() {
        // Given
        CuiJwtProcessor processor = new CuiJwtProcessor();

        // Test that all reflection items are created and contain expected classes
        var configReflection = processor.registerConfigForReflection();
        assertNotNull(configReflection, "Config reflection should not be null");
        assertFalse(configReflection.getClassNames().isEmpty(), "Config reflection should contain class names");

        var nestedConfigReflection = processor.registerNestedConfigForReflection();
        assertNotNull(nestedConfigReflection, "Nested config reflection should not be null");
        assertFalse(nestedConfigReflection.getClassNames().isEmpty(), "Nested config reflection should contain class names");

        var jwtValidationReflection = processor.registerJwtValidationClassesForReflection();
        assertNotNull(jwtValidationReflection, "JWT validation reflection should not be null");
        assertFalse(jwtValidationReflection.getClassNames().isEmpty(), "JWT validation reflection should contain class names");
    }

    @Test
    @DisplayName("Should test multiple calls to build step methods")
    void shouldTestMultipleBuildStepCalls() {
        // Given
        CuiJwtProcessor processor = new CuiJwtProcessor();

        // Test that multiple calls to the same method return consistent results
        var feature1 = processor.feature();
        var feature2 = processor.feature();
        assertEquals(feature1.getName(), feature2.getName(), "Feature name should be consistent");

        var config1 = processor.registerConfigForReflection();
        var config2 = processor.registerConfigForReflection();
        assertEquals(config1.getClassNames(), config2.getClassNames(), "Config reflection should be consistent");

        var runtime1 = processor.runtimeInitializedClasses();
        var runtime2 = processor.runtimeInitializedClasses();
        assertEquals(runtime1.getClassName(), runtime2.getClassName(), "Runtime initialized class should be consistent");
    }
}
