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

import de.cuioss.test.juli.junit5.EnableTestLogger;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Unit tests for {@link CuiJwtProcessor} build step methods.
 * <p>
 * This test class focuses on testing the individual @BuildStep methods
 * of the CuiJwtProcessor to improve test coverage.
 */
@EnableTestLogger
@DisplayName("CuiJwtProcessor Build Step Tests")
class CuiJwtProcessorBuildStepTest {

    private final CuiJwtProcessor processor = new CuiJwtProcessor();

    @Test
    @DisplayName("Should create feature build item")
    void shouldCreateFeatureBuildItem() {
        FeatureBuildItem featureItem = processor.feature();

        assertNotNull(featureItem, "Feature build item should not be null");
        assertEquals("cui-jwt", featureItem.getName(), "Feature name should be 'cui-jwt'");
    }

    @Test
    @DisplayName("Should register config classes for reflection")
    void shouldRegisterConfigForReflection() {
        ReflectiveClassBuildItem reflectiveItem = processor.registerConfigForReflection();

        assertNotNull(reflectiveItem, "Reflective class build item should not be null");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig"),
                "Should register JwtValidationConfig for reflection");
    }

    @Test
    @DisplayName("Should register nested config classes for reflection")
    void shouldRegisterNestedConfigForReflection() {
        ReflectiveClassBuildItem reflectiveItem = processor.registerNestedConfigForReflection();

        assertNotNull(reflectiveItem, "Reflective class build item should not be null");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig$IssuerConfig"),
                "Should register IssuerConfig for reflection");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig$ParserConfig"),
                "Should register ParserConfig for reflection");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.quarkus.config.JwtValidationConfig$HttpJwksLoaderConfig"),
                "Should register HttpJwksLoaderConfig for reflection");
    }

    @Test
    @DisplayName("Should register JWT validation classes for reflection")
    void shouldRegisterJwtValidationClassesForReflection() {
        ReflectiveClassBuildItem reflectiveItem = processor.registerJwtValidationClassesForReflection();

        assertNotNull(reflectiveItem, "Reflective class build item should not be null");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.validation.TokenValidator"),
                "Should register TokenValidator for reflection");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.validation.IssuerConfig"),
                "Should register IssuerConfig for reflection");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.validation.ParserConfig"),
                "Should register ParserConfig for reflection");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig"),
                "Should register HttpJwksLoaderConfig for reflection");
        assertTrue(reflectiveItem.getClassNames().contains("de.cuioss.jwt.validation.security.SecurityEventCounter"),
                "Should register SecurityEventCounter for reflection");
    }

    @Test
    @DisplayName("Should register runtime initialized classes")
    void shouldRegisterRuntimeInitializedClasses() {
        RuntimeInitializedClassBuildItem runtimeItem = processor.runtimeInitializedClasses();

        assertNotNull(runtimeItem, "Runtime initialized class build item should not be null");
        // Test that the method executes without throwing exceptions
        assertDoesNotThrow(() -> processor.runtimeInitializedClasses(),
                "Runtime initialization build step should execute without exceptions");
    }

    @Test
    @DisplayName("Should create DevUI card pages")
    void shouldCreateDevUICard() {
        CardPageBuildItem cardItem = processor.createJwtDevUICard();

        assertNotNull(cardItem, "Card page build item should not be null");
        assertFalse(cardItem.getPages().isEmpty(), "Should have at least one page");
        assertEquals(4, cardItem.getPages().size(), "Should have exactly 4 pages");
    }

    @Test
    @DisplayName("Should create DevUI JSON-RPC service")
    void shouldCreateDevUIJsonRPCService() {
        JsonRPCProvidersBuildItem jsonRpcItem = processor.createJwtDevUIJsonRPCService();

        assertNotNull(jsonRpcItem, "JSON-RPC providers build item should not be null");
        // Test that the method executes without throwing exceptions
        assertDoesNotThrow(() -> processor.createJwtDevUIJsonRPCService(),
                "DevUI JSON-RPC service build step should execute without exceptions");
    }

    @Test
    @DisplayName("Should execute all build steps without exceptions")
    void shouldExecuteAllBuildStepsWithoutExceptions() {
        // Test that all build step methods can be called without throwing exceptions
        assertDoesNotThrow(() -> processor.feature(), "feature() should not throw exceptions");
        assertDoesNotThrow(() -> processor.registerConfigForReflection(),
                "registerConfigForReflection() should not throw exceptions");
        assertDoesNotThrow(() -> processor.registerNestedConfigForReflection(),
                "registerNestedConfigForReflection() should not throw exceptions");
        assertDoesNotThrow(() -> processor.registerJwtValidationClassesForReflection(),
                "registerJwtValidationClassesForReflection() should not throw exceptions");
        assertDoesNotThrow(() -> processor.runtimeInitializedClasses(),
                "runtimeInitializedClasses() should not throw exceptions");
        assertDoesNotThrow(() -> processor.createJwtDevUICard(),
                "createJwtDevUICard() should not throw exceptions");
        assertDoesNotThrow(() -> processor.createJwtDevUIJsonRPCService(),
                "createJwtDevUIJsonRPCService() should not throw exceptions");
    }
}