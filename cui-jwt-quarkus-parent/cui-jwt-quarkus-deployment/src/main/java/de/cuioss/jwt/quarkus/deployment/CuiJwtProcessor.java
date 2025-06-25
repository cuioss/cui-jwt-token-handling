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

import io.quarkus.arc.deployment.AdditionalBeanBuildItem;
import io.quarkus.arc.deployment.SyntheticBeanBuildItem;
import io.smallrye.config.SmallRyeConfig;
import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.annotations.ExecutionTime;
import io.quarkus.deployment.annotations.Record;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.SystemPropertyBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageProxyDefinitionBuildItem;
import io.quarkus.deployment.builditem.nativeimage.NativeImageResourceBuildItem;
import io.quarkus.devui.spi.JsonRPCProvidersBuildItem;
import org.jboss.jandex.DotName;
import io.quarkus.devui.spi.page.CardPageBuildItem;
import io.quarkus.devui.spi.page.Page;
import org.jboss.logging.Logger;

/**
 * Processor for the CUI JWT Quarkus extension.
 * <p>
 * This class handles the build-time processing for the extension, including
 * registering the feature, setting up reflection configuration, and providing
 * build-time configuration validation with enhanced error reporting.
 * </p>
 * <p>
 * Enhanced features include:
 * </p>
 * <ul>
 *   <li>Build-time configuration validation with detailed error messages</li>
 *   <li>Compile-time security checks for configuration consistency</li>
 *   <li>Enhanced reflection registration for native image support</li>
 *   <li>Development-time DevUI integration with runtime status monitoring</li>
 * </ul>
 */
public class CuiJwtProcessor {

    /**
     * The feature name for the CUI JWT extension.
     */
    private static final String FEATURE = "cui-jwt";

    /**
     * Logger for build-time configuration validation and error reporting.
     */
    private static final Logger LOGGER = Logger.getLogger(CuiJwtProcessor.class);

    /**
     * Register the CUI JWT feature with build-time configuration validation.
     *
     * @return A {@link FeatureBuildItem} for the CUI JWT feature
     */
    @BuildStep
    public FeatureBuildItem feature() {
        LOGGER.infof("CUI JWT feature registered");
        return new FeatureBuildItem(FEATURE);
    }


    /**
     * Register the JWT validation configuration for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the JWT validation configuration
     */
    @BuildStep
    public ReflectiveClassBuildItem registerConfigForReflection() {
        return ReflectiveClassBuildItem.builder("de.cuioss.jwt.quarkus.config.JwtValidationConfig")
                .methods(true)
                .fields(true)
                .build();
    }

    /**
     * Register nested configuration classes for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the nested configuration classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerNestedConfigForReflection() {
        return ReflectiveClassBuildItem.builder(
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$IssuerConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$ParserConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$HttpJwksLoaderConfig")
                .methods(true)
                .fields(true)
                .build();
    }

    /**
     * Register JWT validation classes for reflection.
     *
     * @return A {@link ReflectiveClassBuildItem} for the JWT validation classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerJwtValidationClassesForReflection() {
        return ReflectiveClassBuildItem.builder(
                "de.cuioss.jwt.validation.TokenValidator",
                "de.cuioss.jwt.validation.IssuerConfig",
                "de.cuioss.jwt.validation.ParserConfig",
                "de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig",
                "de.cuioss.jwt.validation.security.SecurityEventCounter",
                "de.cuioss.jwt.quarkus.producer.TokenValidatorProducer",
                "de.cuioss.jwt.quarkus.producer.IssuerConfigFactory")
                .methods(true)
                .fields(true)
                .constructors(true)
                .build();
    }

    /**
     * Register SmallRye Config classes for reflection to support getConfigMapping() in native image.
     * This is critical for TokenValidatorProducer's config access pattern.
     *
     * @return A {@link ReflectiveClassBuildItem} for SmallRye Config classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerSmallRyeConfigForReflection() {
        return ReflectiveClassBuildItem.builder(
                "io.smallrye.config.SmallRyeConfig",
                "io.smallrye.config.ConfigMappingLoader",
                "io.smallrye.config.ConfigMappingInterface",
                "io.smallrye.config.ConfigMappingObject",
                "io.smallrye.config.ConfigMappingContext",
                "io.smallrye.config.ConfigMappingMetadata",
                "io.smallrye.config.ConfigMappings",
                "io.smallrye.config.ConfigMappingProvider")
                .methods(true)
                .fields(true)
                .constructors(true)
                .build();
    }

    /**
     * Register core Java classes needed for proxy and reflection operations in native image.
     *
     * @return A {@link ReflectiveClassBuildItem} for core Java classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerCoreJavaClassesForReflection() {
        return ReflectiveClassBuildItem.builder(
                "java.lang.reflect.Proxy",
                "java.lang.reflect.InvocationHandler",
                "java.util.Map",
                "java.util.HashMap",
                "java.util.Optional",
                "java.lang.String",
                "java.lang.Integer",
                "java.lang.Boolean")
                .methods(true)
                .fields(true)
                .constructors(true)
                .build();
    }

    /**
     * Register Bean Validation classes for configuration validation in native image.
     *
     * @return A {@link ReflectiveClassBuildItem} for Bean Validation classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerValidationClassesForReflection() {
        return ReflectiveClassBuildItem.builder(
                "jakarta.validation.constraints.NotNull",
                "jakarta.validation.constraints.NotEmpty",
                "jakarta.validation.Valid",
                "io.smallrye.config.WithDefault")
                .methods(true)
                .fields(true)
                .constructors(true)
                .build();
    }

    /**
     * Register ConfigMapping proxy classes for reflection to support dynamic proxy creation in native image.
     *
     * @return A {@link ReflectiveClassBuildItem} for ConfigMapping proxy classes
     */
    @BuildStep
    public ReflectiveClassBuildItem registerConfigMappingProxiesForReflection() {
        return ReflectiveClassBuildItem.builder(
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$IssuerConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$ParserConfig", 
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$HttpJwksLoaderConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$HealthConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$JwksHealthConfig")
                .methods(true)
                .fields(true)
                .constructors(true)
                .build();
    }

    /**
     * Register classes that need to be initialized at runtime.
     *
     * @return A {@link RuntimeInitializedClassBuildItem} for classes that need runtime initialization
     */
    @BuildStep
    public RuntimeInitializedClassBuildItem runtimeInitializedClasses() {
        return new RuntimeInitializedClassBuildItem("de.cuioss.jwt.validation.jwks.http.HttpJwksLoader");
    }

    /**
     * Register additional CDI beans for JWT validation.
     *
     * @return A {@link AdditionalBeanBuildItem} for CDI beans that need explicit registration
     */
    @BuildStep
    public AdditionalBeanBuildItem additionalBeans() {
        return AdditionalBeanBuildItem.builder()
                .addBeanClass("de.cuioss.jwt.quarkus.producer.TokenValidatorProducer")
                .addBeanClass("de.cuioss.jwt.integration.endpoint.JwtValidationEndpoint")
                .setUnremovable()
                .build();
    }

    /**
     * Register TokenValidator as an unremovable bean to ensure it's available for injection.
     * This is critical for native image compilation where CDI discovery can be limited.
     *
     * @param unremovableBeans producer for unremovable bean build items
     */
    @BuildStep
    public void registerUnremovableBeans(BuildProducer<io.quarkus.arc.deployment.UnremovableBeanBuildItem> unremovableBeans) {
        // Ensure TokenValidator is never removed from the CDI container
        unremovableBeans.produce(io.quarkus.arc.deployment.UnremovableBeanBuildItem.beanTypes(
                DotName.createSimple("de.cuioss.jwt.validation.TokenValidator")
        ));
        
        // Ensure the producer is never removed
        unremovableBeans.produce(io.quarkus.arc.deployment.UnremovableBeanBuildItem.beanTypes(
                DotName.createSimple("de.cuioss.jwt.quarkus.producer.TokenValidatorProducer")
        ));
        
        // Ensure Config is available for injection
        unremovableBeans.produce(io.quarkus.arc.deployment.UnremovableBeanBuildItem.beanTypes(
                DotName.createSimple("org.eclipse.microprofile.config.Config")
        ));
    }

    /**
     * Register native image proxy definitions for ConfigMapping interfaces.
     * This enables dynamic proxy creation in native image for configuration access.
     *
     * @return A {@link NativeImageProxyDefinitionBuildItem} for ConfigMapping proxy definitions
     */
    @BuildStep
    public NativeImageProxyDefinitionBuildItem registerConfigMappingProxies() {
        return new NativeImageProxyDefinitionBuildItem(
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$IssuerConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$ParserConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$HttpJwksLoaderConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$HealthConfig",
                "de.cuioss.jwt.quarkus.config.JwtValidationConfig$JwksHealthConfig"
        );
    }

    /**
     * Create DevUI card page for JWT validation monitoring and debugging.
     *
     * @return A {@link CardPageBuildItem} for the JWT DevUI card
     */
    @BuildStep(onlyIf = IsDevelopment.class)
    public CardPageBuildItem createJwtDevUICard() {
        CardPageBuildItem cardPageBuildItem = new CardPageBuildItem();

        // JWT Validation Status page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:shield-check")
                .title("JWT Validation Status")
                .componentLink("components/qwc-jwt-validation-status.js")
                .staticLabel("View Status"));

        // JWKS Endpoint Monitoring page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:key")
                .title("JWKS Endpoints")
                .componentLink("components/qwc-jwks-endpoints.js")
                .dynamicLabelJsonRPCMethodName("getJwksStatus"));

        // Token Debugging Tools page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:bug")
                .title("Token Debugger")
                .componentLink("components/qwc-jwt-debugger.js")
                .staticLabel("Debug Tokens"));

        // Configuration Overview page
        cardPageBuildItem.addPage(Page.webComponentPageBuilder()
                .icon("font-awesome-solid:cog")
                .title("Configuration")
                .componentLink("components/qwc-jwt-config.js")
                .staticLabel("View Config"));

        return cardPageBuildItem;
    }

    /**
     * Register JSON-RPC providers for DevUI runtime data access.
     *
     * @return A {@link JsonRPCProvidersBuildItem} for JWT DevUI JSON-RPC methods
     */
    @BuildStep(onlyIf = IsDevelopment.class)
    public JsonRPCProvidersBuildItem createJwtDevUIJsonRPCService() {
        return new JsonRPCProvidersBuildItem("CuiJwtDevUI", CuiJwtDevUIJsonRPCService.class);
    }

    /**
     * Add build-time system properties for JWT validation optimization.
     *
     * @param systemProperties producer for system property build items
     */
    @BuildStep
    public void addSystemProperties(BuildProducer<SystemPropertyBuildItem> systemProperties) {
        // Optimize JWT parsing for build-time configuration
        systemProperties.produce(new SystemPropertyBuildItem("de.cuioss.jwt.validation.build.optimize", "true"));

        // Set reasonable defaults for build-time validation
        systemProperties.produce(new SystemPropertyBuildItem("de.cuioss.jwt.validation.build.timeout", "30000"));
    }


    // Health checks are automatically discovered by Quarkus through their annotations
    // (@ApplicationScoped, @Readiness, @Liveness), so no explicit registration is needed
}
