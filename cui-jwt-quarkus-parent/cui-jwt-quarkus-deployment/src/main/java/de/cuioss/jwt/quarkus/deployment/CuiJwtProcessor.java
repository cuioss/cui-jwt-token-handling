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
import io.quarkus.deployment.IsDevelopment;
import io.quarkus.deployment.annotations.BuildProducer;
import io.quarkus.deployment.annotations.BuildStep;
import io.quarkus.deployment.builditem.FeatureBuildItem;
import io.quarkus.deployment.builditem.nativeimage.ReflectiveClassBuildItem;
import io.quarkus.deployment.builditem.nativeimage.RuntimeInitializedClassBuildItem;
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
 * DevUI integration.
 * </p>
 */
public class CuiJwtProcessor {

    /**
     * The feature name for the CUI JWT extension.
     */
    private static final String FEATURE = "cui-jwt";

    /**
     * Logger for build-time processing.
     */
    private static final Logger LOGGER = Logger.getLogger(CuiJwtProcessor.class);

    /**
     * Register the CUI JWT feature.
     *
     * @return A {@link FeatureBuildItem} for the CUI JWT feature
     */
    @BuildStep
    public FeatureBuildItem feature() {
        LOGGER.infof("CUI JWT feature registered");
        return new FeatureBuildItem(FEATURE);
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
                "de.cuioss.jwt.quarkus.producer.TokenValidatorProducer")
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



    // Health checks are automatically discovered by Quarkus through their annotations
    // (@ApplicationScoped, @Readiness, @Liveness), so no explicit registration is needed
}
