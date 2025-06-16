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

import de.cuioss.jwt.quarkus.config.JwtValidationConfig;
import de.cuioss.jwt.validation.IssuerConfig;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.well_known.WellKnownDiscoveryException;
import de.cuioss.jwt.validation.well_known.WellKnownHandler;
import de.cuioss.tools.logging.CuiLogger;
import lombok.experimental.UtilityClass;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Factory class for creating {@link IssuerConfig} instances from configuration properties.
 * <p>
 * This utility class converts the Quarkus configuration properties into the domain
 * model objects used by the JWT validation library.
 * </p>
 */
@UtilityClass
@SuppressWarnings("java:S3655")
// owolff: False Positive, isPresent is checked.
class IssuerConfigFactory {

    private static final CuiLogger log = new CuiLogger(IssuerConfigFactory.class);

    /**
     * Creates a list of IssuerConfig instances from the configuration map.
     *
     * @param issuersConfig the map of issuer configurations
     * @return a list of IssuerConfig instances
     * @throws IllegalStateException if an issuer has no JWKS configuration
     */
    @SuppressWarnings("java:S3655") // owolff: False Positive, isPresent is checked.
    static List<IssuerConfig> createIssuerConfigs(Map<String, JwtValidationConfig.IssuerConfig> issuersConfig) {
        List<IssuerConfig> result = new ArrayList<>();

        for (Map.Entry<String, JwtValidationConfig.IssuerConfig> entry : issuersConfig.entrySet()) {
            String issuerName = entry.getKey();
            JwtValidationConfig.IssuerConfig issuerConfig = entry.getValue();

            // Skip disabled issuers
            if (!issuerConfig.enabled()) {
                log.info("Skipping disabled issuer: %s", issuerName);
                continue;
            }

            result.add(createSingleIssuerConfig(issuerName, issuerConfig));
        }

        return result;
    }

    /**
     * Creates a single IssuerConfig instance from the configuration.
     *
     * @param issuerName the name of the issuer
     * @param issuerConfig the issuer configuration
     * @return an IssuerConfig instance
     * @throws IllegalStateException if the issuer has no JWKS configuration
     */
    private static IssuerConfig createSingleIssuerConfig(String issuerName, JwtValidationConfig.IssuerConfig issuerConfig) {
        IssuerConfig.IssuerConfigBuilder builder = IssuerConfig.builder()
                .issuer(issuerConfig.url());

        // Configure JWKS source
        configureJwksSource(issuerName, issuerConfig, builder);

        // Add audience if present in parser config
        configureAudience(issuerConfig, builder);

        return builder.build();
    }

    /**
     * Configures the JWKS source for an issuer.
     *
     * @param issuerName the name of the issuer
     * @param issuerConfig the issuer configuration
     * @param builder the IssuerConfig builder to configure
     * @throws IllegalStateException if the issuer has no JWKS configuration
     */
    private static void configureJwksSource(String issuerName, JwtValidationConfig.IssuerConfig issuerConfig,
            IssuerConfig.IssuerConfigBuilder builder) {
        if (issuerConfig.jwks().isPresent()) {
            JwtValidationConfig.HttpJwksLoaderConfig jwksConfig = issuerConfig.jwks().get();
            HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder jwksBuilder = HttpJwksLoaderConfig.builder()
                    .refreshIntervalSeconds(jwksConfig.refreshIntervalSeconds())
                    .connectionAndReadTimeoutSeconds(
                        jwksConfig.connectionTimeoutMs() / 1000, // Convert ms to seconds
                        jwksConfig.readTimeoutMs() / 1000); // Convert ms to seconds

            configureJwksUrl(issuerName, jwksConfig, jwksBuilder);
            builder.httpJwksLoaderConfig(jwksBuilder.build());
        } else if (issuerConfig.publicKeyLocation().isPresent()) {
            builder.jwksFilePath(issuerConfig.publicKeyLocation().get());
        } else {
            throw new IllegalStateException("Issuer " + issuerName +
                    " has no JWKS configuration (jwks or publicKeyLocation)");
        }
    }

    /**
     * Configures the JWKS URL for an issuer.
     *
     * @param issuerName the name of the issuer
     * @param jwksConfig the JWKS configuration
     * @param jwksBuilder the HttpJwksLoaderConfig builder to configure
     * @throws IllegalStateException if the issuer has no JWKS URL configuration
     */
    private static void configureJwksUrl(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig jwksConfig,
            HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder jwksBuilder) {
        if (jwksConfig.wellKnownUrl().isPresent()) {
            configureWellKnownUrl(issuerName, jwksConfig, jwksBuilder);
        } else if (jwksConfig.url().isPresent()) {
            jwksBuilder.url(jwksConfig.url().get());
        } else {
            throw new IllegalStateException("Issuer " + issuerName +
                    " has no JWKS URL configuration (url or wellKnownUrl)");
        }
    }

    /**
     * Configures the well-known URL for an issuer.
     *
     * @param issuerName the name of the issuer
     * @param jwksConfig the JWKS configuration
     * @param jwksBuilder the HttpJwksLoaderConfig builder to configure
     * @throws IllegalStateException if the well-known URL fails to process and there is no direct URL fallback
     */
    private static void configureWellKnownUrl(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig jwksConfig,
            HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder jwksBuilder) {
        String wellKnownUrl = jwksConfig.wellKnownUrl().get();
        try {
            // Create a WellKnownHandler to fetch and parse the discovery document
            WellKnownHandler wellKnownHandler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .build();

            // Configure the JWKS loader using the well-known handler
            jwksBuilder.wellKnown(wellKnownHandler);

            log.info("Successfully configured JWKS using well-known URL: %s", wellKnownUrl);
        } catch (WellKnownDiscoveryException e) {
            handleWellKnownDiscoveryFailure(issuerName, jwksConfig, jwksBuilder, wellKnownUrl, e);
        }
    }

    /**
     * Handles a failure to discover the well-known URL.
     *
     * @param issuerName the name of the issuer
     * @param jwksConfig the JWKS configuration
     * @param jwksBuilder the HttpJwksLoaderConfig builder to configure
     * @param wellKnownUrl the well-known URL that failed
     * @param e the exception that occurred
     * @throws IllegalStateException if there is no direct URL fallback
     */
    private static void handleWellKnownDiscoveryFailure(String issuerName, JwtValidationConfig.HttpJwksLoaderConfig jwksConfig,
            HttpJwksLoaderConfig.HttpJwksLoaderConfigBuilder jwksBuilder, String wellKnownUrl,
            WellKnownDiscoveryException e) {
        log.error(e, "Failed to process well-known URL: %s", wellKnownUrl);

        // Fall back to direct URL if available
        if (jwksConfig.url().isPresent()) {
            log.warn("Falling back to direct JWKS URL for issuer %s", issuerName);
            jwksBuilder.url(jwksConfig.url().get());
        } else {
            throw new IllegalStateException("Issuer " + issuerName +
                    " has well-known URL that failed to process and no direct URL as fallback", e);
        }
    }

    /**
     * Configures the audience for an issuer if present.
     *
     * @param issuerConfig the issuer configuration
     * @param builder the IssuerConfig builder to configure
     */
    private static void configureAudience(JwtValidationConfig.IssuerConfig issuerConfig,
            IssuerConfig.IssuerConfigBuilder builder) {
        if (issuerConfig.parser().isPresent()) {
            JwtValidationConfig.ParserConfig parserConfig = issuerConfig.parser().get();
            if (parserConfig.audience().isPresent()) {
                builder.expectedAudience(parserConfig.audience().get());
            }
        }
    }
}
