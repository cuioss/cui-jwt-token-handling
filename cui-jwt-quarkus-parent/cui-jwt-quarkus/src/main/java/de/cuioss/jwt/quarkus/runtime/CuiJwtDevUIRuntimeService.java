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
package de.cuioss.jwt.quarkus.runtime;

import de.cuioss.jwt.quarkus.config.JwtPropertyKeys;
import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.MinimalTokenContent;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import org.eclipse.microprofile.config.Config;

import java.util.HashMap;
import java.util.Map;

/**
 * Runtime JSON-RPC service for CUI JWT DevUI.
 * <p>
 * This service provides runtime methods for JWT validation and status information
 * for the DevUI components. Unlike the build-time service, this provides actual
 * runtime functionality.
 * </p>
 */
@ApplicationScoped
public class CuiJwtDevUIRuntimeService {

    private static final CuiLogger LOGGER = new CuiLogger(CuiJwtDevUIRuntimeService.class);

    // String constants for commonly used literals
    private static final String RUNTIME = "RUNTIME";
    private static final String JWT_VALIDATION_DISABLED = "JWT validation is disabled";
    private static final String MESSAGE = "message";
    private static final String VALID = "valid";
    private static final String ERROR = "error";
    private static final String TOKEN_TYPE = "tokenType";
    private static final String CLAIMS = "claims";
    private static final String ISSUER = "issuer";
    private static final String HEALTH_STATUS = "healthStatus";

    private final Instance<TokenValidator> tokenValidatorInstance;
    private final Config config;

    /**
     * Constructor for dependency injection.
     * <p>
     * Uses direct Config injection instead of JwtValidationConfig CDI injection to avoid
     * known issues with @ConfigMapping CDI injection in Quarkus extensions.
     * </p>
     *
     * @param tokenValidatorInstance the token validator instance
     * @param config the MicroProfile config instance
     */
    public CuiJwtDevUIRuntimeService(Instance<TokenValidator> tokenValidatorInstance, Config config) {
        this.tokenValidatorInstance = tokenValidatorInstance;
        this.config = config;
    }

    /**
     * Get runtime JWT validation status.
     *
     * @return A map containing runtime validation status information
     */
    public Map<String, Object> getValidationStatus() {
        Map<String, Object> status = new HashMap<>();

        boolean isEnabled = isJwtEnabled();
        status.put("enabled", isEnabled);
        status.put("validatorPresent", tokenValidatorInstance.isResolvable());
        status.put("status", RUNTIME);

        if (isEnabled) {
            status.put("statusMessage", "JWT validation is active and ready");
        } else {
            status.put("statusMessage", JWT_VALIDATION_DISABLED);
        }

        return status;
    }

    /**
     * Get runtime JWKS endpoint status.
     *
     * @return A map containing runtime JWKS status information
     */
    public Map<String, Object> getJwksStatus() {
        Map<String, Object> jwksInfo = new HashMap<>();

        jwksInfo.put("status", RUNTIME);

        boolean isEnabled = isJwtEnabled();
        if (isEnabled) {
            jwksInfo.put(MESSAGE, "JWKS endpoints are configured and active");
            jwksInfo.put("issuersConfigured", countEnabledIssuers());
        } else {
            jwksInfo.put(MESSAGE, "JWKS endpoints are disabled");
            jwksInfo.put("issuersConfigured", 0);
        }

        return jwksInfo;
    }

    /**
     * Get runtime configuration information.
     *
     * @return A map containing runtime configuration information
     */
    public Map<String, Object> getConfiguration() {
        Map<String, Object> configMap = new HashMap<>();

        boolean isEnabled = isJwtEnabled();
        configMap.put("enabled", isEnabled);
        configMap.put("healthEnabled", true); // Health is always enabled in runtime
        configMap.put("buildTime", false);
        configMap.put("metricsEnabled", true); // Metrics are always enabled in runtime

        if (isEnabled) {
            configMap.put(MESSAGE, "JWT validation is properly configured");
            configMap.put("issuersCount", countEnabledIssuers());
        } else {
            configMap.put(MESSAGE, JWT_VALIDATION_DISABLED);
            configMap.put("issuersCount", 0);
        }

        return configMap;
    }

    /**
     * Validate a JWT token using the runtime validator.
     *
     * @param token The JWT token to validate
     * @return A map containing validation result
     */
    public Map<String, Object> validateToken(String token) {
        Map<String, Object> result = new HashMap<>();

        if (token == null || token.trim().isEmpty()) {
            result.put(VALID, false);
            result.put(ERROR, "Token is empty or null");
            return result;
        }

        if (!isJwtEnabled()) {
            result.put(VALID, false);
            result.put(ERROR, JWT_VALIDATION_DISABLED);
            return result;
        }

        if (!tokenValidatorInstance.isResolvable()) {
            result.put(VALID, false);
            result.put(ERROR, "Token validator is not available");
            return result;
        }

        try {
            TokenValidator validator = tokenValidatorInstance.get();
            // Try to create an access token first (most common case)
            TokenContent tokenContent = validator.createAccessToken(token.trim());

            result.put(VALID, true);
            result.put(TOKEN_TYPE, "ACCESS_TOKEN");
            result.put(CLAIMS, tokenContent.getClaims());
            result.put(ISSUER, tokenContent.getIssuer());

        } catch (TokenValidationException e) {
            // Try ID token if access token fails
            try {
                TokenValidator validator = tokenValidatorInstance.get();
                TokenContent tokenContent = validator.createIdToken(token.trim());
                result.put(VALID, true);
                result.put(TOKEN_TYPE, "ID_TOKEN");
                result.put(CLAIMS, tokenContent.getClaims());
                result.put(ISSUER, tokenContent.getIssuer());
            } catch (TokenValidationException e2) {
                // Try refresh token if ID token also fails
                try {
                    TokenValidator validator = tokenValidatorInstance.get();
                    MinimalTokenContent tokenContent = validator.createRefreshToken(token.trim());
                    result.put(VALID, true);
                    result.put(TOKEN_TYPE, "REFRESH_TOKEN");
                    result.put("rawToken", tokenContent.getRawToken());
                    // Refresh tokens may not have issuer or claims in the same way
                    if (tokenContent instanceof TokenContent fullTokenContent) {
                        result.put(CLAIMS, fullTokenContent.getClaims());
                        result.put(ISSUER, fullTokenContent.getIssuer());
                    }
                } catch (TokenValidationException e3) {
                    result.put(VALID, false);
                    result.put(ERROR, e.getMessage());
                    result.put("details", "Token validation failed for all token types");
                }
            }
        } catch (Exception e) {
            result.put(VALID, false);
            result.put(ERROR, "Token validation error: " + e.getMessage());
            result.put("details", "Exception during validation: " + e.getClass().getSimpleName());
        }

        return result;
    }

    /**
     * Get runtime health information.
     *
     * @return A map containing runtime health information
     */
    public Map<String, Object> getHealthInfo() {
        Map<String, Object> health = new HashMap<>();

        boolean configValid = isJwtEnabled();
        boolean validatorAvailable = tokenValidatorInstance.isResolvable();

        health.put("configurationValid", configValid);
        health.put("tokenValidatorAvailable", validatorAvailable);
        health.put("securityCounterAvailable", true); // Metrics are always enabled in runtime
        health.put("overallStatus", RUNTIME);

        if (configValid && validatorAvailable) {
            health.put(MESSAGE, "All JWT components are healthy and operational");
            health.put(HEALTH_STATUS, "UP");
        } else if (configValid) {
            health.put(MESSAGE, "Configuration is valid but validator is not available");
            health.put(HEALTH_STATUS, "DOWN");
        } else {
            health.put(MESSAGE, "JWT validation is disabled or misconfigured");
            health.put(HEALTH_STATUS, "DOWN");
        }

        return health;
    }

    /**
     * Helper method to determine if JWT validation is enabled.
     * JWT is considered enabled if there are any enabled issuers configured.
     * Uses direct config access instead of ConfigMapping to avoid issues.
     *
     * @return true if JWT validation is enabled, false otherwise
     */
    private boolean isJwtEnabled() {
        try {
            return countEnabledIssuers() > 0;
        } catch (Exception e) {
            // If configuration cannot be loaded, consider JWT disabled
            return false;
        }
    }

    /**
     * Counts the number of enabled issuers using direct config access.
     * This avoids ConfigMapping issues in native images and extensions.
     *
     * @return number of enabled issuers
     */
    private int countEnabledIssuers() {
        try {
            int count = 0;
            String prefix = JwtPropertyKeys.ISSUERS.BASE + ".";

            for (String propertyName : config.getPropertyNames()) {
                if (propertyName.startsWith(prefix) && propertyName.endsWith(".enabled")) {
                    boolean enabled = config.getOptionalValue(propertyName, Boolean.class).orElse(false);
                    if (enabled) {
                        count++;
                    }
                }
            }
            return count;
        } catch (Exception e) {
            LOGGER.debug("Error counting enabled issuers: " + e.getMessage());
            return 0;
        }
    }
}
