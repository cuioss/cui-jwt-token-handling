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

import java.util.HashMap;
import java.util.Map;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.inject.Instance;
import jakarta.inject.Inject;

import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.MinimalTokenContent;
import de.cuioss.jwt.validation.domain.token.TokenContent;
import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.quarkus.config.JwtValidationConfig;

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

    @Inject
    Instance<TokenValidator> tokenValidatorInstance;

    @Inject
    JwtValidationConfig config;

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
        status.put("status", "RUNTIME");
        
        if (isEnabled) {
            status.put("statusMessage", "JWT validation is active and ready");
        } else {
            status.put("statusMessage", "JWT validation is disabled");
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

        jwksInfo.put("status", "RUNTIME");
        
        boolean isEnabled = isJwtEnabled();
        if (isEnabled) {
            jwksInfo.put("message", "JWKS endpoints are configured and active");
            jwksInfo.put("issuersConfigured", config.issuers().size());
        } else {
            jwksInfo.put("message", "JWKS endpoints are disabled");
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
            configMap.put("message", "JWT validation is properly configured");
            configMap.put("issuersCount", config.issuers().size());
        } else {
            configMap.put("message", "JWT validation is disabled");
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
            result.put("valid", false);
            result.put("error", "Token is empty or null");
            return result;
        }

        if (!isJwtEnabled()) {
            result.put("valid", false);
            result.put("error", "JWT validation is disabled");
            return result;
        }

        if (!tokenValidatorInstance.isResolvable()) {
            result.put("valid", false);
            result.put("error", "Token validator is not available");
            return result;
        }

        try {
            TokenValidator validator = tokenValidatorInstance.get();
            // Try to create an access token first (most common case)
            TokenContent tokenContent = validator.createAccessToken(token.trim());
            
            result.put("valid", true);
            result.put("tokenType", "ACCESS_TOKEN");
            result.put("claims", tokenContent.getClaims());
            result.put("issuer", tokenContent.getIssuer());
            
        } catch (TokenValidationException e) {
            // Try ID token if access token fails
            try {
                TokenValidator validator = tokenValidatorInstance.get();
                TokenContent tokenContent = validator.createIdToken(token.trim());
                result.put("valid", true);
                result.put("tokenType", "ID_TOKEN");
                result.put("claims", tokenContent.getClaims());
                result.put("issuer", tokenContent.getIssuer());
            } catch (TokenValidationException e2) {
                // Try refresh token if ID token also fails
                try {
                    TokenValidator validator = tokenValidatorInstance.get();
                    MinimalTokenContent tokenContent = validator.createRefreshToken(token.trim());
                    result.put("valid", true);
                    result.put("tokenType", "REFRESH_TOKEN");
                    result.put("rawToken", tokenContent.getRawToken());
                    // Refresh tokens may not have issuer or claims in the same way
                    if (tokenContent instanceof TokenContent) {
                        TokenContent fullTokenContent = (TokenContent) tokenContent;
                        result.put("claims", fullTokenContent.getClaims());
                        result.put("issuer", fullTokenContent.getIssuer());
                    }
                } catch (TokenValidationException e3) {
                    result.put("valid", false);
                    result.put("error", e.getMessage());
                    result.put("details", "Token validation failed for all token types");
                }
            }
        } catch (Exception e) {
            result.put("valid", false);
            result.put("error", "Token validation error: " + e.getMessage());
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
        health.put("overallStatus", "RUNTIME");
        
        if (configValid && validatorAvailable) {
            health.put("message", "All JWT components are healthy and operational");
            health.put("healthStatus", "UP");
        } else if (configValid) {
            health.put("message", "Configuration is valid but validator is not available");
            health.put("healthStatus", "DOWN");
        } else {
            health.put("message", "JWT validation is disabled or misconfigured");
            health.put("healthStatus", "DOWN");
        }

        return health;
    }

    /**
     * Helper method to determine if JWT validation is enabled.
     * JWT is considered enabled if there are any enabled issuers configured.
     *
     * @return true if JWT validation is enabled, false otherwise
     */
    private boolean isJwtEnabled() {
        return config.issuers().values().stream()
                .anyMatch(issuer -> issuer.enabled());
    }
}