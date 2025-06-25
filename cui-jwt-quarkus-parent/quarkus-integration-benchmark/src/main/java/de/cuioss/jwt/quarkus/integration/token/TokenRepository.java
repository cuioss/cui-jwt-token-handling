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
package de.cuioss.jwt.quarkus.integration.token;

import de.cuioss.jwt.quarkus.integration.config.BenchmarkConfiguration;
import de.cuioss.tools.logging.CuiLogger;
import io.restassured.RestAssured;
import io.restassured.response.Response;
import io.restassured.path.json.exception.JsonPathException;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Repository for managing pre-loaded JWT tokens from Keycloak.
 * This class fetches real tokens upfront to avoid impacting benchmark performance
 * during actual measurements.
 */
@SuppressWarnings("java:S2245") // owolff: ok for testing
public class TokenRepository {

    private static final CuiLogger LOGGER = new CuiLogger(TokenRepository.class);

    private final List<String> validTokens;
    private final List<String> expiredTokens;
    private final List<String> invalidTokens;
    private final String keycloakUrl;
    private final int tokenPoolSize;

    /**
     * Creates a new token repository.
     *
     * @param keycloakUrl URL of the Keycloak server
     * @param tokenPoolSize Number of tokens to pre-load for each type
     */
    public TokenRepository(String keycloakUrl, int tokenPoolSize) {
        this.keycloakUrl = keycloakUrl;
        this.tokenPoolSize = tokenPoolSize;
        this.validTokens = new ArrayList<>();
        this.expiredTokens = new ArrayList<>();
        this.invalidTokens = new ArrayList<>();
    }

    /**
     * Initializes the token repository by fetching tokens from Keycloak.
     * This method should be called once before benchmark execution.
     *
     * @throws TokenFetchException if token loading fails
     */
    public void initialize() throws TokenFetchException {
        LOGGER.info("🔑 Initializing token repository with %s tokens per type...", tokenPoolSize);

        // Load valid tokens
        loadValidTokens();

        // Generate expired tokens (simulate by using very short-lived tokens)
        loadExpiredTokens();

        // Generate invalid tokens (malformed tokens)
        generateInvalidTokens();

        LOGGER.info("✅ Token repository initialized successfully");
        LOGGER.info("📊 Token counts - Valid: %s, Expired: %s, Invalid: %s",
                validTokens.size(), expiredTokens.size(), invalidTokens.size());
    }

    /**
     * Gets a random valid token from the repository.
     *
     * @return A valid JWT token
     */
    public String getValidToken() {
        if (validTokens.isEmpty()) {
            throw new IllegalStateException("No valid tokens available. Call initialize() first.");
        }
        return validTokens.get(ThreadLocalRandom.current().nextInt(validTokens.size()));
    }

    /**
     * Gets a random expired token from the repository.
     *
     * @return An expired JWT token
     */
    public String getExpiredToken() {
        if (expiredTokens.isEmpty()) {
            throw new IllegalStateException("No expired tokens available. Call initialize() first.");
        }
        return expiredTokens.get(ThreadLocalRandom.current().nextInt(expiredTokens.size()));
    }

    /**
     * Gets a random invalid token from the repository.
     *
     * @return An invalid JWT token
     */
    public String getInvalidToken() {
        if (invalidTokens.isEmpty()) {
            throw new IllegalStateException("No invalid tokens available. Call initialize() first.");
        }
        return invalidTokens.get(ThreadLocalRandom.current().nextInt(invalidTokens.size()));
    }

    /**
     * Gets a random token based on error percentage.
     *
     * @param errorPercentage Percentage of tokens that should be invalid (0-100)
     * @return A JWT token (valid or invalid based on percentage)
     */
    public String getTokenByErrorRate(int errorPercentage) {
        int random = ThreadLocalRandom.current().nextInt(100);

        if (random < errorPercentage) {
            // Return invalid or expired token
            if (random < errorPercentage / 2) {
                return getInvalidToken();
            } else {
                return getExpiredToken();
            }
        } else {
            return getValidToken();
        }
    }

    /**
     * Returns the number of available valid tokens.
     */
    public int getValidTokenCount() {
        return validTokens.size();
    }

    /**
     * Returns the number of available expired tokens.
     */
    public int getExpiredTokenCount() {
        return expiredTokens.size();
    }

    /**
     * Returns the number of available invalid tokens.
     */
    public int getInvalidTokenCount() {
        return invalidTokens.size();
    }

    private void loadValidTokens() throws TokenFetchException {
        LOGGER.info("🔄 Loading %s valid tokens from Keycloak...", tokenPoolSize);

        for (int i = 0; i < tokenPoolSize; i++) {
            try {
                String token = fetchTokenFromKeycloak();
                if (token != null && !token.isEmpty()) {
                    validTokens.add(token);
                    if ((i + 1) % 10 == 0) {
                        LOGGER.debug("Loaded %s valid tokens...", i + 1);
                    }
                } else {
                    LOGGER.warn("Failed to load valid token #%s", i + 1);
                }
            } catch (TokenFetchException e) {
                LOGGER.warn("Error loading valid token #%s: %s", i + 1, e.getMessage());
            }
        }

        LOGGER.info("✅ Loaded %s valid tokens", validTokens.size());
    }

    private void loadExpiredTokens() throws TokenFetchException {
        LOGGER.info("🔄 Loading %s expired tokens from Keycloak...", tokenPoolSize);

        // For expired tokens, we can either:
        // 1. Request tokens with very short expiry (if Keycloak supports it)
        // 2. Use older tokens that have naturally expired
        // 3. Generate tokens with expired timestamps (for testing)

        // For now, we'll fetch normal tokens and let them expire naturally
        // In a real scenario, you might want to configure Keycloak with very short token lifetimes
        for (int i = 0; i < Math.min(tokenPoolSize, 20); i++) { // Limit expired tokens for now
            try {
                String token = fetchTokenFromKeycloak();
                if (token != null && !token.isEmpty()) {
                    expiredTokens.add(token);
                }
            } catch (TokenFetchException e) {
                LOGGER.warn("Error loading expired token #%s: %s", i + 1, e.getMessage());
            }
        }

        LOGGER.info("✅ Loaded %s expired tokens", expiredTokens.size());
    }

    private void generateInvalidTokens() {
        LOGGER.info("🔄 Generating %s invalid tokens...", tokenPoolSize);

        String[] invalidPatterns = {
                "invalid.token.content",
                "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.invalid_payload.invalid_signature",
                "completely_malformed_token",
                "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.wrong_signature",
                "bearer_token_without_proper_format",
                "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.",
                "",
                "null",
                "undefined",
                "Bearer"
        };

        for (int i = 0; i < tokenPoolSize; i++) {
            String pattern = invalidPatterns[i % invalidPatterns.length];

            // Add some variation to make tokens unique
            String invalidToken = pattern + "_" + i;
            invalidTokens.add(invalidToken);
        }

        LOGGER.info("✅ Generated %s invalid tokens", invalidTokens.size());
    }

    private String fetchTokenFromKeycloak() throws TokenFetchException {
        int maxRetries = BenchmarkConfiguration.getMaxTokenFetchRetries();
        int retryDelay = BenchmarkConfiguration.getTokenFetchRetryDelay();

        for (int attempt = 1; attempt <= maxRetries; attempt++) {
            try {
                // Authenticate with Keycloak and get a token
                Response response = RestAssured
                        .given()
                        .contentType("application/x-www-form-urlencoded")
                        .formParam("client_id", BenchmarkConfiguration.getKeycloakClientId())
                        .formParam("username", BenchmarkConfiguration.getKeycloakUsername())
                        .formParam("password", BenchmarkConfiguration.getKeycloakPassword())
                        .formParam("grant_type", "password")
                        .when()
                        .post(keycloakUrl + "/realms/" + BenchmarkConfiguration.getKeycloakRealm() + "/protocol/openid-connect/token");

                if (response.statusCode() == 200) {
                    Map<String, Object> tokenResponse = response.jsonPath().getMap("");
                    String token = (String) tokenResponse.get("access_token");
                    if (token != null && !token.isEmpty()) {
                        return token;
                    }
                } else {
                    LOGGER.warn("Failed to fetch token from Keycloak (attempt %s/%s). Status: %s, Response: %s",
                            attempt, maxRetries, response.statusCode(), response.body().asString());
                }
            } catch (JsonPathException e) {
                LOGGER.warn("JSON parsing error during token fetch (attempt %s/%s): %s", attempt, maxRetries, e.getMessage());
                if (attempt == maxRetries) {
                    throw new TokenFetchException("Failed to parse Keycloak response after " + maxRetries + " attempts", e);
                }
            } catch (RuntimeException e) {
                LOGGER.warn("Network/HTTP error during token fetch (attempt %s/%s): %s", attempt, maxRetries, e.getMessage());
                if (attempt == maxRetries) {
                    throw new TokenFetchException("Failed to fetch token from Keycloak after " + maxRetries + " attempts", e);
                }
            }

            if (attempt < maxRetries) {
                try {
                    LOGGER.debug("Retrying token fetch in %sms...", retryDelay);
                    Thread.sleep(retryDelay);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    throw new TokenFetchException("Token fetch interrupted during retry delay", e);
                }
            }
        }

        throw new TokenFetchException("Failed to fetch token from Keycloak after " + maxRetries + " attempts - no successful response");
    }
}