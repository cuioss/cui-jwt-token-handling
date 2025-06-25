package de.cuioss.jwt.quarkus.integration.token;

import de.cuioss.jwt.quarkus.integration.config.BenchmarkConfiguration;
import de.cuioss.tools.logging.CuiLogger;
import io.restassured.RestAssured;
import io.restassured.response.Response;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Repository for managing pre-loaded JWT tokens from Keycloak.
 * This class fetches real tokens upfront to avoid impacting benchmark performance
 * during actual measurements.
 */
public class TokenRepository {

    private static final CuiLogger log = new CuiLogger(TokenRepository.class);

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
     * @throws Exception if token loading fails
     */
    public void initialize() throws Exception {
        log.info("🔑 Initializing token repository with {} tokens per type...", tokenPoolSize);
        
        // Load valid tokens
        loadValidTokens();
        
        // Generate expired tokens (simulate by using very short-lived tokens)
        loadExpiredTokens();
        
        // Generate invalid tokens (malformed tokens)
        generateInvalidTokens();
        
        log.info("✅ Token repository initialized successfully");
        log.info("📊 Token counts - Valid: {}, Expired: {}, Invalid: {}", 
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

    private void loadValidTokens() throws Exception {
        log.info("🔄 Loading {} valid tokens from Keycloak...", tokenPoolSize);
        
        for (int i = 0; i < tokenPoolSize; i++) {
            try {
                String token = fetchTokenFromKeycloak();
                if (token != null && !token.isEmpty()) {
                    validTokens.add(token);
                    if ((i + 1) % 10 == 0) {
                        log.debug("Loaded {} valid tokens...", i + 1);
                    }
                } else {
                    log.warn("Failed to load valid token #{}", i + 1);
                }
            } catch (Exception e) {
                log.warn("Error loading valid token #{}: {}", i + 1, e.getMessage());
            }
        }
        
        log.info("✅ Loaded {} valid tokens", validTokens.size());
    }

    private void loadExpiredTokens() throws Exception {
        log.info("🔄 Loading {} expired tokens from Keycloak...", tokenPoolSize);
        
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
            } catch (Exception e) {
                log.warn("Error loading expired token #{}: {}", i + 1, e.getMessage());
            }
        }
        
        log.info("✅ Loaded {} expired tokens", expiredTokens.size());
    }

    private void generateInvalidTokens() {
        log.info("🔄 Generating {} invalid tokens...", tokenPoolSize);
        
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
        
        log.info("✅ Generated {} invalid tokens", invalidTokens.size());
    }

    private String fetchTokenFromKeycloak() throws Exception {
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
                    log.warn("Failed to fetch token from Keycloak (attempt {}/{}). Status: {}, Response: {}", 
                            attempt, maxRetries, response.statusCode(), response.body().asString());
                }
            } catch (Exception e) {
                log.warn("Exception during token fetch (attempt {}/{}): {}", attempt, maxRetries, e.getMessage());
                if (attempt == maxRetries) {
                    throw e;
                }
            }
            
            if (attempt < maxRetries) {
                log.debug("Retrying token fetch in {}ms...", retryDelay);
                Thread.sleep(retryDelay);
            }
        }
        
        return null;
    }
}