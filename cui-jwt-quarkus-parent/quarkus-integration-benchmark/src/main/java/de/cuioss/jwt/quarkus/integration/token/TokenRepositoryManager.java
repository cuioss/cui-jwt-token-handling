package de.cuioss.jwt.quarkus.integration.token;

import de.cuioss.jwt.quarkus.integration.config.BenchmarkConfiguration;
import de.cuioss.tools.logging.CuiLogger;

/**
 * Singleton manager for the token repository.
 * Ensures that tokens are loaded once and shared across all benchmark classes
 * to avoid impacting performance measurements.
 */
public class TokenRepositoryManager {

    private static final CuiLogger log = new CuiLogger(TokenRepositoryManager.class);
    
    private static volatile TokenRepositoryManager instance;
    private static final Object lock = new Object();
    
    private TokenRepository tokenRepository;
    private boolean initialized = false;

    private TokenRepositoryManager() {
        // Private constructor for singleton
    }

    /**
     * Gets the singleton instance of the token repository manager.
     *
     * @return The token repository manager instance
     */
    public static TokenRepositoryManager getInstance() {
        if (instance == null) {
            synchronized (lock) {
                if (instance == null) {
                    instance = new TokenRepositoryManager();
                }
            }
        }
        return instance;
    }

    /**
     * Initializes the token repository if not already initialized.
     * This method is thread-safe and will only initialize once.
     *
     * @throws Exception if initialization fails
     */
    public void initialize() throws Exception {
        if (!initialized) {
            synchronized (lock) {
                if (!initialized) {
                    log.info("🚀 Initializing token repository manager...");
                    BenchmarkConfiguration.logConfiguration();
                    
                    String keycloakUrl = BenchmarkConfiguration.getKeycloakUrl();
                    int tokenPoolSize = BenchmarkConfiguration.getTokenPoolSize();
                    
                    tokenRepository = new TokenRepository(keycloakUrl, tokenPoolSize);
                    tokenRepository.initialize();
                    
                    initialized = true;
                    log.info("✅ Token repository manager initialized successfully");
                }
            }
        } else {
            log.debug("Token repository already initialized, skipping...");
        }
    }

    /**
     * Gets the token repository instance.
     * Throws an exception if not initialized.
     *
     * @return The token repository
     * @throws IllegalStateException if not initialized
     */
    public TokenRepository getTokenRepository() {
        if (!initialized || tokenRepository == null) {
            throw new IllegalStateException("Token repository not initialized. Call initialize() first.");
        }
        return tokenRepository;
    }

    /**
     * Checks if the token repository is initialized.
     *
     * @return true if initialized, false otherwise
     */
    public boolean isInitialized() {
        return initialized;
    }

    /**
     * Gets a random valid token.
     *
     * @return A valid JWT token
     */
    public String getValidToken() {
        return getTokenRepository().getValidToken();
    }

    /**
     * Gets a random expired token.
     *
     * @return An expired JWT token
     */
    public String getExpiredToken() {
        return getTokenRepository().getExpiredToken();
    }

    /**
     * Gets a random invalid token.
     *
     * @return An invalid JWT token
     */
    public String getInvalidToken() {
        return getTokenRepository().getInvalidToken();
    }

    /**
     * Gets a token based on error percentage.
     *
     * @param errorPercentage Percentage of tokens that should be invalid (0-100)
     * @return A JWT token (valid or invalid based on percentage)
     */
    public String getTokenByErrorRate(int errorPercentage) {
        return getTokenRepository().getTokenByErrorRate(errorPercentage);
    }

    /**
     * Gets repository statistics.
     *
     * @return A string with token count statistics
     */
    public String getStatistics() {
        if (!initialized) {
            return "Token repository not initialized";
        }
        
        return String.format("Token Repository Stats - Valid: %d, Expired: %d, Invalid: %d",
                tokenRepository.getValidTokenCount(),
                tokenRepository.getExpiredTokenCount(),
                tokenRepository.getInvalidTokenCount());
    }

    /**
     * Resets the token repository manager (for testing purposes).
     * This method should not be used in production.
     */
    protected static void reset() {
        synchronized (lock) {
            instance = null;
        }
    }
}