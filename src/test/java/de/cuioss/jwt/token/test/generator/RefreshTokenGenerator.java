package de.cuioss.jwt.token.test.generator;

import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.Generators;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.jwt.token.test.KeyMaterialHandler;

import java.time.Instant;

import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

/**
 * Generator for OAuth/OIDC refresh tokens.
 * Generates a JWT refresh token string.
 * Can be configured in "default" or "alternative" mode for signing.
 */
public class RefreshTokenGenerator implements TypedGenerator<String> {

    private static final String DEFAULT_KEY_ID = "default-key-id";
    private static final String ALTERNATIVE_KEY_ID = "test-key-id";

    private final boolean useAlternativeMode;
    private final ScopeGenerator scopeGenerator;

    /**
     * Constructor with default mode (false = default mode, true = alternative mode).
     *
     * @param useAlternativeMode whether to use alternative mode for signing
     */
    public RefreshTokenGenerator(boolean useAlternativeMode) {
        this.useAlternativeMode = useAlternativeMode;
        this.scopeGenerator = new ScopeGenerator();
    }

    /**
     * Constructor with default mode (false).
     */
    public RefreshTokenGenerator() {
        this(false);
    }

    @Override
    public String next() {
        try {
            String subject = Generators.letterStrings(5, 10).next();
            String scope = scopeGenerator.next();

            JwtBuilder builder = Jwts.builder()
                    .setIssuer(TestTokenProducer.ISSUER)
                    .setSubject(subject)
                    .setIssuedAt(java.util.Date.from(Instant.now()))
                    .setExpiration(java.util.Date.from(Instant.now().plusSeconds(86400))) // 24 hours
                    .claim("scope", scope)
                    .claim("typ", "Refresh")
                    .setHeaderParam("kid", useAlternativeMode ? ALTERNATIVE_KEY_ID : DEFAULT_KEY_ID);

            // Sign with default private key (we don't have an alternative private key)
            // The "alternative" mode is indicated by the key ID in the header
            builder.signWith(KeyMaterialHandler.getDefaultPrivateKey(), SignatureAlgorithm.RS256);

            return builder.compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate refresh token", e);
        }
    }
}