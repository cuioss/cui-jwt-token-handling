/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.test.generator;

import de.cuioss.jwt.token.test.KeyMaterialHandler;
import de.cuioss.jwt.token.test.TestTokenProducer;
import de.cuioss.test.generator.Generators;
import de.cuioss.test.generator.TypedGenerator;
import de.cuioss.test.generator.domain.EmailGenerator;
import io.jsonwebtoken.JwtBuilder;
import io.jsonwebtoken.Jwts;

import java.time.Instant;
import java.util.Date;
import java.util.Set;

/**
 * Generator for OAuth/OIDC access tokens.
 * Generates a JWT access token string.
 * Can be configured in "default" or "alternative" mode for signing.
 */
public class AccessTokenGenerator implements TypedGenerator<String> {

    private static final String DEFAULT_KEY_ID = "default-key-id";
    private static final String ALTERNATIVE_KEY_ID = "test-key-id";
    public static final String DEFAULT_CLIENT_ID = "test-client";
    public static final String ALTERNATIVE_CLIENT_ID = "alternative-client";

    private final boolean useAlternativeMode;
    private final ScopeGenerator scopeGenerator;
    private final RoleGenerator roleGenerator;
    private final EmailGenerator emailGenerator;
    private final String clientId;

    /**
     * Constructor with default mode (false = default mode, true = alternative mode).
     *
     * @param useAlternativeMode whether to use alternative mode for signing
     */
    public AccessTokenGenerator(boolean useAlternativeMode) {
        this(useAlternativeMode, useAlternativeMode ? ALTERNATIVE_CLIENT_ID : DEFAULT_CLIENT_ID);
    }

    /**
     * Constructor with default mode and specific client ID.
     *
     * @param useAlternativeMode whether to use alternative mode for signing
     * @param clientId           the client ID to include in the azp claim
     */
    public AccessTokenGenerator(boolean useAlternativeMode, String clientId) {
        this.useAlternativeMode = useAlternativeMode;
        this.scopeGenerator = new ScopeGenerator();
        this.roleGenerator = new RoleGenerator();
        this.emailGenerator = new EmailGenerator();
        this.clientId = clientId;
    }

    @Override
    public String next() {
        try {
            String subject = Generators.letterStrings(5, 10).next();
            String email = emailGenerator.next();
            String scope = scopeGenerator.next();
            Set<String> roles = roleGenerator.next();

            JwtBuilder builder = Jwts.builder().issuer(TestTokenProducer.ISSUER).subject(subject).issuedAt(Date.from(Instant.now())).expiration(Date.from(Instant.now().plusSeconds(3600))) // 1 hour
                    .claim("email", email)
                    .claim("scope", scope)
                    .claim("roles", roles)
                    .claim("typ", "Bearer")
                    .header().add("kid", useAlternativeMode ? ALTERNATIVE_KEY_ID : DEFAULT_KEY_ID).and();

            // Only add the azp claim if clientId is not null (for testing missing azp claim)
            if (clientId != null) {
                builder.claim("azp", clientId);
                // Add audience as a direct claim
                builder.claim("aud", clientId);
            }

            // Sign with default private key (we don't have an alternative private key)
            // The "alternative" mode is indicated by the key ID in the header
            builder.signWith(KeyMaterialHandler.getDefaultPrivateKey());

            return builder.compact();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate access token", e);
        }
    }
}
