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
package de.cuioss.jwt.token;

import de.cuioss.jwt.token.adapter.JsonWebToken;
import de.cuioss.jwt.token.adapter.JwtAdapter;
import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.JwtParser;
import io.jsonwebtoken.Jwts;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.io.StringReader;
import java.security.Key;
import java.util.Base64;
import java.util.Optional;

import static de.cuioss.jwt.token.PortalTokenLogMessages.INFO;
import static de.cuioss.jwt.token.PortalTokenLogMessages.WARN;

/**
 * JWT parser implementation with support for remote JWKS (JSON Web Key Set) loading.
 * This parser extends the standard JJWT functionality by adding the ability
 * to fetch and manage public keys from a JWKS endpoint for token signature verification.
 * <p>
 * Key features:
 * <ul>
 *   <li>Remote JWKS endpoint configuration</li>
 *   <li>Automatic key refresh support</li>
 *   <li>TLS certificate configuration for secure key loading</li>
 *   <li>Issuer-based token validation</li>
 * </ul>
 * <p>
 * The parser can be configured using the constructor:
 * <pre>
 * JwksLoader jwksLoader = JwksClientFactory.createHttpLoader(
 *     "https://auth.example.com/.well-known/jwks.json", 
 *     60, 
 *     null);
 * JwksAwareTokenParserImpl parser = new JwksAwareTokenParserImpl(
 *     jwksLoader, 
 *     "https://auth.example.com");
 * </pre>
 * <p>
 * This implementation is thread-safe and handles automatic key rotation
 * based on the configured refresh interval.
 * <p>
 * See specification: {@code doc/specification/technical-components.adoc#_jwtparser}
 * <p>
 * Implements requirement: {@code CUI-JWT-1.3: Signature Validation}
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class JwksAwareTokenParserImpl implements de.cuioss.jwt.token.JwtParser {

    private static final CuiLogger LOGGER = new CuiLogger(JwksAwareTokenParserImpl.class);
    public static final int DEFAULT_REFRESH_INTERVAL = 180;

    private final JwtParser jwtParser;
    private final JwksLoader jwksLoader;

    @Getter
    private final String issuer;

    /**
     * Constructor for JwksAwareTokenParserImpl.
     * 
     * @param jwtParser the JWT parser
     * @param jwksLoader the JWKS loader
     * @param issuer the issuer
     */
    JwksAwareTokenParserImpl(JwtParser jwtParser, JwksLoader jwksLoader, String issuer) {
        this.jwtParser = jwtParser;
        this.jwksLoader = jwksLoader;
        this.issuer = issuer;
    }

    /**
     * Constructor for JwksAwareTokenParserImpl.
     * 
     * @param jwksLoader the JWKS loader, must not be null
     * @param issuer the issuer, must not be null
     */
    public JwksAwareTokenParserImpl(@NonNull JwksLoader jwksLoader, @NonNull String issuer) {
        this.jwksLoader = jwksLoader;
        this.issuer = issuer;
        this.jwtParser = Jwts.parserBuilder()
                .setAllowedClockSkewSeconds(30)
                .requireIssuer(issuer)
                .build();

        // Log the initialization
        LOGGER.info(INFO.CONFIGURED_JWKS.format(
                jwksLoader.toString(),
                DEFAULT_REFRESH_INTERVAL,
                issuer));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<Jws<Claims>> parseToken(String token) throws JwtException {
        LOGGER.debug("Parsing token");
        if (token == null || token.isBlank()) {
            LOGGER.warn(WARN.TOKEN_IS_EMPTY::format);
            return Optional.empty();
        }

        try {
            // Extract the key ID from the token header
            // Split the token into parts
            String[] parts = token.split("\\.");
            if (parts.length != 3) {
                LOGGER.warn("Invalid JWT format: expected 3 parts but got %s", parts.length);
                return Optional.empty();
            }

            // Decode the header
            String headerJson = new String(Base64.getUrlDecoder().decode(parts[0]));
            JsonObject header;
            try (JsonReader reader = Json.createReader(new StringReader(headerJson))) {
                header = reader.readObject();
            }

            // Get the key ID if present
            String kid = null;
            if (header.containsKey("kid")) {
                kid = header.getString("kid");
            }

            Optional<Key> key;
            if (kid != null) {
                // Get the key from the JWKS loader using the key ID
                key = jwksLoader.getKey(kid);
                if (key.isEmpty()) {
                    LOGGER.warn(WARN.KEY_NOT_FOUND.format(kid));
                    return Optional.empty();
                }
            } else {
                // If no key ID is present, try all available keys
                LOGGER.debug("No key ID found in token header, trying all available keys");
                key = jwksLoader.getFirstKey();
                if (key.isEmpty()) {
                    LOGGER.warn("No keys available in JWKS");
                    return Optional.empty();
                }
            }

            // Create a new JwtParser with the signing key and parse the token
            LOGGER.debug("Using key with algorithm: %s", key.get().getAlgorithm());
            try {
                Jws<Claims> jws = Jwts.parserBuilder()
                        .setSigningKey(key.get())
                        .build()
                        .parseClaimsJws(token);

                // Verify the issuer
                String tokenIssuer = jws.getBody().getIssuer();
                if (!issuer.equals(tokenIssuer)) {
                    LOGGER.warn(WARN.ISSUER_MISMATCH.format(tokenIssuer, issuer));
                    return Optional.empty();
                }

                return Optional.of(jws);
            } catch (JwtException e) {
                LOGGER.warn(e, WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
                LOGGER.trace("Offending token '%s'", token);
                return Optional.empty();
            }
        } catch (JwtException e) {
            LOGGER.warn(e, WARN.COULD_NOT_PARSE_TOKEN.format(e.getMessage()));
            LOGGER.trace("Offending token '%s'", token);
            return Optional.empty();
        } catch (Exception e) {
            LOGGER.warn(e, "Error parsing token: %s", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public Optional<JsonWebToken> parse(String token) throws JwtException {
        LOGGER.debug("Parsing token to JsonWebToken");
        return parseToken(token).map(jws -> new JwtAdapter(jws, token));
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean supportsIssuer(String issuer) {
        return this.issuer.equals(issuer);
    }


}
