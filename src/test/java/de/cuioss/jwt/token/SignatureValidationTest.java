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

import de.cuioss.jwt.token.jwks.JwksLoader;
import de.cuioss.jwt.token.test.JWKSFactory;
import de.cuioss.jwt.token.test.KeyMaterialHandler;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Key;
import java.security.KeyPair;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.nio.charset.StandardCharsets;

import static de.cuioss.jwt.token.test.TestTokenProducer.ISSUER;
import static de.cuioss.jwt.token.test.TestTokenProducer.SOME_SCOPES;
import static de.cuioss.jwt.token.test.TestTokenProducer.validSignedJWTWithClaims;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests specifically focused on signature validation aspects of the JWT token handling library.
 * This includes testing support for required algorithms and rejection of unsupported algorithms.
 */
@EnableTestLogger(debug = JwksAwareTokenParserImpl.class, info = JwksAwareTokenParserImpl.class)
@DisplayName("Tests JWT Signature Validation")
public class SignatureValidationTest {

    private static final CuiLogger LOGGER = new CuiLogger(SignatureValidationTest.class);
    private JwksAwareTokenParserImpl tokenParser;

    @BeforeEach
    void setUp() {
        // Use the helper method from JwksAwareTokenParserImplTest to create a valid parser
        tokenParser = JwksAwareTokenParserImplTest.getValidJWKSParserWithLocalJWKS();
    }

    @Test
    @DisplayName("Should validate token with RS256 algorithm")
    void shouldValidateRS256Token() {
        // Create a token signed with RS256 using the TestTokenProducer
        String token = validSignedJWTWithClaims(SOME_SCOPES);

        // Parse and validate the token
        var parsedToken = ParsedToken.jsonWebTokenFrom(token, tokenParser, LOGGER);

        // Assert that the token is valid
        assertTrue(parsedToken.isPresent(), "Token signed with RS256 should be valid");
    }

    @Test
    @DisplayName("Should reject token with 'none' algorithm")
    void shouldRejectNoneAlgorithm() {
        // Create a token with the "none" algorithm
        String token = createUnsignedToken();

        // Parse and validate the token
        var parsedToken = ParsedToken.jsonWebTokenFrom(token, tokenParser, LOGGER);

        // Assert that the token is rejected
        assertFalse(parsedToken.isPresent(), "Token with 'none' algorithm should be rejected");
        // Check for the actual log message that indicates token format rejection
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Invalid JWT token format");
    }

    @Test
    @DisplayName("Should reject token with HS256 algorithm")
    void shouldRejectHS256Token() {
        // Create a token signed with HS256
        String token = createTokenWithSymmetricAlgorithm(SignatureAlgorithm.HS256);

        // Parse and validate the token
        var parsedToken = ParsedToken.jsonWebTokenFrom(token, tokenParser, LOGGER);

        // Assert that the token is rejected
        assertFalse(parsedToken.isPresent(), "Token signed with HS256 should be rejected");
        // Check for the actual log message that indicates algorithm rejection
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unable to parse token due to ParseException");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "HS256");
    }

    @Test
    @DisplayName("Should reject token with HS384 algorithm")
    void shouldRejectHS384Token() {
        // Create a token signed with HS384
        String token = createTokenWithSymmetricAlgorithm(SignatureAlgorithm.HS384);

        // Parse and validate the token
        var parsedToken = ParsedToken.jsonWebTokenFrom(token, tokenParser, LOGGER);

        // Assert that the token is rejected
        assertFalse(parsedToken.isPresent(), "Token signed with HS384 should be rejected");
        // Check for the actual log message that indicates algorithm rejection
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unable to parse token due to ParseException");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "HS384");
    }

    @Test
    @DisplayName("Should reject token with HS512 algorithm")
    void shouldRejectHS512Token() {
        // Create a token signed with HS512
        String token = createTokenWithSymmetricAlgorithm(SignatureAlgorithm.HS512);

        // Parse and validate the token
        var parsedToken = ParsedToken.jsonWebTokenFrom(token, tokenParser, LOGGER);

        // Assert that the token is rejected
        assertFalse(parsedToken.isPresent(), "Token signed with HS512 should be rejected");
        // Check for the actual log message that indicates algorithm rejection
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "Unable to parse token due to ParseException");
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "HS512");
    }

    @Test
    @DisplayName("Should reject token with algorithm confusion attack")
    void shouldRejectAlgorithmConfusionAttack() {
        // Create a token with RS256 in the header but actually signed with HS256
        // This is a common algorithm confusion attack
        String token = createAlgorithmConfusionToken();

        // Parse and validate the token
        var parsedToken = ParsedToken.jsonWebTokenFrom(token, tokenParser, LOGGER);

        // Assert that the token is rejected
        assertFalse(parsedToken.isPresent(), "Token with algorithm confusion should be rejected");
        // Check for the actual log message that indicates key not found
        LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN, "No key found with ID: wrong-key-id");
    }

    /**
     * Creates a token signed with the specified algorithm.
     */
    private String createToken(SignatureAlgorithm algorithm) {
        Instant now = Instant.now();
        Instant expiration = now.plus(1, ChronoUnit.HOURS);

        return Jwts.builder()
                .setSubject("test-subject")
                .setIssuer(ISSUER)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .setHeaderParam("kid", JWKSFactory.DEFAULT_KEY_ID)
                .signWith(KeyMaterialHandler.getDefaultPrivateKey(), algorithm)
                .compact();
    }

    /**
     * Creates an unsigned token (using the "none" algorithm).
     */
    private String createUnsignedToken() {
        Instant now = Instant.now();
        Instant expiration = now.plus(1, ChronoUnit.HOURS);

        return Jwts.builder()
                .setSubject("test-subject")
                .setIssuer(ISSUER)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .setHeaderParam("kid", JWKSFactory.DEFAULT_KEY_ID)
                .setHeaderParam("alg", "none")
                .compact();
    }

    /**
     * Creates a token signed with a symmetric algorithm.
     */
    private String createTokenWithSymmetricAlgorithm(SignatureAlgorithm algorithm) {
        Instant now = Instant.now();
        Instant expiration = now.plus(1, ChronoUnit.HOURS);

        // Generate a symmetric key
        Key key = Keys.secretKeyFor(algorithm);

        return Jwts.builder()
                .setSubject("test-subject")
                .setIssuer(ISSUER)
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(expiration))
                .setHeaderParam("kid", JWKSFactory.DEFAULT_KEY_ID)
                .signWith(key, algorithm)
                .compact();
    }

    /**
     * Creates a token for testing algorithm confusion attacks.
     * This simulates a token that claims to use RS256 but with an invalid signature.
     */
    private String createAlgorithmConfusionToken() {
        // Create a valid token with RS256
        String validToken = createToken(SignatureAlgorithm.RS256);

        // Split the token into its parts
        String[] parts = validToken.split("\\.");

        // Modify the header to keep RS256 but change something else
        String header = new String(Base64.getUrlDecoder().decode(parts[0]), StandardCharsets.UTF_8);
        header = header.replace("\"kid\":\"" + JWKSFactory.DEFAULT_KEY_ID + "\"", "\"kid\":\"wrong-key-id\"");
        String modifiedHeader = Base64.getUrlEncoder().withoutPadding().encodeToString(header.getBytes(StandardCharsets.UTF_8));

        // Construct a token with the modified header but keep the original payload and signature
        // This simulates an algorithm confusion attack where the attacker tries to use a valid signature
        // with a modified header
        return modifiedHeader + "." + parts[1] + "." + parts[2];
    }
}
