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

import de.cuioss.jwt.token.adapter.Claims;
import de.cuioss.jwt.token.adapter.JsonWebToken;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;

import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneId;
import java.util.Optional;

/**
 * Abstract base class for parsed JWT token representations.
 * Provides common functionality for working with {@link JsonWebToken} instances
 * including token validation, expiration checking, and type determination.
 * <p>
 * Key features:
 * <ul>
 *   <li>Token parsing and validation</li>
 *   <li>Expiration time management</li>
 *   <li>Token type determination via "typ" claim</li>
 *   <li>Access to raw token string and JWT claims</li>
 * </ul>
 * <p>
 * Concrete implementations are available for specific token types:
 * <ul>
 *   <li>{@link ParsedAccessToken}: For OAuth2 access tokens</li>
 *   <li>{@link ParsedIdToken}: For OpenID Connect ID tokens</li>
 *   <li>{@link ParsedRefreshToken}: For OAuth2 refresh tokens</li>
 * </ul>
 * <p>
 * Note: The implementation is primarily tested with Keycloak tokens.
 * Some features may be specific to Keycloak's token format.
 * <p>
 * Implements requirement: {@code CUI-JWT-1.2: Token Types}
 * <p>
 * For more details on the requirements, see the
 * <a href="../../../../../../doc/specification/technical-components.adoc">Technical Components Specification</a>.
 *
 * @author Oliver Wolff
 */
@RequiredArgsConstructor
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
public abstract class ParsedToken {

    /**
     * @return the token as encoded String.
     */
    public String getTokenString() {
        return jsonWebToken.getRawToken();
    }

    @Getter
    @EqualsAndHashCode.Include
    protected final JsonWebToken jsonWebToken;

    /**
     * @return boolean indicating whether the token is already expired. Shorthand for
     * {@link #willExpireInSeconds(int)}
     * with '0'.
     */
    public boolean isExpired() {
        return willExpireInSeconds(0);
    }

    /**
     * @param seconds maybe {@code 0}. Calling it with a negative number is not defined.
     * @return boolean indicating whether the token will expired within the given number of seconds.
     */
    public boolean willExpireInSeconds(int seconds) {
        return getExpirationTime().isBefore(OffsetDateTime.now().plusSeconds(seconds));
    }

    /**
     * Extracts the {@link TokenType} from the claim "type."
     * <em>Caution:</em> This is only tested for keycloak.
     * The claim 'typ' is not from the oauth spec.
     */
    public TokenType getType() {
        return TokenType.fromTypClaim(jsonWebToken.getClaim("typ"));
    }

    /**
     * @return {@link OffsetDateTime} representation of the expiration-Time
     */
    public OffsetDateTime getExpirationTime() {
        return OffsetDateTime
                .ofInstant(Instant.ofEpochSecond(jsonWebToken.getExpirationTime()), ZoneId.systemDefault());
    }

    /**
     * @return the subject from the underlying JWT token
     */
    public String getSubject() {
        return jsonWebToken.getSubject();
    }

    /**
     * @return the issuer from the underlying JWT token
     */
    public String getIssuer() {
        return jsonWebToken.getIssuer();
    }

    /**
     * Returns the "Not Before" time from the token if present.
     * The "nbf" (not before) claim identifies the time before which the JWT must not be accepted for processing.
     * This claim is optional, according to the JWT specification (RFC 7519).
     *
     * @return an {@link Optional} containing the {@link OffsetDateTime} representation of the "Not Before" time
     * if the claim is present, or an empty Optional if not
     */
    public Optional<OffsetDateTime> getNotBeforeTime() {
        Optional<Object> notBeforeTime = jsonWebToken.claim(Claims.NOT_BEFORE);
        return notBeforeTime.map(value -> {
            long epochSecond;
            if (value instanceof Long longValue) {
                epochSecond = longValue;
            } else if (value instanceof Integer integerValue) {
                epochSecond = integerValue.longValue();
            } else if (value instanceof Number number) {
                epochSecond = number.longValue();
            } else {
                throw new IllegalArgumentException("Unexpected type for nbf claim: " + value.getClass().getName());
            }
            return OffsetDateTime.ofInstant(Instant.ofEpochSecond(epochSecond), ZoneId.systemDefault());
        });
    }

    /**
     * Returns the "Issued At" time from the token.
     * The "iat" (issued at) claim identifies the time at which the JWT was issued.
     *
     * @return the {@link OffsetDateTime} representation of the "Issued At" time
     */
    public OffsetDateTime getIssuedAtTime() {
        return OffsetDateTime
                .ofInstant(Instant.ofEpochSecond(jsonWebToken.getIssuedAtTime()), ZoneId.systemDefault());
    }

    /**
     * Returns the JWT ID from the token.
     * The "jti" (JWT ID) claim provides a unique identifier for the JWT.
     *
     * @return the JWT ID string
     */
    public String getTokenId() {
        return jsonWebToken.getTokenID();
    }
}
