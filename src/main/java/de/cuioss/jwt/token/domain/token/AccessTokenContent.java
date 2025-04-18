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
package de.cuioss.jwt.token.domain.token;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import lombok.EqualsAndHashCode;
import lombok.ToString;
import lombok.experimental.SuperBuilder;

import java.io.Serial;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Represents the content of an OAuth 2.0 access token.
 * Provides access to access token specific claims like scopes.
 */
@ToString(callSuper = true)
@EqualsAndHashCode(callSuper = true)
@SuperBuilder
public class AccessTokenContent extends BaseTokenContent {

    @Serial
    private static final long serialVersionUID = 1L;

    private final String email;

    /**
     * Constructs a new AccessTokenContent with the given claims, raw token, and email.
     *
     * @param claims   the token claims
     * @param rawToken the raw token string
     * @param email    the user's email address
     */
    public AccessTokenContent(Map<String, ClaimValue> claims, String rawToken, String email) {
        super(claims, rawToken, TokenType.ACCESS_TOKEN);
        this.email = email;
    }

    /**
     * Gets the audience claim value.
     * <p>
     * 'aud' is optional for {@link TokenType#ACCESS_TOKEN}.
     *
     * @return the audience as a list of strings, or throws exception if it's not present
     * @throws IllegalStateException if the audience claim is not present
     */
    public Optional<List<String>> getAudience() {
        return getClaimOption(ClaimName.AUDIENCE)
                .map(ClaimValue::getAsList);
    }

    /**
     * Gets the scopes from the token claims.
     *
     * @return a List of scope strings
     * @throws IllegalStateException if the scope claim is not present in the token
     */
    public List<String> getScopes() {
        return getClaimOption(ClaimName.SCOPE)
                .map(ClaimValue::getAsList)
                .orElseThrow(() -> new IllegalStateException("Scope claim not present in token"));
    }

    /**
     * Gets the email address associated with this token.
     * If not provided in the constructor, tries to extract from the claims.
     *
     * @return an Optional containing the email if present, or empty otherwise
     */
    public Optional<String> getEmail() {
        if (email != null) {
            return Optional.of(email);
        }
        return getClaimOption(ClaimName.EMAIL).map(ClaimValue::getOriginalString);
    }

    /**
     * Gets the preferred username from the token claims.
     *
     * @return an Optional containing the preferred username if present, or empty otherwise
     */
    public Optional<String> getPreferredUsername() {
        return getClaimOption(ClaimName.PREFERRED_USERNAME).map(ClaimValue::getOriginalString);
    }
}
