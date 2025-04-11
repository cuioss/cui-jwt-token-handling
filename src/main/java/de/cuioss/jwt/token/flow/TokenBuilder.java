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
package de.cuioss.jwt.token.flow;

import de.cuioss.jwt.token.domain.claim.ClaimName;
import de.cuioss.jwt.token.domain.claim.ClaimValue;
import de.cuioss.jwt.token.domain.claim.mapper.IdentityMapper;
import de.cuioss.jwt.token.domain.token.AccessTokenContent;
import de.cuioss.jwt.token.domain.token.IdTokenContent;
import de.cuioss.jwt.token.domain.token.RefreshTokenContent;
import jakarta.json.JsonObject;
import lombok.NonNull;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Builder for creating token content objects from decoded JWT tokens.
 */
public class TokenBuilder {

    /**
     * Creates an AccessTokenContent from a decoded JWT.
     *
     * @param decodedJwt the decoded JWT
     * @return an Optional containing the AccessTokenContent if it could be created, empty otherwise
     */
    public Optional<AccessTokenContent> createAccessToken(@NonNull DecodedJwt decodedJwt) {
        Optional<JsonObject> bodyOption = decodedJwt.getBody();
        if (bodyOption.isEmpty()) {
            return Optional.empty();
        }

        JsonObject body = bodyOption.get();
        Map<String, ClaimValue> claims = extractClaims(body);

        return Optional.of(new AccessTokenContent(claims, decodedJwt.getRawToken(), null));
    }

    /**
     * Creates an IdTokenContent from a decoded JWT.
     *
     * @param decodedJwt the decoded JWT
     * @return an Optional containing the IdTokenContent if it could be created, empty otherwise
     */
    public Optional<IdTokenContent> createIdToken(@NonNull DecodedJwt decodedJwt) {
        Optional<JsonObject> bodyOption = decodedJwt.getBody();
        if (bodyOption.isEmpty()) {
            return Optional.empty();
        }

        JsonObject body = bodyOption.get();
        Map<String, ClaimValue> claims = extractClaims(body);

        return Optional.of(new IdTokenContent(claims, decodedJwt.getRawToken()));
    }

    /**
     * Creates a RefreshTokenContent from a raw token string.
     *
     * @param rawToken the raw token string
     * @return an Optional containing the RefreshTokenContent
     */
    public Optional<RefreshTokenContent> createRefreshToken(@NonNull String rawToken) {
        return Optional.of(new RefreshTokenContent(rawToken));
    }

    /**
     * Extracts claims from a JSON object.
     *
     * @param jsonObject the JSON object containing claims
     * @return a map of claim names to claim values
     */
    private Map<String, ClaimValue> extractClaims(JsonObject jsonObject) {
        Map<String, ClaimValue> claims = new HashMap<>();

        // Process all keys in the JSON object
        for (String key : jsonObject.keySet()) {
            // Try to map using known ClaimName
            Optional<ClaimName> claimNameOption = ClaimName.fromString(key);
            if (claimNameOption.isPresent()) {
                ClaimName claimName = claimNameOption.get();
                ClaimValue claimValue = claimName.map(jsonObject);
                claims.put(key, claimValue);
            } else {
                // Use IdentityMapper for unknown claims
                ClaimValue claimValue = new IdentityMapper().map(jsonObject, key);
                claims.put(key, claimValue);
            }
        }

        return claims;
    }
}