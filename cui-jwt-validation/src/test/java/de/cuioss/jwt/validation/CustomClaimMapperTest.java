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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.domain.claim.ClaimValueType;
import de.cuioss.jwt.validation.domain.claim.mapper.ClaimMapper;
import de.cuioss.jwt.validation.domain.claim.mapper.JsonCollectionMapper;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.jwt.validation.test.InMemoryJWKSFactory;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.ClaimControlParameter;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

@EnableTestLogger
@DisplayName("Tests Custom ClaimMapper functionality")
class CustomClaimMapperTest {

    private static final String ROLE_CLAIM = "role";
    private static final List<String> ROLES = Arrays.asList("admin", "user", "manager");

    private TokenValidator tokenValidator;
    private String tokenWithRoles;
    private String jwksContent;

    @BeforeEach
    void setUp() {
        // Create a JWKSKeyLoader with the default JWKS content
        jwksContent = InMemoryJWKSFactory.createDefaultJwks();

        // Create a custom claim mapper for the "role" claim
        ClaimMapper roleMapper = new JsonCollectionMapper();

        // Create issuer config with the custom claim mapper
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(TestTokenHolder.TEST_ISSUER)
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                .jwksContent(jwksContent)
                .claimMapper(ROLE_CLAIM, roleMapper)
                .build();

        // Create validation factory
        tokenValidator = new TokenValidator(issuerConfig);

        // Create a token with a "role" claim containing an array of roles using TestTokenHolder
        var claimControl = ClaimControlParameter.builder().build();
        var tokenHolder = new TestTokenHolder(TokenType.ACCESS_TOKEN, claimControl);

        // Set the audience claim
        tokenHolder.withClaim(ClaimName.AUDIENCE.getName(), ClaimValue.forList(TestTokenHolder.TEST_AUDIENCE, List.of(TestTokenHolder.TEST_AUDIENCE)));

        // Set the issuer and authorized party claims
        tokenHolder.withClaim(ClaimName.ISSUER.getName(), ClaimValue.forPlainString(TestTokenHolder.TEST_ISSUER));
        tokenHolder.withClaim(ClaimName.AUTHORIZED_PARTY.getName(), ClaimValue.forPlainString(TestTokenHolder.TEST_CLIENT_ID));

        // Add the role claim with an array of roles
        tokenHolder.withClaim(ROLE_CLAIM, ClaimValue.forList(String.join(",", ROLES), ROLES));

        // Add scope claim
        tokenHolder.withClaim(ClaimName.SCOPE.getName(), ClaimValue.forList("openid profile email",
                Arrays.asList("openid", "profile", "email")));

        // Get the raw token
        tokenWithRoles = tokenHolder.getRawToken();
    }

    @Test
    @DisplayName("Should use custom claim mapper for role claim")
    void shouldUseCustomClaimMapperForRoleClaim() {
        // Parse the validation
        AccessTokenContent tokenContent = tokenValidator.createAccessToken(tokenWithRoles);
        ClaimValue roleClaim = tokenContent.getClaims().get(ROLE_CLAIM);

        // Verify the role claim was mapped correctly
        assertNotNull(roleClaim, "Role claim should not be null");
        assertEquals(ClaimValueType.STRING_LIST, roleClaim.getType(), "Role claim should be a STRING_LIST");
        assertEquals(ROLES.size(), roleClaim.getAsList().size(), "Role claim should have the correct number of roles");
        assertTrue(roleClaim.getAsList().containsAll(ROLES), "Role claim should contain all the roles");
    }

    @Test
    @DisplayName("Should use default mapper when no custom mapper is configured")
    void shouldUseDefaultMapperWhenNoCustomMapperIsConfigured() {
        // Create issuer config without custom claim mapper
        IssuerConfig issuerConfigWithoutCustomMapper = IssuerConfig.builder()
                .issuer(TestTokenHolder.TEST_ISSUER)
                .expectedAudience(TestTokenHolder.TEST_AUDIENCE)
                .expectedClientId(TestTokenHolder.TEST_CLIENT_ID)
                .jwksContent(jwksContent)
                .build();

        // Create validation factory
        TokenValidator factoryWithoutCustomMapper = new TokenValidator(
                issuerConfigWithoutCustomMapper);

        // Parse the validation
        AccessTokenContent tokenContent = factoryWithoutCustomMapper.createAccessToken(tokenWithRoles);
        ClaimValue roleClaim = tokenContent.getClaims().get(ROLE_CLAIM);

        // Verify the role claim was mapped using the default mapper
        assertNotNull(roleClaim, "Role claim should not be null");
        // The default mapper would not recognize this as a collection
        assertNotEquals(ClaimValueType.STRING_LIST, roleClaim.getType(), "Role claim should not be a STRING_LIST with default mapper");
    }
}
