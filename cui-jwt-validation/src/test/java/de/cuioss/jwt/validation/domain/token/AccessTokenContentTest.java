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
package de.cuioss.jwt.validation.domain.token;

import de.cuioss.jwt.validation.TokenType;
import de.cuioss.jwt.validation.domain.claim.ClaimName;
import de.cuioss.jwt.validation.domain.claim.ClaimValue;
import de.cuioss.jwt.validation.test.TestTokenHolder;
import de.cuioss.jwt.validation.test.generator.ScopeGenerator;
import de.cuioss.jwt.validation.test.generator.TestTokenGenerators;
import de.cuioss.jwt.validation.test.junit.TestTokenSource;
import de.cuioss.test.generator.junit.EnableGeneratorController;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.util.*;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link AccessTokenContent}.
 * <p>
 * Verifies requirements:
 * <ul>
 *   <li><a href="https://github.com/cuioss/cui-jwt/blob/main/doc/Requirements.adoc#CUI-JWT-1.1">CUI-JWT-1.1: Token Structure</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/blob/main/doc/Requirements.adoc#CUI-JWT-1.2">CUI-JWT-1.2: Token Types</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/blob/main/doc/Requirements.adoc#CUI-JWT-2.1">CUI-JWT-2.1: Base Token Functionality</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/blob/main/doc/Requirements.adoc#CUI-JWT-2.2">CUI-JWT-2.2: Access Token Functionality</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/blob/main/doc/Requirements.adoc#CUI-JWT-8.4">CUI-JWT-8.4: Claims Validation</a></li>
 * </ul>
 *
 * @author Oliver Wolff
 */
@DisplayName("AccessTokenContent")
@EnableGeneratorController
class AccessTokenContentTest {

    private static final String TEST_EMAIL = "test@example.com";

    private AccessTokenContent createTokenWithClaim(ClaimName claimName, ClaimValue claimValue) {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        tokenHolder.withClaim(claimName.getName(), claimValue);
        return new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken(), TEST_EMAIL);
    }

    private AccessTokenContent createTokenWithClaims(Map<String, ClaimValue> claims) {
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        return new AccessTokenContent(claims, tokenHolder.getRawToken(), TEST_EMAIL);
    }

    static Stream<Arguments> claimTestData() {
        return Stream.of(
                Arguments.of(ClaimName.ROLES, Arrays.asList("admin", "user", "manager"), "roles"),
                Arguments.of(ClaimName.GROUPS, Arrays.asList("group1", "group2", "group3"), "groups")
        );
    }

    private List<String> getClaimValues(AccessTokenContent token, ClaimName claimName) {
        return switch (claimName) {
            case ROLES -> token.getRoles();
            case GROUPS -> token.getGroups();
            default -> throw new IllegalArgumentException("Unsupported claim: " + claimName);
        };
    }

    private boolean providesClaimValues(AccessTokenContent token, ClaimName claimName, List<String> expected) {
        return switch (claimName) {
            case ROLES -> token.providesRoles(expected);
            case GROUPS -> token.providesGroups(expected);
            default -> throw new IllegalArgumentException("Unsupported claim: " + claimName);
        };
    }

    private Set<String> determineMissingValues(AccessTokenContent token, ClaimName claimName, List<String> expected) {
        return switch (claimName) {
            case ROLES -> token.determineMissingRoles(expected);
            case GROUPS -> token.determineMissingGroups(expected);
            default -> throw new IllegalArgumentException("Unsupported claim: " + claimName);
        };
    }


    @Test
    @DisplayName("Return audience when present")
    void shouldReturnAudienceWhenPresent() {
        List<String> testAudience = Arrays.asList("client1", "client2");
        var accessTokenContent = createTokenWithClaim(
                ClaimName.AUDIENCE, ClaimValue.forList(testAudience.toString(), testAudience));

        Optional<List<String>> audience = accessTokenContent.getAudience();

        assertTrue(audience.isPresent(), "Audience should be present");
        assertEquals(testAudience, audience.get(), "Audience should match expected");
    }


    @Test
    @DisplayName("Return scopes when present")
    void shouldReturnScopesWhenPresent() {
        List<String> testScopes = Arrays.asList("openid", "profile", "email");
        var accessTokenContent = createTokenWithClaim(
                ClaimName.SCOPE, ClaimValue.forList(testScopes.toString(), testScopes));

        List<String> scopes = accessTokenContent.getScopes();

        assertEquals(testScopes, scopes, "Scopes should match expected");
    }

    @Test
    @DisplayName("Throw exception when scopes not present")
    void shouldThrowExceptionWhenScopesNotPresent() {
        var accessTokenContent = createTokenWithClaims(new HashMap<>());

        assertThrows(IllegalStateException.class, accessTokenContent::getScopes,
                "Should throw exception when scopes missing");
    }


    @Test
    @DisplayName("Return email from claims")
    void shouldReturnEmailFromClaims() {
        Map<String, ClaimValue> claims = new HashMap<>();
        claims.put(ClaimName.EMAIL.getName(), ClaimValue.forPlainString(TEST_EMAIL));
        TestTokenHolder tokenHolder = TestTokenGenerators.accessTokens().next();
        var accessTokenContent = new AccessTokenContent(claims, tokenHolder.getRawToken(), null);

        Optional<String> email = accessTokenContent.getEmail();

        assertTrue(email.isPresent(), "Email should be present");
        assertEquals(TEST_EMAIL, email.get(), "Email should match expected");
    }


    @Test
    @DisplayName("Return preferred username when present")
    void shouldReturnPreferredUsernameWhenPresent() {
        String username = "testuser";
        var accessTokenContent = createTokenWithClaim(
                ClaimName.PREFERRED_USERNAME, ClaimValue.forPlainString(username));

        Optional<String> preferredUsername = accessTokenContent.getPreferredUsername();

        assertTrue(preferredUsername.isPresent(), "Preferred username should be present");
        assertEquals(username, preferredUsername.get(), "Preferred username should match");
    }


    @ParameterizedTest
    @MethodSource("claimTestData")
    @DisplayName("Return claim values when present")
    void shouldReturnClaimValuesWhenPresent(ClaimName claimName, List<String> testValues, String description) {
        var accessTokenContent = createTokenWithClaim(
                claimName, ClaimValue.forList(testValues.toString(), testValues));

        List<String> values = getClaimValues(accessTokenContent, claimName);

        assertEquals(testValues, values, description + " should match expected");
    }


    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 3)
    @DisplayName("Provide scopes when all expected are present")
    void shouldProvideScopesWhenAllExpectedArePresent(TestTokenHolder tokenHolder) {
        // Get scopes from the generated token
        List<String> allScopes = tokenHolder.getClaims().get(ClaimName.SCOPE.getName()).getAsList();
        var accessTokenContent = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken(), TEST_EMAIL);

        // Test with subset of scopes (if we have more than one scope)
        List<String> expectedScopes = allScopes.size() > 1 ?
                allScopes.subList(0, allScopes.size() - 1) : allScopes;
        boolean result = accessTokenContent.providesScopes(expectedScopes);

        assertTrue(result, "Should provide all expected scopes");
    }

    @ParameterizedTest
    @TestTokenSource(value = TokenType.ACCESS_TOKEN, count = 2)
    @DisplayName("Not provide scopes when some missing")
    void shouldNotProvideScopesWhenSomeMissing(TestTokenHolder tokenHolder) {
        // Get scopes from the generated token and add a non-existent scope
        List<String> existingScopes = tokenHolder.getClaims().get(ClaimName.SCOPE.getName()).getAsList();
        var accessTokenContent = new AccessTokenContent(tokenHolder.getClaims(), tokenHolder.getRawToken(), TEST_EMAIL);

        List<String> expectedScopes = new ArrayList<>(existingScopes);
        expectedScopes.add("non_existent_scope");
        boolean result = accessTokenContent.providesScopes(expectedScopes);

        assertFalse(result, "Should not provide scopes when some are missing");
    }

    @Test
    @DisplayName("Provide empty scopes")
    void shouldProvideEmptyScopes() {
        List<String> testScopes = Arrays.asList("openid", "profile", "email");
        var accessTokenContent = createTokenWithClaim(
                ClaimName.SCOPE, ClaimValue.forList(testScopes.toString(), testScopes));

        boolean result = accessTokenContent.providesScopes(Collections.emptyList());

        assertTrue(result, "Should provide empty scope list");
    }


    @Test
    @DisplayName("Return missing scopes when some are absent")
    void shouldReturnMissingScopes() {
        ScopeGenerator scopeGenerator = new ScopeGenerator(2, 4);
        String scopeString = scopeGenerator.next();
        Collection<String> scopes = ScopeGenerator.splitScopes(scopeString);

        var accessTokenContent = createTokenWithClaim(
                ClaimName.SCOPE, ClaimValue.forList(scopes.toString(), new ArrayList<>(scopes)));

        List<String> expectedScopes = new ArrayList<>(scopes);
        String missingScope1 = "non_existent_scope1";
        String missingScope2 = "non_existent_scope2";
        expectedScopes.add(missingScope1);
        expectedScopes.add(missingScope2);
        Set<String> missingScopes = accessTokenContent.determineMissingScopes(expectedScopes);

        assertEquals(2, missingScopes.size(), "Should find 2 missing scopes");
        assertTrue(missingScopes.contains(missingScope1), "Should contain first missing scope");
        assertTrue(missingScopes.contains(missingScope2), "Should contain second missing scope");
    }

    @ParameterizedTest
    @MethodSource("claimTestData")
    @DisplayName("Provide claim values when all expected are present")
    void shouldProvideClaimValuesWhenAllExpectedArePresent(ClaimName claimName, List<String> testValues, String description) {
        var accessTokenContent = createTokenWithClaim(
                claimName, ClaimValue.forList(testValues.toString(), testValues));

        List<String> expectedValues = testValues.subList(0, 2);
        boolean result = providesClaimValues(accessTokenContent, claimName, expectedValues);

        assertTrue(result, description + " should provide all expected values");
    }

    @ParameterizedTest
    @MethodSource("claimTestData")
    @DisplayName("Not provide claim values when some missing")
    void shouldNotProvideClaimValuesWhenSomeMissing(ClaimName claimName, List<String> testValues, String description) {
        var accessTokenContent = createTokenWithClaim(
                claimName, ClaimValue.forList(testValues.toString(), testValues));

        List<String> expectedValues = new ArrayList<>(testValues);
        expectedValues.add("non_existent_" + description.substring(0, description.length() - 1));
        boolean result = providesClaimValues(accessTokenContent, claimName, expectedValues);

        assertFalse(result, description + " should not provide when values missing");
    }

    @ParameterizedTest
    @MethodSource("claimTestData")
    @DisplayName("Not provide claim values when claim not present")
    void shouldNotProvideClaimValuesWhenClaimNotPresent(ClaimName claimName, List<String> testValues, String description) {
        var accessTokenContent = createTokenWithClaims(new HashMap<>());

        boolean result = providesClaimValues(accessTokenContent, claimName, List.of(testValues.get(0)));

        assertFalse(result, description + " should not provide when claim absent");
    }

    @ParameterizedTest
    @MethodSource("claimTestData")
    @DisplayName("Return missing claim values when some absent")
    void shouldReturnMissingClaimValues(ClaimName claimName, List<String> testValues, String description) {
        var accessTokenContent = createTokenWithClaim(
                claimName, ClaimValue.forList(testValues.toString(), testValues));

        List<String> expectedValues = new ArrayList<>(testValues);
        String missing1 = "missing1_" + description.substring(0, description.length() - 1);
        String missing2 = "missing2_" + description.substring(0, description.length() - 1);
        expectedValues.add(missing1);
        expectedValues.add(missing2);
        Set<String> missingValues = determineMissingValues(accessTokenContent, claimName, expectedValues);

        assertEquals(2, missingValues.size(), "Should find 2 missing " + description);
        assertTrue(missingValues.contains(missing1), "Should contain first missing value");
        assertTrue(missingValues.contains(missing2), "Should contain second missing value");
    }


}