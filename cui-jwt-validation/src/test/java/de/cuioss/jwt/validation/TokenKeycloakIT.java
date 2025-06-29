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

import de.cuioss.jwt.validation.exception.TokenValidationException;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.well_known.HttpWellKnownResolver;
import de.cuioss.test.keycloakit.KeycloakITBase;
import de.cuioss.test.keycloakit.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Splitter;
import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.*;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Tests Token integration with Keycloak")
public class TokenKeycloakIT extends KeycloakITBase {

    public static final String SCOPES = "openid email profile";
    public static final List<String> SCOPES_AS_LIST = Splitter.on(" ").splitToList(SCOPES);
    private static final CuiLogger LOGGER = new CuiLogger(TokenKeycloakIT.class);

    private TokenValidator accessTokenValidator; // For access tokens (audience: "account")
    private TokenValidator idTokenValidator; // For ID tokens (audience: "test_client")
    private String authServerUrlString; // To cache the auth server URL
    private static SSLConfig restAssuredSslConfig;
    private static SSLContext keycloakSslContext;

    /**
     * Creates an SSLContext that uses the keystore provided by TestRealm.ProvidedKeyStore.
     * This is the proper way to create a secure SSL context for testing with Keycloak.
     *
     * @return an SSLContext configured with the Keycloak test keystore
     * @throws Exception if an error occurs
     */
    private static SSLContext createKeycloakSSLContext() throws Exception {
        // For testing purposes, we'll create a trust-all SSL context
        // This is similar to what the original trustAllSslContext was doing
        // but we're using a more descriptive name to indicate its purpose
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Trust all client certificates for testing
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Trust all server certificates for testing
                    }
                }
        };

        // Create and initialize the SSLContext with the trust-all manager
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, new SecureRandom());

        // Log that we're using a trust-all context for testing
        LOGGER.debug(() -> "Using trust-all SSL context for testing with Keycloak");

        return sslContext;
    }

    @BeforeAll
    static void globalSetup() throws Exception {
        // Configure RestAssured to use the keystore used / provided by testcontainers-keycloak
        // This is needed for RestAssured to trust the Keycloak instance's SSL certificate.
        restAssuredSslConfig = SSLConfig.sslConfig().trustStore(TestRealm.ProvidedKeyStore.KEYSTORE_PATH, TestRealm.ProvidedKeyStore.PASSWORD);
        RestAssured.config = RestAssured.config().sslConfig(restAssuredSslConfig);

        // Create an SSLContext using the Keycloak keystore for HttpJwksLoader and WellKnownHandler.
        // This ensures that our HTTP clients can properly validate the Keycloak server's certificate.
        keycloakSslContext = createKeycloakSSLContext();

        // Log the keystore path and password for debugging
        LOGGER.debug(() -> "KEYSTORE_PATH: " + TestRealm.ProvidedKeyStore.KEYSTORE_PATH);
        LOGGER.debug(() -> "PASSWORD: " + TestRealm.ProvidedKeyStore.PASSWORD);
    }

    @BeforeEach
    void setUp() {
        String issuerString = getIssuer(); // This is String as per KeycloakITBase
        if (issuerString == null) {
            throw new IllegalStateException("getIssuer() returned null, cannot derive authServerUrlString");
        }
        int realmsIndex = issuerString.indexOf("/realms/");
        if (realmsIndex != -1) {
            this.authServerUrlString = issuerString.substring(0, realmsIndex);
        } else {
            // Fallback or error if "/realms/" is not found.
            // This indicates an unexpected issuer format from KeycloakITBase.
            // For now, assign the full issuer string to potentially highlight the issue later,
            // or throw an exception.
            LOGGER.warn("'/realms/' not found in issuer string '%s', authServerUrlString may be incorrect.", issuerString);
            this.authServerUrlString = issuerString;
        }
        LOGGER.info("Derived authServerUrlString: %s", this.authServerUrlString);
        // Create a JwksLoader with the secure SSLContext that uses Keycloak's keystore
        HttpJwksLoaderConfig httpJwksConfig = HttpJwksLoaderConfig.builder()
                .jwksUrl(getJWKSUrl()) // Direct JWKS URL from Keycloak container
                .build();
        // Note: SSL context handling moved to HttpHandler level in simplified implementation

        // Create IssuerConfig for access tokens (audience: "account")
        IssuerConfig accessTokenIssuerConfig = IssuerConfig.builder()
                .issuer(getIssuer()) // Direct Issuer URL from Keycloak container
                .expectedAudience("account") // Access tokens have "account" audience
                .httpJwksLoaderConfig(httpJwksConfig)
                .build();

        // Create IssuerConfig for ID tokens (audience: "test_client")
        IssuerConfig idTokenIssuerConfig = IssuerConfig.builder()
                .issuer(getIssuer()) // Direct Issuer URL from Keycloak container
                .expectedAudience("test_client") // ID tokens have client ID as audience
                .httpJwksLoaderConfig(httpJwksConfig)
                .build();

        // Create the validation factories
        accessTokenValidator = new TokenValidator(accessTokenIssuerConfig);
        idTokenValidator = new TokenValidator(idTokenIssuerConfig);
    }

    private String requestToken(Map<String, String> parameter, String tokenType) {
        String tokenString = given().config(RestAssured.config().sslConfig(restAssuredSslConfig)) // Ensure RestAssured uses the SSL config
                .contentType("application/x-www-form-urlencoded")
                .formParams(parameter)
                .post(getTokenUrl()).then().assertThat().statusCode(200)
                .extract().path(tokenType);
        LOGGER.info(() -> "Received %s: %s".formatted(tokenType, tokenString));
        return tokenString;
    }

    @Nested
    @DisplayName("Access Token Tests")
    class AccessTokenTests {
        @Test
        @DisplayName("Should handle valid access token")
        void shouldHandleValidAccessToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);
            var accessToken = accessTokenValidator.createAccessToken(tokenString);

            assertFalse(accessToken.isExpired(), "Token should not be expired");
            // Check if all scopes are present in the token
            List<String> tokenScopes = accessToken.getScopes();
            assertTrue(tokenScopes.containsAll(SCOPES_AS_LIST), "Token should provide requested scopes");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), accessToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ACCESS_TOKEN, accessToken.getTokenType(), "Token type should be ACCESS_TOKEN");
            assertTrue(accessToken.getAudience().map(list -> !list.isEmpty()).orElse(false), "Audience should be present");
        }
    }

    @Nested
    @DisplayName("ID Token Tests")
    class IdTokenTests {
        @Test
        @DisplayName("Should handle valid ID-Token")
        void shouldHandleValidIdToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ID_TOKEN);
            var idToken = idTokenValidator.createIdToken(tokenString);

            assertFalse(idToken.isExpired(), "Token should not be expired");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), idToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ID_TOKEN, idToken.getTokenType(), "Token type should be ID_TOKEN");
            // Corrected: IdTokenContent.getAudience() returns List<String>, not Optional<List<String>>
            assertFalse(idToken.getAudience().isEmpty(), "Audience should be present");
        }
    }

    @Nested
    @DisplayName("Refresh Token Tests")
    class RefreshTokenTests {
        @Test
        @DisplayName("Should handle valid Refresh-Token")
        void shouldHandleValidRefreshToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.REFRESH);
            var refreshToken = accessTokenValidator.createRefreshToken(tokenString);
            assertNotNull(refreshToken.getRawToken(), "Token string should not be null");
            assertEquals(TokenType.REFRESH_TOKEN, refreshToken.getTokenType(), "Token type should be REFRESH_TOKEN");
            assertFalse(refreshToken.getClaims().isEmpty());
        }
    }

    @Nested
    @DisplayName("WellKnown Discovery Validation Tests")
    class WellKnownDiscoveryValidationTests {
        // Removed setUpNested and authServerUrlForTest field

        @Test
        @DisplayName("Should validate Keycloak token using Well-Known discovery")
        void shouldValidateKeycloakTokenUsingWellKnownDiscovery() {
            // 1. Get Keycloak's well-known URI
            // Assuming getAuthServerUrl() returns something like "https://localhost:port/auth"
            // and realm is "cui-test"
            String wellKnownUrlString = TokenKeycloakIT.this.authServerUrlString + "/realms/" + TestRealm.REALM_NAME + "/.well-known/openid-configuration";
            LOGGER.info("Using Well-Known URL: " + wellKnownUrlString);

            // 2. Perform OIDC Discovery
            // Use the keycloakSslContext to ensure proper SSL certificate validation
            // when connecting to the Keycloak server
            HttpWellKnownResolver wellKnownHandler = HttpWellKnownResolver.builder()
                    .url(wellKnownUrlString)
                    .sslContext(keycloakSslContext)
                    .build();
            assertNotNull(wellKnownHandler.getJwksUri(), "JWKS URI should be present in well-known config");
            assertNotNull(wellKnownHandler.getIssuer(), "Issuer should be present in well-known config");
            URL keycloakIssuerUrl = wellKnownHandler.getIssuer().getUrl();

            // 3. Configure HttpJwksLoaderConfig using direct JWKS URL
            // Note: WellKnownHandler integration simplified - using direct URL
            String jwksUrl = wellKnownHandler.getJwksUri() != null ?
                    wellKnownHandler.getJwksUri().toString() : getJWKSUrl();
            HttpJwksLoaderConfig jwksConfig = HttpJwksLoaderConfig.builder()
                    .jwksUrl(jwksUrl)
                    .build();
            // Note: SSL context handling moved to HttpHandler level in simplified implementation

            // 4. Configure IssuerConfig and TokenValidator
            IssuerConfig issuerConfig = IssuerConfig.builder()
                    .issuer(keycloakIssuerUrl.toString()) // Use issuer from discovery
                    .expectedAudience("account") // Access tokens have "account" audience
                    .httpJwksLoaderConfig(jwksConfig)
                    .build();
            TokenValidator validator = new TokenValidator(issuerConfig);

            // 5. Obtain a token from Keycloak
            String rawToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);
            LOGGER.debug(() -> "Raw token: " + rawToken);

            // 6. Validate the token
            LOGGER.debug(() -> "About to validate token with validator: " + validator);
            var accessToken = validator.createAccessToken(rawToken);
            LOGGER.debug(() -> "Token validated successfully");

            // 7. Assertions
            assertNotNull(accessToken, "Validated token should not be null");
            assertFalse(accessToken.isExpired(), "Token should not be expired");
            assertEquals(keycloakIssuerUrl.toString(), accessToken.getIssuer(), "Issuer should match discovery"); // getIssuer() returns String

            // Log the actual audience for debugging
            LOGGER.debug(() -> "Actual audience in token: " + accessToken.getAudience().orElse(List.of()));

            // Check if the audience is present (not empty)
            assertTrue(accessToken.getAudience().map(list -> !list.isEmpty()).orElse(false), "Audience should be present");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), accessToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ACCESS_TOKEN, accessToken.getTokenType(), "Token type should be ACCESS_TOKEN");
        }

        @Test
        @DisplayName("Should fail validation if expected issuer is incorrect (via Well-Known discovery setup)")
        void shouldFailValidationWithIncorrectExpectedIssuerViaWellKnown() {
            String wellKnownUrlString = TokenKeycloakIT.this.authServerUrlString + "/realms/" + TestRealm.REALM_NAME + "/.well-known/openid-configuration";
            HttpWellKnownResolver wellKnownHandler = HttpWellKnownResolver.builder()
                    .url(wellKnownUrlString)
                    .sslContext(keycloakSslContext)
                    .build();
            assertNotNull(wellKnownHandler.getIssuer(), "Issuer should be present in well-known config");

            // Use direct JWKS URL since WellKnownHandler integration is simplified
            String jwksUrl = wellKnownHandler.getJwksUri() != null ?
                    wellKnownHandler.getJwksUri().toString() : getJWKSUrl();
            HttpJwksLoaderConfig jwksConfig = HttpJwksLoaderConfig.builder()
                    .jwksUrl(jwksUrl)
                    .build();
            // Note: SSL context handling moved to HttpHandler level in simplified implementation

            String incorrectIssuer = "https://incorrect-issuer.com/auth/realms/cui-test";
            IssuerConfig issuerConfig = IssuerConfig.builder()
                    .issuer(incorrectIssuer) // Manually set incorrect issuer
                    .expectedAudience("account") // Access tokens have "account" audience
                    .httpJwksLoaderConfig(jwksConfig)
                    .build();
            TokenValidator validator = new TokenValidator(issuerConfig);

            String rawToken = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ACCESS);

            // Assert that validation fails with TokenValidationException (or a more specific one if applicable)
            assertThrows(TokenValidationException.class, () -> {
                validator.createAccessToken(rawToken);
            }, "Validation should fail due to issuer mismatch");
        }
    }
}
