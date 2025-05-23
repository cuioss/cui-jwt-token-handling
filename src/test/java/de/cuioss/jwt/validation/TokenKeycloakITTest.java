/*
 * Copyright 2025 the original author or authors.
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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.test.keycloakit.KeycloakITBase;
import de.cuioss.test.keycloakit.TestRealm;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.Splitter;
import io.restassured.RestAssured;
import io.restassured.config.SSLConfig;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

import static io.restassured.RestAssured.given;
import static org.junit.jupiter.api.Assertions.*;

@DisplayName("Tests Token integration with Keycloak")
public class TokenKeycloakITTest extends KeycloakITBase {

    public static final String SCOPES = "openid email profile";
    public static final List<String> SCOPES_AS_LIST = Splitter.on(" ").splitToList(SCOPES);
    private static final CuiLogger LOGGER = new CuiLogger(TokenKeycloakITTest.class);

    private TokenValidator factory;

    /**
     * Creates an SSLContext that trusts all certificates.
     * WARNING: This should only be used for testing purposes, never in production!
     *
     * @return an SSLContext that trusts all certificates
     * @throws Exception if an error occurs
     */
    private static SSLContext createSSLContextFromSSLConfig(SSLConfig sslConfig) throws Exception {
        KeyStore trustStore = sslConfig.getTrustStore();

        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);
        TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    public X509Certificate[] getAcceptedIssuers() {
                        return new X509Certificate[0];
                    }

                    public void checkClientTrusted(X509Certificate[] certs, String authType) {
                        // Trust all client certificates
                    }

                    public void checkServerTrusted(X509Certificate[] certs, String authType) {
                        // Trust all server certificates
                    }
                }
        };
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, trustAllCerts, null);
        return sslContext;
    }

    @BeforeEach
    void setUp() throws Exception {
        // Configure RestAssured to use the keystore used / provided by testcontainers-keycloak
        SSLConfig sslConfig = SSLConfig.sslConfig().trustStore(TestRealm.ProvidedKeyStore.KEYSTORE_PATH, TestRealm.ProvidedKeyStore.PASSWORD);
        RestAssured.config = RestAssured.config().sslConfig(sslConfig);

        // Log the keystore path and password for debugging
        LOGGER.debug(() -> "KEYSTORE_PATH: " + TestRealm.ProvidedKeyStore.KEYSTORE_PATH);
        LOGGER.debug(() -> "PASSWORD: " + TestRealm.ProvidedKeyStore.PASSWORD);

        // Create a JwksLoader with the SSLContext
        HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
                .jwksUrl(getJWKSUrl())
                .refreshIntervalSeconds(100)
                .sslContext(createSSLContextFromSSLConfig(sslConfig))
                .build();

        // Create an IssuerConfig
        IssuerConfig issuerConfig = IssuerConfig.builder()
                .issuer(getIssuer())
                .httpJwksLoaderConfig(config)
                .build();

        // Create the validation factory
        factory = new TokenValidator(issuerConfig);
    }

    private String requestToken(Map<String, String> parameter, String tokenType) {
        String tokenString = given().contentType("application/x-www-form-urlencoded")
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
            var accessToken = factory.createAccessToken(tokenString);

            assertFalse(accessToken.isExpired(), "Token should not be expired");
            // Check if all scopes are present in the token
            List<String> tokenScopes = accessToken.getScopes();
            assertTrue(tokenScopes.containsAll(SCOPES_AS_LIST), "Token should provide requested scopes");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), accessToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ACCESS_TOKEN, accessToken.getTokenType(), "Token type should be ACCESS_TOKEN");
        }
    }

    @Nested
    @DisplayName("ID Token Tests")
    class IdTokenTests {
        @Test
        @DisplayName("Should handle valid ID-Token")
        void shouldHandleValidIdToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.ID_TOKEN);
            var idToken = factory.createIdToken(tokenString);

            assertFalse(idToken.isExpired(), "Token should not be expired");
            assertEquals(TestRealm.TestUser.EMAIL.toLowerCase(), idToken.getEmail().orElse(""), "Email should match test user");
            assertEquals(TokenType.ID_TOKEN, idToken.getTokenType(), "Token type should be ID_TOKEN");
        }
    }

    @Nested
    @DisplayName("Refresh Token Tests")
    class RefreshTokenTests {
        @Test
        @DisplayName("Should handle valid Refresh-Token")
        void shouldHandleValidRefreshToken() {
            var tokenString = requestToken(parameterForScopedToken(SCOPES), TokenTypes.REFRESH);
            var refreshToken = factory.createRefreshToken(tokenString);
            assertNotNull(refreshToken.getRawToken(), "Token string should not be null");
            assertEquals(TokenType.REFRESH_TOKEN, refreshToken.getTokenType(), "Token type should be REFRESH_TOKEN");
            assertFalse(refreshToken.getClaims().isEmpty());
        }
    }
}
