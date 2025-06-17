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
package de.cuioss.jwt.validation.well_known;

import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.test.dispatcher.WellKnownDispatcher;
import de.cuioss.test.juli.LogAsserts;
import de.cuioss.test.juli.TestLogLevel;
import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.test.mockwebserver.EnableMockWebServer;
import de.cuioss.test.mockwebserver.URIBuilder;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcher;
import de.cuioss.test.mockwebserver.dispatcher.ModuleDispatcherElement;
import de.cuioss.tools.net.http.SecureSSLContextProvider;
import lombok.Getter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import javax.net.ssl.SSLContext;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Test suite for {@link WellKnownHandler}.
 * <p>
 * Verifies the functionality of the WellKnownHandler class, which is responsible
 * for fetching and parsing the OpenID Connect discovery document from a
 * .well-known/openid-configuration endpoint.
 * </p>
 */
@EnableMockWebServer
@EnableTestLogger(rootLevel = TestLogLevel.DEBUG, debug = WellKnownHandler.class)
@DisplayName("Tests WellKnownHandler functionality")
@ModuleDispatcher
class WellKnownHandlerTest {

    @Getter
    private static final WellKnownDispatcher wellKnownDispatcher = new WellKnownDispatcher();

    private URL baseUrl;


    /**
     * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
     * This method is called by the ModuleDispatcher framework.
     *
     * @return the WellKnownDispatcher
     */
    public ModuleDispatcherElement getModuleDispatcher() {
        return wellKnownDispatcher;
    }

    @BeforeEach
    void setUp(URIBuilder uriBuilder) throws MalformedURLException {
        // Get the base URL from the mock server
        baseUrl = URI.create(uriBuilder.buildAsString()).toURL();

        // Reset the dispatcher to its default state
        wellKnownDispatcher.returnDefault();

        // Reset the call counter
        wellKnownDispatcher.setCallCounter(0);
    }

    @Nested
    @DisplayName("Success Scenario Tests")
    @ModuleDispatcher
    class SuccessScenarioTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should successfully fetch and parse discovery document")
        void shouldFetchAndParseDiscoveryDocument(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify endpoints
            assertEquals(baseUrl.toString() + "/oidc/jwks.json",
                    handler.getJwksUri().getUrl().toString(),
                    "JWKS URI should match");

            assertEquals(baseUrl.toString(),
                    handler.getIssuer().getUrl().toString(),
                    "Issuer should match");

            assertEquals(baseUrl.toString() + "/protocol/openid-connect/auth",
                    handler.getAuthorizationEndpoint().getUrl().toString(),
                    "Authorization endpoint should match");

            assertEquals(baseUrl.toString() + "/protocol/openid-connect/token",
                    handler.getTokenEndpoint().getUrl().toString(),
                    "Token endpoint should match");

            assertTrue(handler.getUserinfoEndpoint().isPresent(), "Userinfo endpoint should be present");
            assertEquals(baseUrl.toString() + "/protocol/openid-connect/userinfo",
                    handler.getUserinfoEndpoint().get().getUrl().toString(),
                    "Userinfo endpoint should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // No need to verify logging in this test
        }
    }

    @Nested
    @DisplayName("Error Handling Tests")
    @ModuleDispatcher
    class ErrorHandlingTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should throw exception for null or empty URL during build")
        void shouldThrowExceptionForNullOrEmptyUrl() {
            // Test with null URL
            var builder = WellKnownHandler.builder().url((String) null);
            WellKnownDiscoveryException nullException = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception for null URL during build"
            );
            assertInstanceOf(IllegalArgumentException.class, nullException.getCause(), "Cause should be IllegalArgumentException");
            assertTrue(nullException.getCause().getMessage().contains("URI must not be null or empty"),
                    "Exception cause message should mention that URI must not be null or empty");

            // Test with empty URL
            builder = WellKnownHandler.builder().url("");
            WellKnownDiscoveryException emptyException = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception for empty URL during build"
            );
            assertInstanceOf(IllegalArgumentException.class, emptyException.getCause(), "Cause should be IllegalArgumentException");
            assertTrue(emptyException.getCause().getMessage().contains("URI must not be null or empty"),
                    "Exception cause message should mention that URI must not be null or empty");

            // Test with blank URL
            builder = WellKnownHandler.builder().url("   ");
            WellKnownDiscoveryException blankException = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception for blank URL during build"
            );
            assertInstanceOf(IllegalArgumentException.class, blankException.getCause(), "Cause should be IllegalArgumentException");
            assertTrue(blankException.getCause().getMessage().contains("URI must not be null or empty"),
                    "Exception cause message should mention that URI must not be null or empty");
        }

        @Test
        @DisplayName("Should throw exception for malformed URL during build")
        void shouldThrowExceptionForMalformedUrl() {
            var builder = WellKnownHandler.builder().url("not-a-url");
            WellKnownDiscoveryException exception = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception for malformed URL during build"
            );
            assertTrue(exception.getMessage().contains("while fetching or reading from"),
                    "Exception message should mention fetching or reading error");
        }

        @Test
        @DisplayName("Should throw exception when server returns error")
        void shouldThrowExceptionWhenServerReturnsError(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnError();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            var builder = WellKnownHandler.builder().url(wellKnownUrl);


            // When/Then - Verify that the expected exception is thrown
            assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception when server returns error"
            );
            wellKnownDispatcher.assertCallsAnswered(1);
            // The actual error message might vary depending on the HTTP client
            // Just verify that an exception is thrown
        }

        @Test
        @DisplayName("Should throw exception for invalid JSON response")
        void shouldThrowExceptionForInvalidJsonResponse(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnInvalidJson();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            var builder = WellKnownHandler.builder().url(wellKnownUrl);


            // When/Then - Verify that the expected exception is thrown
            assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception for invalid JSON response"
            );
            wellKnownDispatcher.assertCallsAnswered(1);

            // The actual error message might vary depending on the JSON parser
            // Just verify that an exception is thrown
        }

        @Test
        @DisplayName("Should throw exception when issuer is missing")
        void shouldThrowExceptionWhenIssuerIsMissing(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnMissingIssuer();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            var builder = WellKnownHandler.builder().url(wellKnownUrl);

            // When/Then - Verify that the expected exception is thrown
            var exception = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception when issuer is missing"
            );
            // The dispatcher is called during the build process
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify exception message
            assertTrue(exception.getMessage().contains("Required field 'issuer' not found"),
                    "Exception message should mention missing issuer field");
        }

        @Test
        @DisplayName("Should throw exception when jwks_uri is missing")
        void shouldThrowExceptionWhenJwksUriIsMissing(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnMissingJwksUri();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            var builder = WellKnownHandler.builder().url(wellKnownUrl);

            // When/Then - Verify that the expected exception is thrown
            var exception = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception when jwks_uri is missing"
            );
            // The dispatcher is called during the build process
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify exception message
            assertTrue(exception.getMessage().contains("Required URL field 'jwks_uri' is missing"),
                    "Exception message should mention missing jwks_uri field");
        }

        @Test
        @DisplayName("Should throw exception when issuer validation fails")
        void shouldThrowExceptionWhenIssuerValidationFails(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnInvalidIssuer();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            var builder = WellKnownHandler.builder().url(wellKnownUrl);

            // When/Then - Verify that the expected exception is thrown
            var exception = assertThrows(
                    WellKnownDiscoveryException.class, builder::build,
                    "Should throw exception when issuer validation fails"
            );
            // The dispatcher is called during the build process
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify exception message
            assertTrue(exception.getMessage().contains("Issuer validation failed"),
                    "Exception message should mention issuer validation failure");

            // Verify logging
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    JWTValidationLogMessages.ERROR.ISSUER_VALIDATION_FAILED.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Endpoint Retrieval Tests")
    @ModuleDispatcher
    class EndpointRetrievalTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should throw exceptions during build for missing required endpoints")
        void shouldThrowExceptionDuringBuildForMissingRequiredEndpoints(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            // Configure the dispatcher to return a document with only issuer and jwks_uri
            wellKnownDispatcher.returnOnlyRequiredFields();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When/Then - Verify that the expected exception is thrown
            // The build should throw an exception because authorization_endpoint and token_endpoint are required
            // but missing in the document
            var builder = WellKnownHandler.builder()
                    .url(wellKnownUrl);
            var exception = assertThrows(
                    WellKnownDiscoveryException.class,
                    builder::build,
                    "Should throw exception during build when required endpoints are missing"
            );

            // Verify the exception message mentions the missing required field
            assertTrue(
                    exception.getMessage().contains("Required URL field 'authorization_endpoint' is missing") ||
                            exception.getMessage().contains("Required URL field 'token_endpoint' is missing"),
                    "Exception message should mention missing required field"
            );
        }
    }

    @Nested
    @DisplayName("Logging Tests")
    @ModuleDispatcher
    class LoggingTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should log messages for successful operations")
        void shouldLogDebugMessagesForSuccessfulOperations(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When
            WellKnownHandler.builder().url(wellKnownUrl).build();

            // Then
            // Verify that at least one log message is present
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.WARN,
                    JWTValidationLogMessages.WARN.ACCESSIBILITY_CHECK_HTTP_ERROR.resolveIdentifierString());
        }

        @Test
        @DisplayName("Should log error messages for failed operations")
        void shouldLogErrorMessagesForFailedOperations(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            wellKnownDispatcher.returnInvalidIssuer();
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When/Then - Verify that the expected exception is thrown
            var builder = WellKnownHandler.builder().url(wellKnownUrl);
            assertThrows(
                    WellKnownDiscoveryException.class,
                    builder::build,
                    "Should throw exception when issuer validation fails"
            );

            // Then verify logging
            LogAsserts.assertLogMessagePresentContaining(TestLogLevel.ERROR,
                    JWTValidationLogMessages.ERROR.ISSUER_VALIDATION_FAILED.resolveIdentifierString());
        }
    }

    @Nested
    @DisplayName("Builder Tests")
    @ModuleDispatcher
    class BuilderTests {

        /**
         * Returns the WellKnownDispatcher for the ModuleDispatcher annotation.
         * This method is called by the ModuleDispatcher framework.
         *
         * @return the WellKnownDispatcher
         */
        public ModuleDispatcherElement getModuleDispatcher() {
            return wellKnownDispatcher;
        }

        @Test
        @DisplayName("Should use custom TLS versions configuration")
        void shouldUseCustomTlsVersionsConfiguration(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // Create a custom SecureSSLContextProvider with TLS 1.3 as minimum
            SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_3);

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .tlsVersions(secureSSLContextProvider)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify that the handler was created successfully
            assertNotNull(handler.getJwksUri(), "JWKS URI should not be null");
            assertNotNull(handler.getIssuer(), "Issuer should not be null");
            assertNotNull(handler.getAuthorizationEndpoint(), "Authorization endpoint should not be null");
            assertNotNull(handler.getTokenEndpoint(), "Token endpoint should not be null");
        }

        @Test
        @DisplayName("Should use custom parser configuration")
        void shouldUseCustomParserConfiguration(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // Create a custom ParserConfig with non-default values
            ParserConfig parserConfig = ParserConfig.builder()
                    .maxStringSize(2048)
                    .maxArraySize(32)
                    .maxDepth(5)
                    .build();

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .parserConfig(parserConfig)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);
        }

        @Test
        @DisplayName("Should use custom SSL context")
        void shouldUseCustomSslContext(URIBuilder uriBuilder) throws Exception {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // Create a custom SSLContext with proper initialization
            SSLContext sslContext = SSLContext.getInstance(SecureSSLContextProvider.TLS_V1_2);
            sslContext.init(null, null, new SecureRandom());

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .sslContext(sslContext)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify that the handler was created successfully
            assertNotNull(handler.getJwksUri(), "JWKS URI should not be null");
            assertNotNull(handler.getIssuer(), "Issuer should not be null");
            assertNotNull(handler.getAuthorizationEndpoint(), "Authorization endpoint should not be null");
            assertNotNull(handler.getTokenEndpoint(), "Token endpoint should not be null");
        }

        @Test
        @DisplayName("Should use custom connect timeout")
        void shouldUseCustomConnectTimeout(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .connectTimeoutSeconds(30)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify that the handler was created successfully
            assertNotNull(handler.getJwksUri(), "JWKS URI should not be null");
            assertNotNull(handler.getIssuer(), "Issuer should not be null");
            assertNotNull(handler.getAuthorizationEndpoint(), "Authorization endpoint should not be null");
            assertNotNull(handler.getTokenEndpoint(), "Token endpoint should not be null");
        }

        @Test
        @DisplayName("Should use custom read timeout")
        void shouldUseCustomReadTimeout(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .readTimeoutSeconds(60)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify that the handler was created successfully
            assertNotNull(handler.getJwksUri(), "JWKS URI should not be null");
            assertNotNull(handler.getIssuer(), "Issuer should not be null");
            assertNotNull(handler.getAuthorizationEndpoint(), "Authorization endpoint should not be null");
            assertNotNull(handler.getTokenEndpoint(), "Token endpoint should not be null");
        }

        @Test
        @DisplayName("Should use both timeout configurations")
        void shouldUseBothTimeoutConfigurations(URIBuilder uriBuilder) throws MalformedURLException {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .connectTimeoutSeconds(15)
                    .readTimeoutSeconds(45)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify that the handler was created successfully
            assertNotNull(handler.getJwksUri(), "JWKS URI should not be null");
            assertNotNull(handler.getIssuer(), "Issuer should not be null");
            assertNotNull(handler.getAuthorizationEndpoint(), "Authorization endpoint should not be null");
            assertNotNull(handler.getTokenEndpoint(), "Token endpoint should not be null");
        }

        @Test
        @DisplayName("Should throw exception for zero connect timeout")
        void shouldThrowExceptionForZeroConnectTimeout() {
            // Given
            var builder = WellKnownHandler.builder()
                    .url("https://example.com/.well-known/openid-configuration");

            // When & Then
            assertThrows(IllegalArgumentException.class, () -> builder.connectTimeoutSeconds(0), "Should throw IllegalArgumentException for zero connect timeout");
        }

        @Test
        @DisplayName("Should throw exception for negative connect timeout")
        void shouldThrowExceptionForNegativeConnectTimeout() {
            // Given
            var builder = WellKnownHandler.builder()
                    .url("https://example.com/.well-known/openid-configuration");

            // When & Then
            assertThrows(IllegalArgumentException.class, () -> builder.connectTimeoutSeconds(-1), "Should throw IllegalArgumentException for negative connect timeout");
        }

        @Test
        @DisplayName("Should throw exception for zero read timeout")
        void shouldThrowExceptionForZeroReadTimeout() {
            // Given
            var builder = WellKnownHandler.builder()
                    .url("https://example.com/.well-known/openid-configuration");

            // When & Then
            assertThrows(IllegalArgumentException.class, () -> builder.readTimeoutSeconds(0), "Should throw IllegalArgumentException for zero read timeout");
        }

        @Test
        @DisplayName("Should throw exception for negative read timeout")
        void shouldThrowExceptionForNegativeReadTimeout() {
            // Given
            var builder = WellKnownHandler.builder()
                    .url("https://example.com/.well-known/openid-configuration");

            // When & Then
            assertThrows(IllegalArgumentException.class, () -> builder.readTimeoutSeconds(-1), "Should throw IllegalArgumentException for negative read timeout");
        }

        @Test
        @DisplayName("Should use all builder methods together")
        void shouldUseAllBuilderMethodsTogether(URIBuilder uriBuilder) throws Exception {
            // Given
            URL wellKnownUrl = URI.create(uriBuilder
                    .addPathSegment("/.well-known/openid-configuration")
                    .buildAsString()).toURL();

            // Create a custom SecureSSLContextProvider
            SecureSSLContextProvider secureSSLContextProvider = new SecureSSLContextProvider(SecureSSLContextProvider.TLS_V1_3);

            // Create a custom SSLContext with proper initialization
            SSLContext sslContext = SSLContext.getInstance(SecureSSLContextProvider.TLS_V1_2);
            sslContext.init(null, null, new SecureRandom());

            // Create a custom ParserConfig
            ParserConfig parserConfig = ParserConfig.builder()
                    .maxStringSize(2048)
                    .maxArraySize(32)
                    .maxDepth(5)
                    .build();

            // When
            WellKnownHandler handler = WellKnownHandler.builder()
                    .url(wellKnownUrl)
                    .connectTimeoutSeconds(20)
                    .readTimeoutSeconds(40)
                    .tlsVersions(secureSSLContextProvider)
                    .sslContext(sslContext)
                    .parserConfig(parserConfig)
                    .build();

            // Then
            assertNotNull(handler, "Handler should not be null");
            assertEquals(wellKnownUrl, handler.getWellKnownUrl(), "Well-known URL should match");

            // Verify the dispatcher was called
            wellKnownDispatcher.assertCallsAnswered(1);

            // Verify that the handler was created successfully
            assertNotNull(handler.getJwksUri(), "JWKS URI should not be null");
            assertNotNull(handler.getIssuer(), "Issuer should not be null");
            assertNotNull(handler.getAuthorizationEndpoint(), "Authorization endpoint should not be null");
            assertNotNull(handler.getTokenEndpoint(), "Token endpoint should not be null");
        }
    }
}
