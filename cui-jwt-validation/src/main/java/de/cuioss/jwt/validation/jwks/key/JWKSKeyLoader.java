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
package de.cuioss.jwt.validation.jwks.key;

import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.parser.JwksParser;
import de.cuioss.jwt.validation.jwks.parser.KeyProcessor;
import de.cuioss.jwt.validation.security.JwkAlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.security.SecurityEventCounter.EventType;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;

import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a string content.
 * <p>
 * This implementation is useful when the JWKS content is already available as a string.
 * <p>
 * This implementation supports cryptographic agility by handling multiple key types
 * and algorithms, including RSA, EC, and RSA-PSS.
 * <p>
 * The class stores the original JWKS content string and the ETag value from HTTP responses
 * to support content-based caching and HTTP 304 "Not Modified" handling in HttpJwksLoader.
 * <p>
 * Security features:
 * <ul>
 *   <li>JWKS content size validation to prevent memory exhaustion attacks</li>
 *   <li>Secure JSON parsing with limits on string size, array size, and depth</li>
 *   <li>Security event tracking for monitoring and alerting</li>
 * </ul>
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/security.adoc">Security Specification</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@ToString(of = {"keyInfoMap", "originalString", "etag", "parserConfig", "securityEventCounter"})
@EqualsAndHashCode(of = {"keyInfoMap", "originalString", "etag", "parserConfig", "securityEventCounter"})
public class JWKSKeyLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(JWKSKeyLoader.class);

    @NonNull
    private final String originalString;
    private final String etag;
    private final ParserConfig parserConfig;
    @NonNull
    private final SecurityEventCounter securityEventCounter;
    @NonNull
    private final JwkAlgorithmPreferences jwkAlgorithmPreferences;
    @NonNull
    private final JwksType jwksType;
    @NonNull
    private final LoaderStatus status;
    private final Map<String, KeyInfo> keyInfoMap;

    /**
     * Builder for JWKSKeyLoader.
     */
    public static class JWKSKeyLoaderBuilder {
        private String originalString;
        private String etag;
        private ParserConfig parserConfig = ParserConfig.builder().build();
        private SecurityEventCounter securityEventCounter;
        private JwkAlgorithmPreferences jwkAlgorithmPreferences = new JwkAlgorithmPreferences(); // Default instance
        private JwksType jwksType = JwksType.MEMORY; // Default to MEMORY type

        JWKSKeyLoaderBuilder() {
        }

        /**
         * Sets the original JWKS content string.
         *
         * @param originalString the JWKS content as a string
         * @return this builder
         */
        public JWKSKeyLoaderBuilder originalString(String originalString) {
            this.originalString = originalString;
            return this;
        }

        /**
         * Sets the ETag value.
         *
         * @param etag the ETag value
         * @return this builder
         */
        public JWKSKeyLoaderBuilder etag(String etag) {
            this.etag = etag;
            return this;
        }

        /**
         * Sets the parser configuration.
         *
         * @param parserConfig the parser configuration
         * @return this builder
         */
        public JWKSKeyLoaderBuilder parserConfig(ParserConfig parserConfig) {
            this.parserConfig = parserConfig != null ? parserConfig : ParserConfig.builder().build();
            return this;
        }

        /**
         * Sets the security event counter.
         *
         * @param securityEventCounter the security event counter
         * @return this builder
         */
        public JWKSKeyLoaderBuilder securityEventCounter(SecurityEventCounter securityEventCounter) {
            this.securityEventCounter = securityEventCounter;
            return this;
        }

        /**
         * Sets the JWK algorithm preferences.
         *
         * @param jwkAlgorithmPreferences the JWK algorithm preferences
         * @return this builder
         */
        public JWKSKeyLoaderBuilder jwkAlgorithmPreferences(JwkAlgorithmPreferences jwkAlgorithmPreferences) {
            this.jwkAlgorithmPreferences = jwkAlgorithmPreferences != null ? jwkAlgorithmPreferences : new JwkAlgorithmPreferences();
            return this;
        }

        /**
         * Sets the JWKS source type.
         *
         * @param jwksType the JWKS source type
         * @return this builder
         */
        public JWKSKeyLoaderBuilder jwksType(JwksType jwksType) {
            this.jwksType = jwksType;
            return this;
        }

        /**
         * Builds a new JWKSKeyLoader.
         *
         * @return a new JWKSKeyLoader
         */
        public JWKSKeyLoader build() {
            if (originalString == null) {
                throw new IllegalArgumentException("originalString must not be null");
            }
            if (securityEventCounter == null) {
                throw new IllegalArgumentException("securityEventCounter must not be null");
            }
            try {
                return new JWKSKeyLoader(originalString, etag, parserConfig, securityEventCounter, jwkAlgorithmPreferences, jwksType);
            } catch (JsonException | IllegalStateException | IllegalArgumentException e) {
                // If an exception occurs during construction, log it and return an empty JWKSKeyLoader
                LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return new JWKSKeyLoader("{}", etag, parserConfig != null ? parserConfig : ParserConfig.builder().build(), securityEventCounter, jwkAlgorithmPreferences != null ? jwkAlgorithmPreferences : new JwkAlgorithmPreferences(), jwksType);
            }
        }
    }

    /**
     * Creates a new builder for JWKSKeyLoader.
     *
     * @return a new builder
     */
    public static JWKSKeyLoaderBuilder builder() {
        return new JWKSKeyLoaderBuilder();
    }


    /**
     * Creates a new JWKSKeyLoader with the specified JWKS content, ETag, ParserConfig, SecurityEventCounter, and JwkAlgorithmPreferences.
     *
     * @param originalString the JWKS content as a string, must not be null
     * @param etag        the ETag value from the HTTP response, may be null
     * @param parserConfig the configuration for parsing, may be null (defaults to a new instance)
     * @param securityEventCounter the counter for security events, must not be null
     * @param jwkAlgorithmPreferences the JWK algorithm preferences for parsing validation, must not be null
     * @param jwksType the type of JWKS source, must not be null
     */
    public JWKSKeyLoader(
            @NonNull String originalString,
            String etag,
            ParserConfig parserConfig,
            @NonNull SecurityEventCounter securityEventCounter,
            @NonNull JwkAlgorithmPreferences jwkAlgorithmPreferences,
            @NonNull JwksType jwksType) {
        this.originalString = originalString;
        this.etag = etag;
        this.parserConfig = parserConfig != null ? parserConfig : ParserConfig.builder().build();
        this.securityEventCounter = securityEventCounter;
        this.jwkAlgorithmPreferences = jwkAlgorithmPreferences;
        this.jwksType = jwksType;

        ParseResult result = parseJwksContent(originalString);
        this.keyInfoMap = result.keyInfoMap();
        this.status = result.status();
    }


    private ParseResult parseJwksContent(String originalString) {
        // Create parser components
        JwksParser parser = new JwksParser(parserConfig, securityEventCounter);
        KeyProcessor processor = new KeyProcessor(securityEventCounter, jwkAlgorithmPreferences);

        // Parse JWKS content to get individual JWK objects (includes structure validation)
        List<JsonObject> jwkObjects = parser.parse(originalString);

        // Process each key (includes key parameter validation)
        Map<String, KeyInfo> keyMap = new ConcurrentHashMap<>();
        for (JsonObject jwk : jwkObjects) {
            var keyInfoOpt = processor.processKey(jwk);
            if (keyInfoOpt.isPresent()) {
                KeyInfo keyInfo = keyInfoOpt.get();
                keyMap.put(keyInfo.keyId(), keyInfo);
            }
        }

        LoaderStatus status = keyMap.isEmpty() ? LoaderStatus.ERROR : LoaderStatus.OK;
        return new ParseResult(keyMap, status);
    }

    private record ParseResult(Map<String, KeyInfo> keyInfoMap, LoaderStatus status) {
    }

    /**
     * Checks if this loader contains valid keys.
     *
     * @return true if the loader contains at least one valid key, false otherwise
     */
    public boolean isNotEmpty() {
        return !keyInfoMap.isEmpty();
    }


    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        if (MoreStrings.isBlank(kid)) {
            LOGGER.debug("Key ID is null or empty");
            return Optional.empty();
        }

        return Optional.ofNullable(keyInfoMap.get(kid));
    }

    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        if (keyInfoMap.isEmpty()) {
            return Optional.empty();
        }
        // Return the first key info in the map
        return Optional.of(keyInfoMap.values().iterator().next());
    }

    @Override
    public List<KeyInfo> getAllKeyInfos() {
        return new ArrayList<>(keyInfoMap.values());
    }

    @Override
    public Set<String> keySet() {
        return keyInfoMap.keySet();
    }

    /**
     * Gets the type of JWKS source used by this loader.
     *
     * @return the JWKS source type
     */
    @Override
    public @NonNull JwksType getJwksType() {
        return jwksType;
    }

    /**
     * Gets the status of the JWKS loader.
     *
     * @return the status of the loader
     */
    @Override
    public @NonNull LoaderStatus getStatus() {
        return status;
    }

    /**
     * Checks if the JWKS loader is healthy and can access at least one cryptographic key.
     * <p>
     * For in-memory and file-based loaders, this checks if keys were successfully parsed
     * during construction and are currently available.
     *
     * @return {@code true} if the loader can access at least one key, {@code false} otherwise
     */
    @Override
    public boolean isHealthy() {
        return status == LoaderStatus.OK && !keyInfoMap.isEmpty();
    }


}
