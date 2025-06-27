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

import de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR;
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.security.SecurityEventCounter.EventType;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.NonNull;
import lombok.ToString;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.security.spec.InvalidKeySpecException;
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
 * to support content-based caching and HTTP 304 "Not Modified" handling in {@link HttpJwksLoader}.
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
    private static final String RSA_KEY_TYPE = "RSA";
    private static final String EC_KEY_TYPE = "EC";

    @Getter
    @NonNull
    private final String originalString;
    @Getter
    private final String etag;
    @Getter
    private final ParserConfig parserConfig;
    @Getter
    @NonNull
    private final SecurityEventCounter securityEventCounter;
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
            this.parserConfig = parserConfig;
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
                return new JWKSKeyLoader(originalString, etag, parserConfig, securityEventCounter, jwksType);
            } catch (JsonException | IllegalStateException | IllegalArgumentException e) {
                // If an exception occurs during construction, log it and return an empty JWKSKeyLoader
                LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return new JWKSKeyLoader("{}", etag, parserConfig, securityEventCounter, jwksType);
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
     * Creates a new JWKSKeyLoader with the specified JWKS content, ETag, ParserConfig, and SecurityEventCounter.
     *
     * @param originalString the JWKS content as a string, must not be null
     * @param etag        the ETag value from the HTTP response, may be null
     * @param parserConfig the configuration for parsing, may be null (defaults to a new instance)
     * @param securityEventCounter the counter for security events, must not be null
     * @param jwksType the type of JWKS source, must not be null
     */
    public JWKSKeyLoader(
            @NonNull String originalString,
            String etag,
            ParserConfig parserConfig,
            @NonNull SecurityEventCounter securityEventCounter,
            @NonNull JwksType jwksType) {
        this.originalString = originalString;
        this.etag = etag;
        this.parserConfig = parserConfig != null ? parserConfig : ParserConfig.builder().build();
        this.securityEventCounter = securityEventCounter;
        this.jwksType = jwksType;

        ParseResult result = parseJwksContent(originalString, securityEventCounter);
        this.keyInfoMap = result.keyInfoMap();
        this.status = result.status();
    }

    /**
     * Factory method to create a JWKS key loader with comprehensive validation.
     *
     * @param originalString       the JWKS JSON string
     * @param etag                 the ETag for caching (can be null)
     * @param parserConfig         the parser configuration (can be null, will use default)
     * @param securityEventCounter the security event counter for tracking events
     * @param jwksType             the type of JWKS (file, HTTP, etc.)
     * @return a new JWKSKeyLoader instance
     * @throws IllegalArgumentException if originalString or securityEventCounter is null
     */
    public static JWKSKeyLoader create(
            @NonNull String originalString,
            String etag,
            ParserConfig parserConfig,
            @NonNull SecurityEventCounter securityEventCounter,
            @NonNull JwksType jwksType) {
        return new JWKSKeyLoader(originalString, etag, parserConfig, securityEventCounter, jwksType);
    }

    private ParseResult parseJwksContent(String originalString, SecurityEventCounter securityEventCounter) {
        try {
            Map<String, KeyInfo> parsedMap = parseJwks(originalString);
            LoaderStatus determinedStatus = parsedMap.isEmpty() ? LoaderStatus.ERROR : LoaderStatus.OK;
            return new ParseResult(parsedMap, determinedStatus);
        } catch (JsonException e) {
            LOGGER.warn(e, WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return new ParseResult(new ConcurrentHashMap<>(), LoaderStatus.ERROR);
        }
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

    /**
     * Parse JWKS content and extract keys.
     * Implements security measures to prevent JSON parsing attacks:
     * - JWKS content size validation
     * - JSON depth limits
     * - JSON object size limits
     * - Protection against duplicate keys
     * - Security event tracking for monitoring and alerting
     *
     * @param jwksContent the JWKS content as a string
     * @return a map of key IDs to key infos
     */
    private Map<String, KeyInfo> parseJwks(String jwksContent) {
        Map<String, KeyInfo> result = new ConcurrentHashMap<>();

        // Check if the JWKS content size exceeds the maximum allowed size
        int actualSize = jwksContent.getBytes(StandardCharsets.UTF_8).length;
        int upperLimit = parserConfig.getMaxPayloadSize();
        if (actualSize > upperLimit) {
            LOGGER.error(ERROR.JWKS_CONTENT_SIZE_EXCEEDED.format(upperLimit, actualSize));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return result;
        }

        try {
            // Use the JsonReaderFactory from ParserConfig with security settings
            try (JsonReader reader = parserConfig.getJsonReaderFactory()
                    .createReader(new StringReader(jwksContent))) {
                JsonObject jwks = reader.readObject();
                parseJsonWebKeySet(jwks, result);
            }
        } catch (JsonException e) {
            // Handle invalid JSON format
            LOGGER.error(e, ERROR.JWKS_INVALID_JSON.format(e.getMessage()));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
        }

        return result;
    }

    /**
     * Parse a JSON Web Key Set object and extract keys.
     * Enhanced with comprehensive validation:
     * - Validates JWKS structure and required fields
     * - Validates key parameters and algorithms
     * - Enforces size limits for security
     *
     * @param jwks   the JSON Web Key Set object
     * @param result the map to store the extracted keys
     */
    private void parseJsonWebKeySet(JsonObject jwks, Map<String, KeyInfo> result) {
        // Validate basic JWKS structure
        if (!validateJwksStructure(jwks)) {
            return;
        }

        // Check if this is a JWKS with a "keys" array or a single key
        if (JwkKeyConstants.Keys.isPresent(jwks)) {
            parseKeysArray(jwks, result);
        } else if (JwkKeyConstants.KeyType.isPresent(jwks)) {
            // This is a single key object
            processSingleKey(jwks, result);
        } else {
            LOGGER.warn(WARN.JWKS_MISSING_KEYS::format);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
        }
    }

    /**
     * Parse a standard JWKS with a "keys" array.
     *
     * @param jwks   the JWKS object
     * @param result the map to store the extracted keys
     */
    private void parseKeysArray(JsonObject jwks, Map<String, KeyInfo> result) {
        var keysArray = JwkKeyConstants.Keys.extract(jwks);
        if (keysArray.isPresent()) {
            for (int i = 0; i < keysArray.get().size(); i++) {
                JsonObject jwk = keysArray.get().getJsonObject(i);
                processSingleKey(jwk, result);
            }
        }
    }

    /**
     * Process a single JWK and add it to the result map.
     * Enhanced with comprehensive validation.
     *
     * @param jwk    the JWK object
     * @param result the map to store the extracted key
     */
    private void processSingleKey(JsonObject jwk, Map<String, KeyInfo> result) {
        // Validate key parameters first
        if (!validateKeyParameters(jwk)) {
            return;
        }

        var keyType = JwkKeyConstants.KeyType.getString(jwk);
        if (keyType.isEmpty()) {
            LOGGER.warn(WARN.JWK_MISSING_KTY::format);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return;
        }

        String kty = keyType.get();
        String kid = JwkKeyConstants.KeyId.from(jwk).orElse("default-key-id");

        KeyInfo keyInfo = switch (kty) {
            case RSA_KEY_TYPE -> processRsaKey(jwk, kid);
            case EC_KEY_TYPE -> processEcKey(jwk, kid);
            default -> {
                LOGGER.debug("Unsupported key type: %s for key ID: %s", kty, kid);
                yield null;
            }
        };

        if (keyInfo != null) {
            result.put(kid, keyInfo);
        }
    }

    /**
     * Process an RSA key and create a KeyInfo object.
     *
     * @param jwk the JWK object
     * @param kid the key ID
     * @return the KeyInfo object or null if processing failed
     */
    private KeyInfo processRsaKey(JsonObject jwk, String kid) {
        try {
            var publicKey = JwkKeyHandler.parseRsaKey(jwk);
            // Determine algorithm if not specified
            String alg = JwkKeyConstants.Algorithm.from(jwk).orElse("RS256");// Default to RS256 if not specified
            LOGGER.debug("Parsed RSA key with ID: %s and algorithm: %s", kid, alg);
            return new KeyInfo(publicKey, alg, kid);
        } catch (InvalidKeySpecException | IllegalStateException e) {
            LOGGER.warn(e, WARN.RSA_KEY_PARSE_FAILED.format(kid, e.getMessage()));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return null;
        }
    }

    /**
     * Process an EC key and create a KeyInfo object.
     *
     * @param jwk the JWK object
     * @param kid the key ID
     * @return the KeyInfo object or null if processing failed
     */
    private KeyInfo processEcKey(JsonObject jwk, String kid) {
        try {
            var publicKey = JwkKeyHandler.parseEcKey(jwk);
            // Determine algorithm if not specified
            var algOption = JwkKeyConstants.Algorithm.from(jwk);
            String alg = algOption.orElse(null);
            if (algOption.isEmpty()) {
                // Determine algorithm based on curve
                String curve = JwkKeyConstants.Curve.from(jwk).orElse("P-256");
                alg = JwkKeyHandler.determineEcAlgorithm(curve);
            }
            LOGGER.debug("Parsed EC key with ID: %s and algorithm: %s", kid, alg);
            return new KeyInfo(publicKey, alg, kid);
        } catch (InvalidKeySpecException | IllegalStateException e) {
            LOGGER.warn(e, WARN.RSA_KEY_PARSE_FAILED.format(kid, e.getMessage()));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return null;
        }
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
    public JwksType getJwksType() {
        return jwksType;
    }

    /**
     * Gets the status of the JWKS loader.
     *
     * @return the status of the loader
     */
    @Override
    public LoaderStatus getStatus() {
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

    /**
     * Validates the structure and content of a JWKS object.
     * This method performs comprehensive validation to prevent malformed
     * or malicious JWKS content from being processed.
     * 
     * @param jwks the JWKS object to validate
     * @return true if the JWKS structure is valid, false otherwise
     */
    private boolean validateJwksStructure(JsonObject jwks) {
        // Basic null check
        if (jwks == null) {
            LOGGER.warn("JWKS object is null");
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }

        // Check for excessive number of top-level properties
        if (jwks.size() > 10) {
            LOGGER.warn("JWKS object has excessive number of properties: {}", jwks.size());
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }

        // If it has a "keys" array, validate it
        if (JwkKeyConstants.Keys.isPresent(jwks)) {
            JsonArray keysArray = jwks.getJsonArray(JwkKeyConstants.Keys.KEY);

            // Check array size limits
            if (keysArray.size() > 50) {
                LOGGER.warn("JWKS keys array exceeds maximum size: {}", keysArray.size());
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return false;
            }

            if (keysArray.isEmpty()) {
                LOGGER.warn("JWKS keys array is empty");
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return false;
            }
        }

        return true;
    }

    /**
     * Validates individual key parameters and algorithms.
     * This method ensures that keys contain required fields and use
     * supported algorithms.
     * 
     * @param keyObject the individual key object to validate
     * @return true if the key is valid, false otherwise
     */
    private boolean validateKeyParameters(JsonObject keyObject) {
        // Validate required key type
        if (!JwkKeyConstants.KeyType.isPresent(keyObject)) {
            LOGGER.warn("Key missing required 'kty' parameter");
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }

        String keyType = keyObject.getString(JwkKeyConstants.KeyType.KEY);

        // Validate key type is supported
        if (!"RSA".equals(keyType) && !"EC".equals(keyType)) {
            LOGGER.warn("Unsupported key type: {}", keyType);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }

        // Validate key ID exists and is reasonable length
        if (keyObject.containsKey(JwkKeyConstants.KeyId.KEY)) {
            String keyId = keyObject.getString(JwkKeyConstants.KeyId.KEY);
            if (keyId.length() > 100) {
                LOGGER.warn("Key ID exceeds maximum length: {}", keyId.length());
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return false;
            }
        }

        // Validate algorithm if present
        if (keyObject.containsKey(JwkKeyConstants.Algorithm.KEY)) {
            String algorithm = keyObject.getString(JwkKeyConstants.Algorithm.KEY);
            if (!isValidAlgorithm(algorithm)) {
                LOGGER.warn("Invalid or unsupported algorithm: {}", algorithm);
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return false;
            }
        }

        return true;
    }

    /**
     * Validates if an algorithm is supported and secure.
     * 
     * @param algorithm the algorithm to validate
     * @return true if the algorithm is valid and supported
     */
    private boolean isValidAlgorithm(String algorithm) {
        return algorithm != null && (
                "RS256".equals(algorithm) || "RS384".equals(algorithm) || "RS512".equals(algorithm) ||
                        "ES256".equals(algorithm) || "ES384".equals(algorithm) || "ES512".equals(algorithm) ||
                        "PS256".equals(algorithm) || "PS384".equals(algorithm) || "PS512".equals(algorithm)
        );
    }
}
