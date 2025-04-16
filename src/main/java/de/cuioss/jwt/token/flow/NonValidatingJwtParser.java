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

import de.cuioss.jwt.token.JWTTokenLogMessages;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.string.MoreStrings;
import jakarta.json.Json;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import jakarta.json.JsonReaderFactory;
import lombok.AccessLevel;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.ToString;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

/**
 * This class provides a unified way to parse JWT tokens and extract common information
 * such as the header, body, signature, issuer, and kid-header.
 * <p>
 * Security features:
 * <ul>
 *   <li>Token size validation to prevent memory exhaustion</li>
 *   <li>Payload size validation for JSON parsing</li>
 *   <li>Standard Base64 decoding for JWT parts</li>
 *   <li>Proper character encoding handling</li>
 *   <li>JSON depth limits to prevent stack overflow attacks</li>
 *   <li>JSON array size limits to prevent denial of service attacks</li>
 *   <li>JSON string size limits to prevent memory exhaustion</li>
 * </ul>
 * <p>
 * Basic usage example:
 * <pre>
 * // Create a parser with default settings
 * NonValidatingJwtParser parser = NonValidatingJwtParser.builder().build();
 * 
 * // Decode a JWT token
 * Optional&lt;DecodedJwt&gt; decodedJwt = parser.decode(tokenString);
 * 
 * // Access decoded JWT information
 * decodedJwt.ifPresent(jwt -> {
 *     // Access header information
 *     jwt.getHeader().ifPresent(header -> {
 *         String algorithm = header.getString("alg");
 *         String tokenType = header.getString("typ");
 *     });
 *     
 *     // Access payload information
 *     jwt.getBody().ifPresent(body -> {
 *         String subject = body.getString("sub");
 *         String issuer = body.getString("iss");
 *         int expirationTime = body.getInt("exp");
 *     });
 *     
 *     // Access common JWT fields with convenience methods
 *     jwt.getIssuer().ifPresent(issuer -> System.out.println("Issuer: " + issuer));
 *     jwt.getKid().ifPresent(kid -> System.out.println("Key ID: " + kid));
 *     
 *     // Get the raw token
 *     String rawToken = jwt.getRawToken();
 * });
 * </pre>
 * <p>
 * Example with custom security settings:
 * <pre>
 * // Create a parser with custom security settings
 * NonValidatingJwtParser customParser = NonValidatingJwtParser.builder()
 *     .maxTokenSize(1024)  // 1KB max token size
 *     .maxPayloadSize(512)  // 512 bytes max payload size
 *     .maxStringSize(256)   // 256 bytes max string size
 *     .maxArraySize(10)     // 10 elements max array size
 *     .maxDepth(5)          // 5 levels max JSON depth
 *     .logWarningsOnDecodeFailure(false)  // suppress warnings
 *     .build();
 *     
 * // Decode a token with the custom parser
 * Optional&lt;DecodedJwt&gt; result = customParser.decode(tokenString);
 * </pre>
 * <p>
 * Example handling empty or invalid tokens:
 * <pre>
 * // Handle empty or null tokens
 * Optional&lt;DecodedJwt&gt; emptyResult = parser.decode("");
 * assertFalse(emptyResult.isPresent());
 * 
 * // Handle invalid token format
 * Optional&lt;DecodedJwt&gt; invalidResult = parser.decode("invalid.token.format");
 * assertFalse(invalidResult.isPresent());
 * </pre>
 * <p>
 * Implements requirements: {@code CUI-JWT-8.1: Token Size Limits} and {@code CUI-JWT-8.2: Safe Parsing}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@ToString
@EqualsAndHashCode
@RequiredArgsConstructor(access = AccessLevel.PRIVATE)
@Builder
public class NonValidatingJwtParser {

    /**
     * Builder for configuring NonValidatingJwtParser with specific security settings.
     * <p>
     * You can use this builder to configure the parser with specific security settings:
     * <pre>
     * NonValidatingJwtParser parser = NonValidatingJwtParser.builder()
     *     .maxTokenSize(16 * 1024)  // 16KB
     *     .maxPayloadSize(8 * 1024)  // 8KB
     *     .logWarningsOnDecodeFailure(false)  // suppress warnings
     *     .build();
     * </pre>
     */
    @SuppressWarnings("java:S2094") // owolff: Suppressing SonarLint warning for builder class. Needed for javadoc
    public static class NonValidatingJwtParserBuilder {
        // Content generated by Lombok
    }

    private static final CuiLogger LOGGER = new CuiLogger(NonValidatingJwtParser.class);

    /**
     * Default maximum size of a JWT token in bytes to prevent overflow attacks.
     * 8KB as recommended by OAuth 2.0 JWT BCP Section 3.11.
     */
    public static final int DEFAULT_MAX_TOKEN_SIZE = 8 * 1024;

    /**
     * Default maximum size of decoded JSON payload in bytes.
     * 8KB as recommended by OAuth 2.0 JWT BCP Section 3.11.
     */
    public static final int DEFAULT_MAX_PAYLOAD_SIZE = 8 * 1024;

    /**
     * Default maximum string size for JSON parsing.
     */
    public static final int DEFAULT_MAX_STRING_SIZE = 4 * 1024;

    /**
     * Default maximum array size for JSON parsing.
     */
    public static final int DEFAULT_MAX_ARRAY_SIZE = 64;

    /**
     * Default maximum depth for JSON parsing.
     */
    public static final int DEFAULT_MAX_DEPTH = 10;

    /**
     * Maximum size of a JWT token in bytes to prevent overflow attacks.
     */
    @Builder.Default
    private final int maxTokenSize = DEFAULT_MAX_TOKEN_SIZE;

    /**
     * Maximum size of decoded JSON payload in bytes.
     */
    @Builder.Default
    private final int maxPayloadSize = DEFAULT_MAX_PAYLOAD_SIZE;

    /**
     * Maximum string size for JSON parsing.
     */
    @Builder.Default
    private final int maxStringSize = DEFAULT_MAX_STRING_SIZE;

    /**
     * Maximum array size for JSON parsing.
     */
    @Builder.Default
    private final int maxArraySize = DEFAULT_MAX_ARRAY_SIZE;

    /**
     * Maximum depth for JSON parsing.
     */
    @Builder.Default
    private final int maxDepth = DEFAULT_MAX_DEPTH;

    /**
     * Cached JsonReaderFactory with security settings.
     * This is lazily initialized to avoid unnecessary creation.
     */
    @Getter(lazy = true)
    private final JsonReaderFactory jsonReaderFactory = createJsonReaderFactory();

    /**
     * Creates a JsonReaderFactory with security settings.
     * This method is used by the lazy getter for jsonReaderFactory.
     *
     * @return a JsonReaderFactory configured with security settings
     */
    private JsonReaderFactory createJsonReaderFactory() {
        Map<String, Object> config = new HashMap<>();
        // Use the correct property names for Jakarta JSON API
        config.put("jakarta.json.stream.maxStringLength", maxStringSize);
        config.put("jakarta.json.stream.maxArraySize", maxArraySize);
        config.put("jakarta.json.stream.maxDepth", maxDepth);
        return Json.createReaderFactory(config);
    }

    /**
     * Flag to control whether warnings are logged when decoding fails.
     * This is useful when checking if a token is a JWT without logging warnings.
     */
    @Builder.Default
    private final boolean logWarningsOnDecodeFailure = true;

    /**
     * Decodes a JWT token and returns a DecodedJwt object containing the decoded parts.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     *
     * @param token the JWT token string to parse
     * @return an Optional containing the DecodedJwt if parsing is successful,
     * or empty if the token is invalid or cannot be parsed
     */
    public Optional<DecodedJwt> decode(String token) {
        return decode(token, logWarningsOnDecodeFailure);
    }

    /**
     * Decodes a JWT token and returns a DecodedJwt object containing the decoded parts.
     * <p>
     * Security considerations:
     * <ul>
     *   <li>Does not validate signatures - use only for inspection</li>
     *   <li>Implements size checks to prevent overflow attacks</li>
     *   <li>Uses standard Java Base64 decoder</li>
     * </ul>
     * <p>
     * This method allows controlling whether warnings are logged when decoding fails.
     * This is useful when checking if a token is a JWT without logging warnings.
     *
     * @param token the JWT token string to parse
     * @param logWarnings whether to log warnings when decoding fails
     * @return an Optional containing the DecodedJwt if parsing is successful,
     * or empty if the token is invalid or cannot be parsed
     */
    public Optional<DecodedJwt> decode(String token, boolean logWarnings) {
        if (MoreStrings.isEmpty(token)) {
            if (logWarnings) {
                LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_IS_EMPTY::format);
            }
            return Optional.empty();
        }

        if (token.getBytes(StandardCharsets.UTF_8).length > maxTokenSize) {
            if (logWarnings) {
                LOGGER.warn(JWTTokenLogMessages.WARN.TOKEN_SIZE_EXCEEDED.format(maxTokenSize));
            }
            return Optional.empty();
        }

        String[] parts = token.split("\\.");
        if (parts.length != 3) {
            if (logWarnings) {
                LOGGER.warn(JWTTokenLogMessages.WARN.INVALID_JWT_FORMAT.format(parts.length));
            }
            return Optional.empty();
        }

        try {
            // Decode the header (first part)
            Optional<JsonObject> headerOpt = decodeJsonPart(parts[0], logWarnings);
            if (headerOpt.isEmpty()) {
                if (logWarnings) {
                    LOGGER.warn(JWTTokenLogMessages.WARN.FAILED_TO_DECODE_HEADER::format);
                }
                return Optional.empty();
            }

            // Decode the payload (second part)
            Optional<JsonObject> bodyOpt = decodeJsonPart(parts[1], logWarnings);
            if (bodyOpt.isEmpty()) {
                if (logWarnings) {
                    LOGGER.warn(JWTTokenLogMessages.WARN.FAILED_TO_DECODE_PAYLOAD::format);
                }
                return Optional.empty();
            }

            // The signature part (third part) is kept as is
            String signature = parts[2];

            return Optional.of(new DecodedJwt(headerOpt.get(), bodyOpt.get(), signature, parts, token));
        } catch (Exception e) {
            if (logWarnings) {
                LOGGER.warn(e, JWTTokenLogMessages.WARN.FAILED_TO_PARSE_TOKEN.format(e.getMessage()));
            }
            return Optional.empty();
        }
    }

    /**
     * Decodes a Base64Url encoded JSON part of a JWT token.
     * Implements security measures to prevent JSON parsing attacks:
     * - JSON depth limits
     * - JSON object size limits
     * - Protection against duplicate keys
     *
     * @param encodedPart the Base64Url encoded part
     * @param logWarnings whether to log warnings when decoding fails
     * @return an Optional containing the decoded JsonObject, or empty if decoding fails
     */
    private Optional<JsonObject> decodeJsonPart(String encodedPart, boolean logWarnings) {
        try {
            byte[] decoded = Base64.getUrlDecoder().decode(encodedPart);

            if (decoded.length > maxPayloadSize) {
                if (logWarnings) {
                    LOGGER.warn(JWTTokenLogMessages.WARN.DECODED_PART_SIZE_EXCEEDED.format(maxPayloadSize));
                }
                return Optional.empty();
            }

            // Use the cached JsonReaderFactory with security settings
            try (JsonReader reader = getJsonReaderFactory()
                    .createReader(new StringReader(new String(decoded, StandardCharsets.UTF_8)))) {
                return Optional.of(reader.readObject());
            }
        } catch (Exception e) {
            if (logWarnings) {
                LOGGER.warn(e, JWTTokenLogMessages.WARN.FAILED_TO_DECODE_PART.format(e.getMessage()));
            }
            return Optional.empty();
        }
    }

}
