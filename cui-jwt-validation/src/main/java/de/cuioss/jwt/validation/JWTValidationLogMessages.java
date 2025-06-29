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

import de.cuioss.tools.logging.LogRecord;
import de.cuioss.tools.logging.LogRecordModel;
import lombok.experimental.UtilityClass;

/**
 * Provides logging messages for the cui-jwt-validation module.
 * All messages follow the format: JWTValidation-[identifier]: [message]
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-7">CUI-JWT-7: Logging</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-7.1">CUI-JWT-7.1: Structured Logging</a></li>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-7.2">CUI-JWT-7.2: Helpful Error Messages</a></li>
 * </ul>
 * <p>
 * For more detailed information about log messages, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/LogMessages.adoc">Log Messages Documentation</a>
 *
 * @since 1.0
 */
@UtilityClass
public final class JWTValidationLogMessages {

    private static final String PREFIX = "JWTValidation";

    /**
     * Contains debug-level log messages for informational and diagnostic purposes.
     * These messages are typically used for tracing program pipeline and providing
     * detailed information about normal operations.
     */
    @UtilityClass
    public static final class DEBUG {
        public static final LogRecord JWKS_URL_MISSING_SCHEME = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("JWKS URL '%s' seems to be missing a scheme, prepending 'https://'")
                .build();

        public static final LogRecord JWKS_URI_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Created JWKS URI '%s' from URL string '%s'")
                .build();

        public static final LogRecord INITIALIZED_JWKS_LOADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(3)
                .template("Initialized HttpJwksLoader with URL: %s, refresh interval: %s seconds")
                .build();

        public static final LogRecord RESOLVING_KEY_LOADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(4)
                .template("Resolving key loader for JWKS endpoint: %s")
                .build();

        public static final LogRecord REFRESHING_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(5)
                .template("Refreshing keys from JWKS endpoint: %s")
                .build();

        public static final LogRecord FETCHED_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(6)
                .template("Successfully fetched JWKS from URL: %s")
                .build();

        public static final LogRecord KEY_ID_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(7)
                .template("Key ID is null or empty")
                .build();

        public static final LogRecord KEY_NOT_FOUND_REFRESHING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(8)
                .template("Key with ID %s not found, refreshing keys")
                .build();

        public static final LogRecord RECEIVED_304_NOT_MODIFIED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(9)
                .template("Received 304 Not Modified response, using cached JWKS")
                .build();

        public static final LogRecord CONTENT_UNCHANGED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(10)
                .template("JWKS content unchanged, using existing key loader")
                .build();

        // Token creation success events
        public static final LogRecord ACCESS_TOKEN_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(11)
                .template("Successfully created access token")
                .build();

        public static final LogRecord ID_TOKEN_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(12)
                .template("Successfully created ID-Token")
                .build();

        public static final LogRecord REFRESH_TOKEN_CREATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(13)
                .template("Successfully created Refresh-Token")
                .build();

        // WellKnownHandler debug messages
        public static final LogRecord OPTIONAL_URL_FIELD_MISSING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(14)
                .template("Optional URL field '%s' is missing in discovery document from %s")
                .build();

        public static final LogRecord VALIDATING_ISSUER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(15)
                .template("Validating issuer: Document issuer='%s', WellKnown URL='%s'")
                .build();

        public static final LogRecord ISSUER_VALIDATION_SUCCESSFUL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(16)
                .template("Issuer validation successful for %s")
                .build();

        public static final LogRecord PERFORMING_ACCESSIBILITY_CHECK = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(17)
                .template("Performing accessibility check for %s URL: %s")
                .build();

        public static final LogRecord USING_HEAD_METHOD = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(18)
                .template("Using HEAD method for accessibility check")
                .build();

        public static final LogRecord ACCESSIBILITY_CHECK_SUCCESSFUL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(19)
                .template("Accessibility check for %s URL '%s' successful (HTTP %s)")
                .build();

        public static final LogRecord FETCHING_DISCOVERY_DOCUMENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(20)
                .template("Fetching OpenID Connect discovery document from: %s")
                .build();

        public static final LogRecord DISCOVERY_DOCUMENT_FETCHED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(21)
                .template("Successfully fetched discovery document: %s")
                .build();

    }

    /**
     * Contains error-level log messages for significant problems that require attention.
     * These messages indicate failures that impact functionality but don't necessarily
     * prevent the application from continuing to run.
     */
    @UtilityClass
    public static final class ERROR {
        public static final LogRecord SIGNATURE_VALIDATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(200)
                .template("Failed to validate validation signature: %s")
                .build();

        public static final LogRecord JWKS_CONTENT_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(201)
                .template("JWKS content size exceeds maximum allowed size (upperLimit=%s, actual=%s)")
                .build();

        public static final LogRecord JWKS_INVALID_JSON = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(202)
                .template("Failed to parse JWKS JSON: %s")
                .build();

        // WellKnownHandler error messages
        public static final LogRecord ISSUER_VALIDATION_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(203)
                .template("Issuer validation failed. Document issuer '%s' (normalized to base URL for .well-known: %s://%s%s%s) does not match the .well-known URL '%s'. Expected path for .well-known: '%s'. SchemeMatch=%s, HostMatch=%s, PortMatch=%s (IssuerPort=%s, WellKnownPort=%s), PathMatch=%s (WellKnownPath='%s')")
                .build();


        public static final LogRecord JWKS_LOAD_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(205)
                .template("Failed to load JWKS")
                .build();

        public static final LogRecord WELL_KNOWN_LOAD_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(206)
                .template("Failed to load well-known endpoints from: %s after %d attempts")
                .build();

        public static final LogRecord JWKS_LOADER_INIT_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(207)
                .template("Failed to initialize JWKS loader via well-known discovery for: %s")
                .build();
    }

    /**
     * Contains info-level log messages for general operational information.
     * These messages provide high-level information about the normal operation
     * of the application that is useful for monitoring.
     */
    @UtilityClass
    public static final class INFO {
        public static final LogRecord TOKEN_FACTORY_INITIALIZED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(1)
                .template("TokenValidator initialized with %s issuer configurations")
                .build();

        public static final LogRecord JWKS_LOADED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(2)
                .template("Successfully loaded and parsed JWKS from %s with %s keys")
                .build();


        public static final LogRecord JWKS_KEYS_UPDATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(23)
                .template("Keys updated due to data change - load state: %s")
                .build();

        public static final LogRecord JWKS_HTTP_LOADED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(24)
                .template("Successfully loaded JWKS from HTTP endpoint")
                .build();

        public static final LogRecord ISSUER_RECOVERED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(25)
                .template("Issuer %s recovered and moved to healthy state")
                .build();

        public static final LogRecord JWKS_BACKGROUND_REFRESH_STARTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(26)
                .template("Background JWKS refresh started with interval: %s seconds")
                .build();

        public static final LogRecord JWKS_BACKGROUND_REFRESH_UPDATED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(27)
                .template("Background JWKS refresh updated keys, load state: %s")
                .build();
    }

    /**
     * Contains warning-level log messages for potential issues that don't prevent
     * normal operation but may indicate problems. These messages highlight situations
     * that should be monitored or addressed to prevent future errors.
     */
    @UtilityClass
    public static final class WARN {
        public static final LogRecord TOKEN_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(100)
                .template("Token exceeds maximum size limit of %s bytes, validation will be rejected")
                .build();

        public static final LogRecord TOKEN_IS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(101)
                .template("The given validation was empty, request will be rejected")
                .build();


        public static final LogRecord KEY_NOT_FOUND = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(102)
                .template("No key found with ID: %s")
                .build();

        public static final LogRecord ISSUER_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(103)
                .template("Token issuer '%s' does not match expected issuer '%s'")
                .build();

        public static final LogRecord JWKS_FETCH_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(104)
                .template("Failed to fetch JWKS: HTTP %s")
                .build();

        public static final LogRecord JWKS_REFRESH_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(105)
                .template("Error refreshing JWKS: %s")
                .build();

        public static final LogRecord RSA_KEY_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(106)
                .template("Failed to parse RSA key with ID %s: %s")
                .build();

        public static final LogRecord EC_KEY_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(107)
                .template("Failed to parse EC key with ID %s: %s")
                .build();

        public static final LogRecord JWKS_JSON_PARSE_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(108)
                .template("Failed to parse JWKS JSON: %s")
                .build();

        public static final LogRecord FAILED_TO_DECODE_JWT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(109)
                .template("Failed to decode JWT Token")
                .build();


        public static final LogRecord INVALID_JWT_FORMAT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(110)
                .template("Invalid JWT Token format: expected 3 parts but got %s")
                .build();

        public static final LogRecord FAILED_TO_DECODE_HEADER = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(110)
                .template("Failed to decode header part")
                .build();

        public static final LogRecord FAILED_TO_DECODE_PAYLOAD = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(111)
                .template("Failed to decode payload part")
                .build();


        public static final LogRecord DECODED_PART_SIZE_EXCEEDED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(112)
                .template("Decoded part exceeds maximum size limit of %s bytes")
                .build();


        public static final LogRecord FAILED_TO_FETCH_JWKS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(113)
                .template("Failed to fetch JWKS from URL: %s")
                .build();

        public static final LogRecord UNSUPPORTED_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(114)
                .template("Unsupported algorithm: %s")
                .build();


        public static final LogRecord JWKS_MISSING_KEYS = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(115)
                .template("JWKS JSON does not contain 'keys' array or 'kty' field")
                .build();

        public static final LogRecord JWK_MISSING_KTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(116)
                .template("JWK is missing required field 'kty'")
                .build();

        public static final LogRecord TOKEN_NBF_FUTURE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(117)
                .template("Token has a 'not before' claim that is more than 60 seconds in the future")
                .build();

        public static final LogRecord UNKNOWN_TOKEN_TYPE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(118)
                .template("Unknown validation type: %s")
                .build();

        public static final LogRecord FAILED_TO_READ_JWKS_FILE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(119)
                .template("Failed to read JWKS from file: %s")
                .build();

        public static final LogRecord MISSING_CLAIM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(120)
                .template("Token is missing required claim: %s")
                .build();

        public static final LogRecord FALLBACK_TO_LAST_VALID_JWKS_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(121)
                .template("New JWKS response has no valid keys, falling back to previous valid keys")
                .build();

        public static final LogRecord FALLBACK_TO_LAST_VALID_JWKS_EXCEPTION = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(122)
                .template("Falling back to last valid JWKS due to exception: %s")
                .build();

        public static final LogRecord TOKEN_EXPIRED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(123)
                .template("Token has expired")
                .build();


        public static final LogRecord AZP_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(124)
                .template("Token authorized party '%s' does not match expected client ID '%s'")
                .build();

        public static final LogRecord MISSING_RECOMMENDED_ELEMENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(125)
                .template("Missing recommended element: %s")
                .build();

        public static final LogRecord AUDIENCE_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(126)
                .template("Token audience %s does not match any of the expected audiences %s")
                .build();

        public static final LogRecord NO_ISSUER_CONFIG = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(127)
                .template("No configuration found for issuer: %s")
                .build();

        public static final LogRecord INVALID_BASE64_CONTENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(128)
                .template("Given contentKey '%s' does not resolve to a non base64 encoded String, actual content = %s")
                .build();

        public static final LogRecord ALGORITHM_REJECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(129)
                .template("Algorithm %s is explicitly rejected for security reasons")
                .build();

        public static final LogRecord KEY_ROTATION_DETECTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(130)
                .template("Key rotation detected: JWKS content has changed")
                .build();

        public static final LogRecord ACCESSIBILITY_CHECK_HTTP_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(131)
                .template("Accessibility check for %s URL '%s' returned HTTP status %s. It might be inaccessible.")
                .build();

        public static final LogRecord JWKS_FETCH_HTTP_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(132)
                .template("Fetching JWKS from %s failed: HTTP status %s")
                .build();

        public static final LogRecord JWKS_REFRESH_HTTP_ERROR = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(133)
                .template("Refreshing JWKS from %s failed: HTTP status %s")
                .build();

        public static final LogRecord JWKS_URL_MALFORMED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(134)
                .template("JWKS URL '%s' is malformed")
                .build();

        public static final LogRecord INVALID_JWKS_URI = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(135)
                .template("Creating HttpJwksLoaderConfig with invalid JWKS URI. The loader will return empty results.")
                .build();

        public static final LogRecord JWKS_LOAD_FAILED_CACHED_CONTENT = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(136)
                .template("Load operation failed but using cached content")
                .build();

        public static final LogRecord JWKS_LOAD_FAILED_NO_CACHE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(137)
                .template("Load operation failed with no cached content available")
                .build();

        public static final LogRecord ISSUER_DUAL_MAP_MISMATCH = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(138)
                .template("Issuer %s exists in configuration but not in dual maps - performing health check")
                .build();

        public static final LogRecord JWK_KEY_MISSING_KTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(139)
                .template("Key missing required 'kty' parameter")
                .build();

        public static final LogRecord JWK_UNSUPPORTED_KEY_TYPE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(140)
                .template("Unsupported key type: %s")
                .build();

        public static final LogRecord JWK_KEY_ID_TOO_LONG = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(141)
                .template("Key ID exceeds maximum length: %s")
                .build();

        public static final LogRecord JWK_INVALID_ALGORITHM = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(142)
                .template("Invalid or unsupported algorithm: %s")
                .build();

        public static final LogRecord JWKS_OBJECT_NULL = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(143)
                .template("JWKS object is null")
                .build();

        public static final LogRecord JWKS_EXCESSIVE_PROPERTIES = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(144)
                .template("JWKS object has excessive number of properties: %s")
                .build();

        public static final LogRecord JWKS_KEYS_ARRAY_TOO_LARGE = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(145)
                .template("JWKS keys array exceeds maximum size: %s")
                .build();

        public static final LogRecord JWKS_KEYS_ARRAY_EMPTY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(146)
                .template("JWKS keys array is empty")
                .build();

        public static final LogRecord OPERATION_RETRY_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(147)
                .template("Operation %s failed after %d attempts")
                .build();

        public static final LogRecord HTTP_STATUS_WARNING = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(148)
                .template("HTTP %s (%s) from %s")
                .build();

        public static final LogRecord HTTP_FETCH_FAILED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(149)
                .template("Failed to fetch HTTP content from %s")
                .build();

        public static final LogRecord HTTP_FETCH_INTERRUPTED = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(150)
                .template("Interrupted while fetching HTTP content from %s")
                .build();

        public static final LogRecord JWKS_LOADER_NOT_HEALTHY = LogRecordModel.builder()
                .prefix(PREFIX)
                .identifier(151)
                .template("Delegate JWKS loader initialized but not healthy for: %s")
                .build();
    }

}
