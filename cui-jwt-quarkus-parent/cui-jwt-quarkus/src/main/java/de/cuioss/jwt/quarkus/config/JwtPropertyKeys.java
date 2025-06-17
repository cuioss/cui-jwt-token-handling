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
package de.cuioss.jwt.quarkus.config;

import lombok.experimental.UtilityClass;

/**
 * Constants for JWT property keys used in the cui-jwt-quarkus module.
 * <p>
 * This class follows the DSL-style nested constants pattern to organize
 * property keys in a hierarchical, discoverable manner.
 * </p>
 * <p>
 * All properties are prefixed with "cui.jwt".
 * </p>
 *
 * @since 1.0
 */
@UtilityClass
public final class JwtPropertyKeys {

    /**
     * The common prefix for all JWT properties.
     */
    public static final String PREFIX = "cui.jwt";
    public static final String DOT_JWKS = ".jwks";

    /**
     * Properties related to JWT parser configuration.
     */
    @UtilityClass
    public static final class PARSER {
        /**
         * Base path for parser configurations.
         */
        public static final String BASE = PREFIX + ".parser";

        /**
         * The expected audience claim value.
         */
        public static final String AUDIENCE = BASE + ".audience";

        /**
         * The leeway in seconds to allow for clock skew.
         */
        public static final String LEEWAY_SECONDS = BASE + ".leeway-seconds";

        /**
         * The maximum token size in bytes.
         */
        public static final String MAX_TOKEN_SIZE_BYTES = BASE + ".max-token-size-bytes";

        /**
         * Whether to validate the "nbf" (not before) claim.
         */
        public static final String VALIDATE_NOT_BEFORE = BASE + ".validate-not-before";

        /**
         * Whether to validate the "exp" (expiration) claim.
         */
        public static final String VALIDATE_EXPIRATION = BASE + ".validate-expiration";

        /**
         * Whether to validate the "iat" (issued at) claim.
         */
        public static final String VALIDATE_ISSUED_AT = BASE + ".validate-issued-at";

        /**
         * Comma-separated list of allowed signing algorithms.
         */
        public static final String ALLOWED_ALGORITHMS = BASE + ".allowed-algorithms";
    }

    /**
     * Properties related to JWT issuers configuration.
     */
    @UtilityClass
    public static final class ISSUERS {
        /**
         * Base path for issuer configurations.
         */
        public static final String BASE = PREFIX + ".issuers";

        /**
         * The issuer URL/identifier.
         */
        public static final String URL = BASE + ".url";

        /**
         * Location of the public key or certificate.
         */
        public static final String PUBLIC_KEY_LOCATION = BASE + ".public-key-location";

        /**
         * Whether this issuer configuration is enabled.
         */
        public static final String ENABLED = BASE + ".enabled";

        /**
         * Properties related to JWKS configuration.
         */
        @UtilityClass
        public static final class JWKS {
            /**
             * Base path for JWKS configurations.
             */
            public static final String BASE = ISSUERS.BASE + DOT_JWKS;

            /**
             * The URL of the JWKS endpoint.
             */
            public static final String URL = BASE + ".url";

            /**
             * The URL of the OpenID Connect discovery document.
             */
            public static final String WELL_KNOWN_URL = BASE + ".well-known-url";

            /**
             * The cache time-to-live in seconds.
             */
            public static final String CACHE_TTL_SECONDS = BASE + ".cache-ttl-seconds";

            /**
             * The refresh interval in seconds.
             */
            public static final String REFRESH_INTERVAL_SECONDS = BASE + ".refresh-interval-seconds";

            /**
             * The connection timeout in milliseconds.
             */
            public static final String CONNECTION_TIMEOUT_MS = BASE + ".connection-timeout-ms";

            /**
             * The read timeout in milliseconds.
             */
            public static final String READ_TIMEOUT_MS = BASE + ".read-timeout-ms";

            /**
             * The maximum number of retries.
             */
            public static final String MAX_RETRIES = BASE + ".max-retries";

            /**
             * Whether to use HTTP proxy settings from the system properties.
             */
            public static final String USE_SYSTEM_PROXY = BASE + ".use-system-proxy";
        }
    }

    /**
     * Properties related to health checks.
     */
    @UtilityClass
    public static final class HEALTH {
        /**
         * Base path for health check configurations.
         */
        public static final String BASE = PREFIX + ".health";

        /**
         * Whether health checks are enabled.
         */
        public static final String ENABLED = BASE + ".enabled";

        /**
         * Properties related to JWKS endpoint health checks.
         */
        @UtilityClass
        public static final class JWKS {
            /**
             * Base path for JWKS health check configurations.
             */
            public static final String BASE = HEALTH.BASE + DOT_JWKS;

            /**
             * The cache time-to-live in seconds for health check results.
             */
            public static final String CACHE_SECONDS = BASE + ".cache-seconds";

            /**
             * The timeout in seconds for JWKS endpoint connectivity checks.
             */
            public static final String TIMEOUT_SECONDS = BASE + ".timeout-seconds";
        }
    }

    /**
     * Properties related to metrics.
     */
    @UtilityClass
    public static final class METRICS {
        /**
         * Base path for metrics configurations.
         */
        public static final String BASE = PREFIX + ".validation";

        /**
         * Counter for validation errors by type.
         */
        public static final String VALIDATION_ERRORS = BASE + ".errors";

        /**
         * Base path for JWKS metrics.
         */
        public static final String JWKS_BASE = PREFIX + DOT_JWKS;

        /**
         * Gauge for JWKS cache size.
         */
        public static final String JWKS_CACHE_SIZE = JWKS_BASE + ".cache.size";
    }
}
