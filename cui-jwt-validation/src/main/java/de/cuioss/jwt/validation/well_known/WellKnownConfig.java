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

import lombok.Builder;
import lombok.Value;

/**
 * Configuration class for well-known endpoint operations.
 * <p>
 * This class provides configuration options for well-known endpoint discovery,
 * such as HTTP timeout settings and retry behavior.
 * <p>
 * This class is immutable and thread-safe.
 * <p>
 * Usage example:
 * <pre>
 * WellKnownConfig config = WellKnownConfig.builder()
 *     .connectTimeoutSeconds(5)
 *     .readTimeoutSeconds(10)
 *     .maxAttempts(3)
 *     .build();
 * </pre>
 * <p>
 * Implements requirements:
 * <ul>
 *   <li><a href="https://github.com/cuioss/cui-jwt/tree/main/doc/Requirements.adoc#CUI-JWT-4">CUI-JWT-4: Key Management</a></li>
 * </ul>
 * <p>
 * For more detailed specifications, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/well-known.adoc">Well-Known Discovery Specification</a>
 *
 * @since 1.0
 */
@Builder
@Value
public class WellKnownConfig {

    /**
     * Default connection timeout for well-known endpoint HTTP requests in seconds.
     */
    public static final int DEFAULT_CONNECT_TIMEOUT_SECONDS = 2;

    /**
     * Default read timeout for well-known endpoint HTTP requests in seconds.
     */
    public static final int DEFAULT_READ_TIMEOUT_SECONDS = 3;

    /**
     * Default maximum number of retry attempts for well-known endpoint requests.
     */
    public static final int DEFAULT_MAX_ATTEMPTS = 3;

    /**
     * Connection timeout for well-known endpoint HTTP requests in seconds.
     * This value determines how long to wait when establishing connections to
     * well-known OpenID configuration endpoints.
     */
    @Builder.Default
    int connectTimeoutSeconds = DEFAULT_CONNECT_TIMEOUT_SECONDS;

    /**
     * Read timeout for well-known endpoint HTTP requests in seconds.
     * This value determines how long to wait when reading data from
     * well-known OpenID configuration endpoints.
     */
    @Builder.Default
    int readTimeoutSeconds = DEFAULT_READ_TIMEOUT_SECONDS;

    /**
     * Maximum number of retry attempts for well-known endpoint requests.
     * This value determines how many times to retry failed requests before giving up.
     */
    @Builder.Default
    int maxAttempts = DEFAULT_MAX_ATTEMPTS;
}