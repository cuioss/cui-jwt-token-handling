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
package de.cuioss.jwt.validation.jwks;

import de.cuioss.jwt.validation.JWTValidationLogMessages;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoader;
import de.cuioss.jwt.validation.jwks.http.HttpJwksLoaderConfig;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.JsonException;
import lombok.NonNull;
import lombok.experimental.UtilityClass;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Factory for creating instances of {@link JwksLoader}.
 * <p>
 * Key features:
 * <ul>
 *   <li>Creates appropriate loader based on the JWKS URL</li>
 *   <li>Supports HTTP and file-based JWKS sources</li>
 *   <li>Integrates with SecurityEventCounter for security event tracking</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * // Create a SecurityEventCounter for tracking security events
 * SecurityEventCounter securityEventCounter = new SecurityEventCounter();
 * 
 * // Configure and create an HTTP-based JWKS loader
 * HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
 *     .url("https://auth.example.com/.well-known/jwks.json")
 *     .refreshIntervalSeconds(60)
 *     .build();
 * JwksLoader loader = JwksLoaderFactory.createHttpLoader(config, securityEventCounter);
 * 
 * // Get a key by ID
 * Optional&lt;KeyInfo&gt; keyInfo = loader.getKeyInfo("kid123");
 * </pre>
 * <p>
 * See specification: <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/technical-components.adoc#_jwksloader">Technical Components Specification - JwksLoader</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@UtilityClass
public class JwksLoaderFactory {

    private static final CuiLogger LOGGER = new CuiLogger(JwksLoaderFactory.class);


    /**
     * Creates a JwksLoader that loads JWKS from an HTTP endpoint.
     *
     * @param config               the configuration for the HTTP JWKS loader
     * @param securityEventCounter the counter for security events
     * @return an instance of JwksLoader
     */
    public static JwksLoader createHttpLoader(@NonNull HttpJwksLoaderConfig config, @NonNull SecurityEventCounter securityEventCounter) {
        return new HttpJwksLoader(config, securityEventCounter);
    }


    /**
     * Creates a JwksLoader that loads JWKS from a file.
     *
     * @param filePath             the path to the JWKS file
     * @param securityEventCounter the counter for security events
     * @return an instance of JwksLoader
     */
    public static JwksLoader createFileLoader(@NonNull String filePath, @NonNull SecurityEventCounter securityEventCounter) {
        LOGGER.debug("Resolving key loader for JWKS file: %s", filePath);
        try {
            String jwksContent = new String(Files.readAllBytes(Path.of(filePath)));
            LOGGER.debug("Successfully read JWKS from file: %s", filePath);
            JWKSKeyLoader keyLoader = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .securityEventCounter(securityEventCounter)
                    .jwksType(JwksType.FILE)
                    .build();
            LOGGER.debug("Successfully loaded %s keys", keyLoader.keySet().size());
            return keyLoader;
        } catch (IOException e) {
            LOGGER.warn(e, JWTValidationLogMessages.WARN.FAILED_TO_READ_JWKS_FILE.format(filePath));
            securityEventCounter.increment(SecurityEventCounter.EventType.FAILED_TO_READ_JWKS_FILE);
            return JWKSKeyLoader.builder()
                    .originalString("{}")
                    .securityEventCounter(securityEventCounter)
                    .jwksType(JwksType.FILE)
                    .build(); // Empty JWKS
        }
    }

    /**
     * Creates a JwksLoader that loads JWKS from in-memory string content.
     *
     * @param jwksContent          the JWKS content as a string
     * @param securityEventCounter the counter for security events
     * @return an instance of JwksLoader
     */
    public static JwksLoader createInMemoryLoader(@NonNull String jwksContent, @NonNull SecurityEventCounter securityEventCounter) {
        LOGGER.debug("Resolving key loader for in-memory JWKS data");
        try {
            JWKSKeyLoader keyLoader = JWKSKeyLoader.builder()
                    .originalString(jwksContent)
                    .securityEventCounter(securityEventCounter)
                    .jwksType(JwksType.MEMORY)
                    .build();
            LOGGER.debug("Successfully loaded %s key(s)", keyLoader.keySet().size());
            return keyLoader;
        } catch (JsonException | IllegalArgumentException e) {
            LOGGER.warn(e, JWTValidationLogMessages.WARN.JWKS_JSON_PARSE_FAILED.format(e.getMessage()));
            securityEventCounter.increment(SecurityEventCounter.EventType.JWKS_JSON_PARSE_FAILED);
            return JWKSKeyLoader.builder()
                    .originalString("{}")
                    .securityEventCounter(securityEventCounter)
                    .jwksType(JwksType.MEMORY)
                    .build(); // Empty JWKS
        }
    }

}
