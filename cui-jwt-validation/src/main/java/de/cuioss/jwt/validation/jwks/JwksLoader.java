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

import de.cuioss.jwt.validation.jwks.key.KeyInfo;

import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Interface for loading JSON Web Keys (JWK) from a JWKS source.
 * <p>
 * Implementations can load keys from different sources like HTTP endpoints or files.
 * <p>
 * This interface supports cryptographic agility by providing methods to get keys
 * along with their algorithm information.
 * <p>
 * Usage examples:
 * <p>
 * File-based JWKS loader:
 * <pre>
 * // Create a file-based JWKS loader
 * String jwksFilePath = "/path/to/jwks.json";
 * SecurityEventCounter securityEventCounter = new SecurityEventCounter();
 * JwksLoader fileJwksLoader = JwksLoaderFactory.createFileLoader(jwksFilePath, securityEventCounter);
 * 
 * // Get a key by ID
 * String keyId = "my-key-id";
 * Optional&lt;KeyInfo&gt; keyInfo = fileJwksLoader.getKeyInfo(keyId);
 * 
 * // Use the key if present
 * keyInfo.ifPresent(info -> {
 *     PublicKey publicKey = info.getKey();
 *     String algorithm = info.getAlgorithm();
 *     // Use the key for signature verification
 * });
 * </pre>
 * <p>
 * HTTP-based JWKS loader:
 * <pre>
 * // Create an HTTP-based JWKS loader with 60-second refresh interval
 * String jwksEndpoint = "https://example.com/.well-known/jwks.json";
 * HttpJwksLoaderConfig config = HttpJwksLoaderConfig.builder()
 *     .url(jwksEndpoint)
 *     .refreshIntervalSeconds(60)
 *     .build();
 * SecurityEventCounter securityEventCounter = new SecurityEventCounter();
 * JwksLoader httpJwksLoader = JwksLoaderFactory.createHttpLoader(config, securityEventCounter);
 * 
 * // Get a key by ID
 * Optional&lt;KeyInfo&gt; keyInfo = httpJwksLoader.getKeyInfo("my-key-id");
 * 
 * // Get the first available key
 * Optional&lt;KeyInfo&gt; firstKey = httpJwksLoader.getFirstKeyInfo();
 * 
 * // Get all available key IDs
 * Set&lt;String&gt; keyIds = httpJwksLoader.keySet();
 * </pre>
 * <p>
 * In-memory JWKS loader:
 * <pre>
 * // Create an in-memory JWKS loader
 * String jwksContent = "{\"keys\":[{\"kty\":\"RSA\",\"kid\":\"my-key-id\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"...\",\"e\":\"...\"}]}";
 * SecurityEventCounter securityEventCounter = new SecurityEventCounter();
 * JwksLoader inMemoryJwksLoader = JwksLoaderFactory.createInMemoryLoader(jwksContent, securityEventCounter);
 * 
 * // Get all available keys
 * List&lt;KeyInfo&gt; allKeys = inMemoryJwksLoader.getAllKeyInfos();
 * </pre>
 * <p>
 * For more details on the security aspects, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/security.adoc">Security Specification</a>
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
@SuppressWarnings("JavadocLinkAsPlainText")
public interface JwksLoader {

    /**
     * Gets a key by its ID.
     *
     * @param kid the key ID
     * @return an Optional containing the key info if found, empty otherwise
     */
    Optional<KeyInfo> getKeyInfo(String kid);

    /**
     * Gets the first available key.
     *
     * @return an Optional containing the first key info if available, empty otherwise
     */
    Optional<KeyInfo> getFirstKeyInfo();

    /**
     * Gets all available keys with their algorithms.
     *
     * @return a List containing all available key infos
     */
    List<KeyInfo> getAllKeyInfos();

    /**
     * Gets the set of all available key IDs.
     *
     * @return a Set containing all available key IDs
     */
    Set<String> keySet();

    /**
     * Gets the type of JWKS source used by this loader.
     *
     * @return the JWKS source type
     */
    JwksType getJwksType();

    /**
     * Gets the status of the JWKS loader.
     * <p>
     * A loader status is OK if it can load at least one key.
     *
     * @return the status of the loader
     */
    LoaderStatus getStatus();

}
