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
package de.cuioss.jwt.validation.jwks.parser;

import de.cuioss.jwt.validation.jwks.key.JwkKeyConstants;
import de.cuioss.jwt.validation.security.JwkAlgorithmPreferences;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.security.SecurityEventCounter.EventType;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.JsonArray;
import jakarta.json.JsonObject;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

/**
 * Validates JWKS structure and individual key parameters.
 * This class is responsible for:
 * <ul>
 *   <li>Validating JWKS structure and size limits</li>
 *   <li>Validating individual key parameters</li>
 *   <li>Enforcing algorithm preferences</li>
 *   <li>Security event tracking for validation failures</li>
 * </ul>
 */
@RequiredArgsConstructor
public class JwksValidator {
    
    private static final CuiLogger LOGGER = new CuiLogger(JwksValidator.class);
    
    // Maximum number of top-level properties in JWKS
    private static final int MAX_JWKS_PROPERTIES = 10;
    
    // Maximum number of keys in JWKS array
    private static final int MAX_KEYS_IN_ARRAY = 50;
    
    // Maximum length for key ID
    private static final int MAX_KEY_ID_LENGTH = 100;
    
    @NonNull
    private final JwkAlgorithmPreferences jwkAlgorithmPreferences;
    
    @NonNull
    private final SecurityEventCounter securityEventCounter;
    
    /**
     * Validates the structure and content of a JWKS object.
     * 
     * @param jwks the JWKS object to validate
     * @return true if the JWKS structure is valid, false otherwise
     */
    public boolean validateJwksStructure(JsonObject jwks) {
        // Basic null check
        if (jwks == null) {
            LOGGER.warn("JWKS object is null");
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }
        
        // Check for excessive number of top-level properties
        if (jwks.size() > MAX_JWKS_PROPERTIES) {
            LOGGER.warn("JWKS object has excessive number of properties: {}", jwks.size());
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }
        
        // If it has a "keys" array, validate it
        if (JwkKeyConstants.Keys.isPresent(jwks)) {
            return validateKeysArray(jwks);
        }
        
        return true;
    }
    
    /**
     * Validates the "keys" array in a JWKS object.
     * 
     * @param jwks the JWKS object containing the keys array
     * @return true if the keys array is valid, false otherwise
     */
    private boolean validateKeysArray(JsonObject jwks) {
        JsonArray keysArray = jwks.getJsonArray(JwkKeyConstants.Keys.KEY);
        
        // Check array size limits
        if (keysArray.size() > MAX_KEYS_IN_ARRAY) {
            LOGGER.warn("JWKS keys array exceeds maximum size: {}", keysArray.size());
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }
        
        if (keysArray.isEmpty()) {
            LOGGER.warn("JWKS keys array is empty");
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }
        
        return true;
    }
    
    /**
     * Validates individual key parameters and algorithms.
     * 
     * @param keyObject the individual key object to validate
     * @return true if the key is valid, false otherwise
     */
    public boolean validateKeyParameters(JsonObject keyObject) {
        // Validate required key type
        if (!validateKeyType(keyObject)) {
            return false;
        }
        
        // Validate key ID if present
        if (!validateKeyId(keyObject)) {
            return false;
        }
        
        // Validate algorithm if present
        if (!validateAlgorithm(keyObject)) {
            return false;
        }
        
        return true;
    }
    
    /**
     * Validates the key type parameter.
     * 
     * @param keyObject the key object
     * @return true if key type is valid, false otherwise
     */
    private boolean validateKeyType(JsonObject keyObject) {
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
        
        return true;
    }
    
    /**
     * Validates the key ID parameter if present.
     * 
     * @param keyObject the key object
     * @return true if key ID is valid or not present, false otherwise
     */
    private boolean validateKeyId(JsonObject keyObject) {
        if (keyObject.containsKey(JwkKeyConstants.KeyId.KEY)) {
            String keyId = keyObject.getString(JwkKeyConstants.KeyId.KEY);
            if (keyId.length() > MAX_KEY_ID_LENGTH) {
                LOGGER.warn("Key ID exceeds maximum length: {}", keyId.length());
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return false;
            }
        }
        return true;
    }
    
    /**
     * Validates the algorithm parameter if present.
     * 
     * @param keyObject the key object
     * @return true if algorithm is valid or not present, false otherwise
     */
    private boolean validateAlgorithm(JsonObject keyObject) {
        if (keyObject.containsKey(JwkKeyConstants.Algorithm.KEY)) {
            String algorithm = keyObject.getString(JwkKeyConstants.Algorithm.KEY);
            if (!jwkAlgorithmPreferences.isSupported(algorithm)) {
                LOGGER.warn("Invalid or unsupported algorithm: {}", algorithm);
                securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
                return false;
            }
        }
        return true;
    }
}