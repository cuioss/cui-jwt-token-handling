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

import de.cuioss.jwt.validation.JWTValidationLogMessages.ERROR;
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.jwt.validation.ParserConfig;
import de.cuioss.jwt.validation.jwks.key.JwkKeyConstants;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.security.SecurityEventCounter.EventType;
import de.cuioss.tools.logging.CuiLogger;
import jakarta.json.JsonArray;
import jakarta.json.JsonException;
import jakarta.json.JsonObject;
import jakarta.json.JsonReader;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;

import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Parses JWKS content and extracts individual JWK objects.
 * This class is responsible for:
 * <ul>
 *   <li>Parsing JSON content with security limits</li>
 *   <li>Extracting keys from JWKS structure</li>
 *   <li>Handling both standard JWKS format and single key format</li>
 *   <li>Security event tracking for parsing failures</li>
 * </ul>
 */
@RequiredArgsConstructor
public class JwksParser {
    
    private static final CuiLogger LOGGER = new CuiLogger(JwksParser.class);
    
    @NonNull
    private final ParserConfig parserConfig;
    
    @NonNull
    private final SecurityEventCounter securityEventCounter;
    
    /**
     * Parse JWKS content and extract individual JWK objects.
     * 
     * @param jwksContent the JWKS content as a string
     * @return a list of parsed JWK objects, empty if parsing fails
     */
    public List<JsonObject> parse(String jwksContent) {
        List<JsonObject> result = new ArrayList<>();
        
        // Check content size
        if (!validateContentSize(jwksContent)) {
            return result;
        }
        
        try {
            // Use the JsonReaderFactory from ParserConfig with security settings
            try (JsonReader reader = parserConfig.getJsonReaderFactory()
                    .createReader(new StringReader(jwksContent))) {
                JsonObject jwks = reader.readObject();
                extractKeys(jwks, result);
            }
        } catch (JsonException e) {
            // Handle invalid JSON format
            LOGGER.error(e, ERROR.JWKS_INVALID_JSON.format(e.getMessage()));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
        }
        
        return result;
    }
    
    /**
     * Validate JWKS content size to prevent memory exhaustion attacks.
     * 
     * @param jwksContent the JWKS content
     * @return true if content size is within limits, false otherwise
     */
    private boolean validateContentSize(String jwksContent) {
        int actualSize = jwksContent.getBytes(StandardCharsets.UTF_8).length;
        int upperLimit = parserConfig.getMaxPayloadSize();
        
        if (actualSize > upperLimit) {
            LOGGER.error(ERROR.JWKS_CONTENT_SIZE_EXCEEDED.format(upperLimit, actualSize));
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
            return false;
        }
        
        return true;
    }
    
    /**
     * Extract keys from a JWKS object.
     * Handles both standard JWKS format (with "keys" array) and single key format.
     * 
     * @param jwks the JWKS object
     * @param result the list to store extracted keys
     */
    private void extractKeys(JsonObject jwks, List<JsonObject> result) {
        // Check if this is a JWKS with a "keys" array or a single key
        if (JwkKeyConstants.Keys.isPresent(jwks)) {
            extractKeysFromArray(jwks, result);
        } else if (JwkKeyConstants.KeyType.isPresent(jwks)) {
            // This is a single key object
            result.add(jwks);
        } else {
            LOGGER.warn(WARN.JWKS_MISSING_KEYS::format);
            securityEventCounter.increment(EventType.JWKS_JSON_PARSE_FAILED);
        }
    }
    
    /**
     * Extract keys from a standard JWKS with "keys" array.
     * 
     * @param jwks the JWKS object
     * @param result the list to store extracted keys
     */
    private void extractKeysFromArray(JsonObject jwks, List<JsonObject> result) {
        var keysArray = JwkKeyConstants.Keys.extract(jwks);
        if (keysArray.isPresent()) {
            JsonArray array = keysArray.get();
            for (int i = 0; i < array.size(); i++) {
                result.add(array.getJsonObject(i));
            }
        }
    }
}