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

import de.cuioss.jwt.validation.JWTValidationLogMessages.DEBUG;
import de.cuioss.jwt.validation.JWTValidationLogMessages.WARN;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.HttpStatusFamily;
import lombok.RequiredArgsConstructor;

import java.net.URL;
import java.util.Map;

/**
 * Handles endpoint mapping and URL validation for well-known discovery.
 * <p>
 * This class is responsible for:
 * <ul>
 *   <li>Creating HttpHandler instances for discovered endpoints</li>
 *   <li>Validating endpoint URLs and accessibility</li>
 *   <li>Managing endpoint mappings</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@RequiredArgsConstructor
class WellKnownEndpointMapper {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownEndpointMapper.class);

    private final HttpHandler baseHandler;

    /**
     * Adds an HttpHandler to the map of endpoints.
     *
     * @param map The map to add to
     * @param key The key for the HttpHandler
     * @param urlString The URL string to add
     * @param wellKnownUrl The well-known URL (used for error messages)
     * @param isRequired Whether this URL is required
     * @return WellKnownResult indicating success or failure
     */
    WellKnownResult<Void> addHttpHandlerToMap(Map<String, HttpHandler> map, String key, String urlString, URL wellKnownUrl, boolean isRequired) {
        if (urlString == null) {
            if (isRequired) {
                return WellKnownResult.error("Required URL field '" + key + "' is missing in discovery document from " + wellKnownUrl);
            }
            LOGGER.debug(DEBUG.OPTIONAL_URL_FIELD_MISSING.format(key, wellKnownUrl));
            return WellKnownResult.success(null);
        }
        try {
            HttpHandler handler = baseHandler.asBuilder()
                    .uri(urlString)
                    .build();
            map.put(key, handler);
            return WellKnownResult.success(null);
        } catch (IllegalArgumentException e) {
            return WellKnownResult.error("Malformed URL for field '" + key + "': " + urlString + " from " + wellKnownUrl + " - " + e.getMessage());
        }
    }

    /**
     * Performs accessibility check for a specific endpoint.
     *
     * @param endpointName The name of the endpoint
     * @param handler The HttpHandler for the endpoint
     */
    void performAccessibilityCheck(String endpointName, HttpHandler handler) {
        if (handler != null) {
            HttpStatusFamily statusFamily = handler.pingHead();
            if (statusFamily != HttpStatusFamily.SUCCESS) {
                LOGGER.warn(WARN.ACCESSIBILITY_CHECK_HTTP_ERROR.format(endpointName, handler.getUrl(), statusFamily));
            } else {
                LOGGER.debug(DEBUG.ACCESSIBILITY_CHECK_SUCCESSFUL.format(endpointName, handler.getUrl(), statusFamily));
            }
        }
    }
}