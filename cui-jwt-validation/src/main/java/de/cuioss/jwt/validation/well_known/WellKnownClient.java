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
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import de.cuioss.tools.net.http.HttpStatusFamily;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

/**
 * Handles HTTP client operations for well-known endpoint discovery.
 * <p>
 * This class is responsible for:
 * <ul>
 *   <li>Creating and configuring HTTP clients</li>
 *   <li>Fetching discovery documents from well-known endpoints</li>
 *   <li>Handling HTTP responses and status codes</li>
 * </ul>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@RequiredArgsConstructor
class WellKnownClient {

    private static final CuiLogger LOGGER = new CuiLogger(WellKnownClient.class);

    private final HttpHandler httpHandler;

    /**
     * Fetches the discovery document from the well-known endpoint.
     *
     * @return the discovery document as a string
     * @throws WellKnownDiscoveryException if fetching fails
     */
    String fetchDiscoveryDocument() {
        URL resolvedUrl = httpHandler.getUrl();
        LOGGER.debug(DEBUG.FETCHING_DISCOVERY_DOCUMENT.format(resolvedUrl));

        try {
            HttpRequest request = httpHandler.requestBuilder()
                    .header("Accept", "application/json")
                    .GET()
                    .build();

            HttpClient httpClient = httpHandler.createHttpClient();
            HttpResponse<String> response = httpClient.send(request, HttpResponse.BodyHandlers.ofString());

            HttpStatusFamily statusFamily = HttpStatusFamily.fromStatusCode(response.statusCode());
            if (statusFamily != HttpStatusFamily.SUCCESS) {
                throw new WellKnownDiscoveryException("Failed to fetch discovery document from " + resolvedUrl +
                        ". HTTP status: " + response.statusCode() + " (" + statusFamily + ")");
            }

            return response.body();
        } catch (IOException e) {
            throw new WellKnownDiscoveryException("IOException while fetching or reading from " + resolvedUrl, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new WellKnownDiscoveryException("Interrupted while fetching from " + resolvedUrl, e);
        } catch (Exception e) {
            throw new WellKnownDiscoveryException("Error while fetching from " + resolvedUrl, e);
        }
    }
}