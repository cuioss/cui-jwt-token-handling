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
package de.cuioss.jwt.integration;

import de.cuioss.test.juli.junit5.EnableTestLogger;
import de.cuioss.tools.logging.CuiLogger;
import io.restassured.RestAssured;
import org.junit.jupiter.api.BeforeAll;

/**
 * Base class for integration tests with proper external port configuration.
 * <p>
 * This class configures REST Assured to use the external test port
 * that is configured via Maven properties and Docker port mapping.
 * Tests should always access the application from the outside perspective.
 */
@EnableTestLogger
public abstract class BaseIntegrationTest {

    private static final CuiLogger log = new CuiLogger(BaseIntegrationTest.class);
    private static final String DEFAULT_TEST_PORT = "8443";
    
    @BeforeAll
    static void setUpBaseIntegrationTest() {
        // Configure HTTPS with relaxed validation for self-signed certificates
        RestAssured.useRelaxedHTTPSValidation();
        RestAssured.baseURI = "https://localhost";
        
        // Use the external test port from Maven properties
        // This allows Docker port mapping (e.g., 10443:8443) while tests use the external port
        String testPort = System.getProperty("test.https.port", DEFAULT_TEST_PORT);
        RestAssured.port = Integer.parseInt(testPort);
        
        log.info("Integration tests configured for HTTPS port: {}", testPort);
    }
}