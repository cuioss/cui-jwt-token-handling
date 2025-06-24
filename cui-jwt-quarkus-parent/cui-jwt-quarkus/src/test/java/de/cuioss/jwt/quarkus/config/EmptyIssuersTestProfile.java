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

import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.HashMap;
import java.util.Map;

/**
 * Test profile with empty issuers configuration.
 * <p>
 * This profile is used to test the error handling path where no issuers are configured.
 */
public class EmptyIssuersTestProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> config = new HashMap<>();

        // Global parser configuration
        config.put("cui.jwt.parser.leeway-seconds", "30");
        config.put("cui.jwt.parser.max-token-size-bytes", "8192");
        config.put("cui.jwt.parser.validate-not-before", "true");
        config.put("cui.jwt.parser.validate-expiration", "true");
        config.put("cui.jwt.parser.validate-issued-at", "false");
        config.put("cui.jwt.parser.allowed-algorithms", "RS256,RS384,RS512,ES256,ES384,ES512");

        // Health check configuration
        config.put("cui.jwt.health.enabled", "true");
        config.put("cui.jwt.health.jwks.cache-seconds", "30");
        config.put("cui.jwt.health.jwks.timeout-seconds", "5");

        return config;
    }
}