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
package de.cuioss.jwt.quarkus.deployment;

/**
 * Exception thrown when JWT configuration validation fails at build time.
 * <p>
 * This exception provides detailed error messages to help developers
 * quickly identify and fix configuration issues.
 * </p>
 */
public class JwtConfigurationException extends RuntimeException {

    /**
     * Constructs a new JWT configuration exception with the specified detail message.
     *
     * @param message the detail message
     */
    public JwtConfigurationException(String message) {
        super(message);
    }

    /**
     * Constructs a new JWT configuration exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public JwtConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}