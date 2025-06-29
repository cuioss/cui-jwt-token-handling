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
package de.cuioss.jwt.validation.jwks.http;

import java.io.Serial;

/**
 * Runtime exception thrown when JWKS loading fails.
 * This includes HTTP errors, network failures, and invalid JWKS content.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public class JwksLoadException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new JWKS load exception with the specified detail message.
     *
     * @param message the detail message
     */
    public JwksLoadException(String message) {
        super(message);
    }

    /**
     * Constructs a new JWKS load exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     */
    public JwksLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}