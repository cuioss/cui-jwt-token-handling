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

/**
 * Exception thrown when HTTP content loading fails.
 * <p>
 * This exception is used by HTTP-based loaders to indicate failures in
 * retrieving content from HTTP endpoints, such as network errors,
 * HTTP error responses, or content parsing issues.
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public class HttpLoadException extends RuntimeException {

    private static final long serialVersionUID = 1L;

    /**
     * Constructs a new HTTP load exception with the specified detail message.
     *
     * @param message the detail message
     */
    public HttpLoadException(String message) {
        super(message);
    }

    /**
     * Constructs a new HTTP load exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause
     */
    public HttpLoadException(String message, Throwable cause) {
        super(message, cause);
    }
}