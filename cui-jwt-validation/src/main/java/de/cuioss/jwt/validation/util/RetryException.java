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
package de.cuioss.jwt.validation.util;

import java.io.Serial;

/**
 * Exception thrown when an operation fails after retry attempts.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public class RetryException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = 1L;

    private final int attemptsMade;

    /**
     * Constructs a new retry exception with the specified detail message and cause.
     *
     * @param message the detail message
     * @param cause the cause of the exception
     * @param attemptsMade number of attempts made before failure
     */
    public RetryException(String message, Throwable cause, int attemptsMade) {
        super(message, cause);
        this.attemptsMade = attemptsMade;
    }

    /**
     * Gets the number of attempts made before failure.
     * 
     * @return the number of attempts
     */
    public int getAttemptsMade() {
        return attemptsMade;
    }
}