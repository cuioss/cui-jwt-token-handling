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

import de.cuioss.jwt.validation.jwks.LoaderStatus;

/**
 * Result type for well-known discovery operations that provides explicit error handling
 * without exceptions. This follows the same pattern as ETagAwareHttpHandler.LoadResult
 * and aligns with the resilient architecture design.
 *
 * @param <T> the type of the result value
 * @param value the result value, null if operation failed
 * @param status the loader status indicating success or failure
 * @param errorMessage descriptive error message if status is ERROR, null otherwise
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public record WellKnownResult<T>(T value, LoaderStatus status, String errorMessage) {

    /**
     * Creates a successful result with the given value.
     *
     * @param <T> the type of the result value
     * @param value the successful result value
     * @return a WellKnownResult indicating success
     */
    public static <T> WellKnownResult<T> success(T value) {
        return new WellKnownResult<>(value, LoaderStatus.OK, null);
    }

    /**
     * Creates an error result with the given error message.
     *
     * @param <T> the type of the result value
     * @param message the error message
     * @return a WellKnownResult indicating failure
     */
    public static <T> WellKnownResult<T> error(String message) {
        return new WellKnownResult<>(null, LoaderStatus.ERROR, message);
    }

    /**
     * Creates an undefined result (status not yet determined).
     *
     * @param <T> the type of the result value
     * @return a WellKnownResult indicating undefined status
     */
    public static <T> WellKnownResult<T> undefined() {
        return new WellKnownResult<>(null, LoaderStatus.UNDEFINED, null);
    }

    /**
     * Checks if this result represents a successful operation.
     *
     * @return true if status is OK, false otherwise
     */
    public boolean isSuccess() {
        return status == LoaderStatus.OK;
    }

    /**
     * Checks if this result represents a failed operation.
     *
     * @return true if status is ERROR, false otherwise
     */
    public boolean isError() {
        return status == LoaderStatus.ERROR;
    }

    /**
     * Checks if this result represents an undefined status.
     *
     * @return true if status is UNDEFINED, false otherwise
     */
    public boolean isUndefined() {
        return status == LoaderStatus.UNDEFINED;
    }
}