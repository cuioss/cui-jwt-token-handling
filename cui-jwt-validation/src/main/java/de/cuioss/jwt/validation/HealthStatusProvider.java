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
package de.cuioss.jwt.validation;

import de.cuioss.jwt.validation.jwks.LoaderStatus;

/**
 * Common interface for components that provide health status information.
 * <p>
 * This interface unifies health checking across different JWT validation components
 * by providing a consistent way to check component health and retrieve status information.
 * <p>
 * Implementation requirements:
 * <ul>
 *   <li>Implementations must be thread-safe for concurrent access</li>
 *   <li>Health checks should be fail-fast to avoid blocking callers</li>
 *   <li>For lazy-loading implementations, {@link #isHealthy()} may trigger initial loading</li>
 *   <li>The {@link #getStatus()} should reflect the current state accurately</li>
 * </ul>
 * <p>
 * Usage example:
 * <pre>
 * HealthStatusProvider provider = someComponent;
 * if (provider.isHealthy()) {
 *     // Component is healthy and ready to use
 *     LoaderStatus status = provider.getStatus();
 *     if (status == LoaderStatus.OK) {
 *         // Proceed with operations
 *     }
 * } else {
 *     // Handle unhealthy state
 *     LoaderStatus status = provider.getStatus();
 *     if (status == LoaderStatus.ERROR) {
 *         // Log error or take corrective action
 *     }
 * }
 * </pre>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
public interface HealthStatusProvider {

    /**
     * Checks if the component is healthy and operational.
     * <p>
     * This method performs an actual health check by verifying that the component
     * can perform its intended operations. The exact definition of "healthy" depends
     * on the implementation:
     * <ul>
     *   <li>For JWKS loaders: Can access at least one cryptographic key</li>
     *   <li>For well-known resolvers: Can discover and access required endpoints</li>
     *   <li>For validators: Are properly configured and ready to validate tokens</li>
     * </ul>
     * <p>
     * For components with lazy initialization, this method may trigger the initial
     * loading operation if not already performed.
     *
     * @return {@code true} if the component is healthy and operational, {@code false} otherwise
     */
    boolean isHealthy();

    /**
     * Gets the current status of the component.
     * <p>
     * The status provides more detailed information about the component's state:
     * <ul>
     *   <li>{@link LoaderStatus#UNDEFINED} - Initial state, not yet initialized</li>
     *   <li>{@link LoaderStatus#OK} - Component is operational and healthy</li>
     *   <li>{@link LoaderStatus#ERROR} - Component encountered an error</li>
     * </ul>
     * <p>
     * The status should be consistent with the {@link #isHealthy()} result:
     * <ul>
     *   <li>If {@code isHealthy() == true}, status should be {@link LoaderStatus#OK}</li>
     *   <li>If {@code isHealthy() == false}, status should be {@link LoaderStatus#ERROR} or {@link LoaderStatus#UNDEFINED}</li>
     * </ul>
     *
     * @return the current status of the component, never {@code null}
     */
    LoaderStatus getStatus();
}