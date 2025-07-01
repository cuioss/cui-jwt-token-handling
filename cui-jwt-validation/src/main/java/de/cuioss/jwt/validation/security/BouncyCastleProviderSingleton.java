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
package de.cuioss.jwt.validation.security;

import de.cuioss.tools.logging.CuiLogger;
import lombok.Getter;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Provider;
import java.security.Security;

/**
 * Singleton for managing the BouncyCastle security provider.
 * <p>
 * This class ensures that the BouncyCastle provider is registered only once
 * in a thread-safe manner, avoiding potential concurrency issues that can occur
 * with static initializer blocks.
 * <p>
 * BouncyCastle is used for:
 * <ul>
 *   <li>Support for modern cryptographic algorithms across all JVM versions</li>
 *   <li>Consistent implementation of ECDSA signature verification</li>
 *   <li>Support for RSA-PSS signatures (PS256, PS384, PS512)</li>
 * </ul>
 * <p>
 * Usage:
 * <pre>
 * // Get the provider name
 * String providerName = BouncyCastleProviderSingleton.getInstance().getProviderName();
 *
 * // Use the provider name with Signature.getInstance
 * Signature signature = Signature.getInstance(algorithm, providerName);
 * </pre>
 * <p>
 * This implementation uses the initialization-on-demand holder idiom for thread-safe
 * lazy initialization, which is the recommended way to implement singletons in Java.
 * <p>
 * For more information on the cryptographic algorithms supported, see the
 * <a href="https://github.com/cuioss/cui-jwt/tree/main/doc/specification/security.adoc">Security Specification</a>
 *
 * @author Oliver Wolff
 * @since 1.0
 */
@SuppressWarnings("java:S6548") // owolff: A singleton here is ok and better than the alternative: static initializer
public class BouncyCastleProviderSingleton {

    private static final CuiLogger LOGGER = new CuiLogger(BouncyCastleProviderSingleton.class);

    @Getter
    private final Provider provider;

    /**
     * Private constructor to prevent direct instantiation.
     * Initializes and registers the BouncyCastle provider if not already registered.
     */
    private BouncyCastleProviderSingleton() {
        Provider existingProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (existingProvider == null) {
            LOGGER.debug("Registering BouncyCastle provider");
            provider = new BouncyCastleProvider();
            Security.addProvider(provider);
        } else {
            LOGGER.debug("Using existing BouncyCastle provider");
            provider = existingProvider;
        }
    }

    /**
     * Initialization-on-demand holder idiom for thread-safe lazy initialization.
     * This pattern is thread-safe without requiring the volatile keyword.
     */
    private static class LazyHolder {
        private static final BouncyCastleProviderSingleton INSTANCE = new BouncyCastleProviderSingleton();
    }

    /**
     * Gets the singleton instance of the BouncyCastleProviderSingleton.
     * Thread-safe due to JVM's class initialization guarantees.
     *
     * @return the singleton instance
     */
    public static BouncyCastleProviderSingleton getInstance() {
        return LazyHolder.INSTANCE;
    }

    /**
     * Gets the name of the BouncyCastle provider.
     *
     * @return the provider name
     */
    public String getProviderName() {
        return BouncyCastleProvider.PROVIDER_NAME;
    }

}
