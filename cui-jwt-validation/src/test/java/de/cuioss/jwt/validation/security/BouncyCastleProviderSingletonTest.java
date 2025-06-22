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

import de.cuioss.test.juli.junit5.EnableTestLogger;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.Provider;
import java.security.Security;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Tests for {@link BouncyCastleProviderSingleton}.
 */
@EnableTestLogger
@DisplayName("Tests for BouncyCastleProviderSingleton")
class BouncyCastleProviderSingletonTest {

    @Test
    @DisplayName("Should return the same instance on multiple calls")
    void shouldReturnSameInstance() {

        BouncyCastleProviderSingleton instance1 = BouncyCastleProviderSingleton.getInstance();
        BouncyCastleProviderSingleton instance2 = BouncyCastleProviderSingleton.getInstance();
        assertNotNull(instance1, "Instance should not be null");
        assertSame(instance1, instance2, "Multiple calls should return the same instance");
    }

    @Test
    @DisplayName("Should return the correct provider name")
    void shouldReturnCorrectProviderName() {

        String providerName = BouncyCastleProviderSingleton.getInstance().getProviderName();
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, providerName, "Provider name should match BouncyCastleProvider.PROVIDER_NAME");
    }

    @Test
    @DisplayName("Should return a valid provider instance")
    void shouldReturnValidProvider() {

        Provider provider = BouncyCastleProviderSingleton.getInstance().getProvider();
        assertNotNull(provider, "Provider should not be null");
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, provider.getName(), "Provider name should match BouncyCastleProvider.PROVIDER_NAME");
    }

    @Test
    @DisplayName("Should register the provider with the JVM security system")
    void shouldRegisterProviderWithJvm() {

        assertNotNull(BouncyCastleProviderSingleton.getInstance()); // Ensure provider is registered
        Provider registeredProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        assertNotNull(registeredProvider, "Provider should be registered with the JVM security system");
        assertEquals(BouncyCastleProvider.PROVIDER_NAME, registeredProvider.getName(), "Registered provider name should match BouncyCastleProvider.PROVIDER_NAME");
    }

    @Test
    @DisplayName("Should use existing provider if already registered")
    void shouldUseExistingProvider() {

        Provider existingProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        if (existingProvider == null) {
            // If not already registered, register it
            Security.addProvider(new BouncyCastleProvider());
            existingProvider = Security.getProvider(BouncyCastleProvider.PROVIDER_NAME);
        }
        Provider provider = BouncyCastleProviderSingleton.getInstance().getProvider();
        assertNotNull(provider, "Provider should not be null");
        assertEquals(existingProvider.getName(), provider.getName(), "Provider name should match existing provider");
    }
}