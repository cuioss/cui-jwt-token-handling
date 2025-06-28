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

import de.cuioss.jwt.validation.jwks.JwksLoader;
import de.cuioss.jwt.validation.jwks.JwksType;
import de.cuioss.jwt.validation.jwks.LoaderStatus;
import de.cuioss.jwt.validation.jwks.key.JWKSKeyLoader;
import de.cuioss.jwt.validation.jwks.key.KeyInfo;
import de.cuioss.jwt.validation.security.SecurityEventCounter;
import de.cuioss.jwt.validation.util.RetryUtil;
import de.cuioss.tools.logging.CuiLogger;
import de.cuioss.tools.net.http.HttpHandler;
import lombok.NonNull;

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Simplified JWKS loader that loads from HTTP endpoint with retry logic.
 * No caching, no statistics - just reliable loading.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
public class HttpJwksLoader implements JwksLoader {
    
    private static final CuiLogger LOGGER = new CuiLogger(HttpJwksLoader.class);
    
    private final HttpHandler httpHandler;
    private final SecurityEventCounter securityEventCounter;
    private volatile JWKSKeyLoader keyLoader;
    private volatile LoaderStatus status = LoaderStatus.UNDEFINED;
    
    public HttpJwksLoader(@NonNull HttpHandler httpHandler, 
                          @NonNull SecurityEventCounter securityEventCounter) {
        this.httpHandler = httpHandler;
        this.securityEventCounter = securityEventCounter;
    }
    
    /**
     * Constructor using HttpJwksLoaderConfig.
     * Uses the httpHandler directly from the config with all its settings.
     */
    public HttpJwksLoader(@NonNull HttpJwksLoaderConfig config, 
                          @NonNull SecurityEventCounter securityEventCounter) {
        this.httpHandler = config.getHttpHandler();
        this.securityEventCounter = securityEventCounter;
    }
    
    @Override
    public Optional<KeyInfo> getKeyInfo(String kid) {
        ensureLoaded();
        return keyLoader != null ? keyLoader.getKeyInfo(kid) : Optional.empty();
    }
    
    @Override
    public Optional<KeyInfo> getFirstKeyInfo() {
        ensureLoaded();
        return keyLoader != null ? keyLoader.getFirstKeyInfo() : Optional.empty();
    }
    
    @Override
    public List<KeyInfo> getAllKeyInfos() {
        ensureLoaded();
        return keyLoader != null ? keyLoader.getAllKeyInfos() : List.of();
    }
    
    @Override
    public Set<String> keySet() {
        ensureLoaded();
        return keyLoader != null ? keyLoader.keySet() : Set.of();
    }
    
    @Override
    public JwksType getJwksType() {
        return JwksType.HTTP;
    }
    
    @Override
    public LoaderStatus getStatus() {
        return status;
    }
    
    @Override
    public boolean isHealthy() {
        // For simplified loader, we consider it healthy if we can load keys
        // This will trigger lazy loading on first health check
        if (keyLoader == null) {
            try {
                ensureLoaded();
            } catch (Exception e) {
                LOGGER.debug("Health check failed during key loading: %s", e.getMessage());
                return false;
            }
        }
        return status == LoaderStatus.OK;
    }
    
    private void ensureLoaded() {
        if (keyLoader == null) {
            loadKeys();
        }
    }
    
    private void loadKeys() {
        try {
            String jwksContent = RetryUtil.executeWithRetry(
                this::fetchJwksContent,
                "fetch JWKS from " + httpHandler.getUrl()
            );
            
            this.keyLoader = JWKSKeyLoader.builder()
                .originalString(jwksContent)
                .securityEventCounter(securityEventCounter)
                .jwksType(JwksType.HTTP)
                .build();
            this.status = LoaderStatus.OK;
            
            LOGGER.info("Successfully loaded JWKS from %s", httpHandler.getUrl());
            
        } catch (Exception e) {
            this.status = LoaderStatus.ERROR;
            LOGGER.error(e, "Failed to load JWKS from %s", httpHandler.getUrl());
            throw new RuntimeException("Failed to load JWKS", e);
        }
    }
    
    private String fetchJwksContent() {
        try {
            HttpClient client = httpHandler.createHttpClient();
            HttpRequest request = httpHandler.requestBuilder().build();
            
            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            if (response.statusCode() != 200) {
                throw new IOException("HTTP " + response.statusCode() + " from " + httpHandler.getUrl());
            }
            
            return response.body();
            
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            throw new RuntimeException("Failed to fetch JWKS content", e);
        }
    }
}
