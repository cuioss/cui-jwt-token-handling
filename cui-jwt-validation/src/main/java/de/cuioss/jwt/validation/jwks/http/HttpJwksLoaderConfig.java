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

import lombok.Builder;
import lombok.NonNull;
import lombok.Value;

/**
 * Simplified configuration for {@link HttpJwksLoader}.
 * Only contains the URL - all complex caching and refresh settings removed.
 * 
 * @author Oliver Wolff
 * @since 1.0
 */
@Value
@Builder
public class HttpJwksLoaderConfig {
    
    @NonNull
    String url;
    
    /**
     * Creates a simple config with just a URL.
     */
    public static HttpJwksLoaderConfig forUrl(@NonNull String url) {
        return HttpJwksLoaderConfig.builder().url(url).build();
    }
}