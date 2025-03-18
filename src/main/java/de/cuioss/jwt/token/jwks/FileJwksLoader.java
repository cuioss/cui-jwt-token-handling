/*
 * Copyright 2023 the original author or authors.
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * https://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.cuioss.jwt.token.jwks;

import de.cuioss.tools.logging.CuiLogger;
import lombok.EqualsAndHashCode;
import lombok.NonNull;
import lombok.ToString;
import lombok.experimental.Delegate;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * Implementation of {@link JwksLoader} that loads JWKS from a file.
 *
 * @author Oliver Wolff
 */
@ToString
@EqualsAndHashCode
public class FileJwksLoader implements JwksLoader {

    private static final CuiLogger LOGGER = new CuiLogger(FileJwksLoader.class);

    private final Path jwksPath;

    @Delegate
    private final JWKSKeyLoader delegate;

    /**
     * Creates a new FileJwksLoader with the specified file path.
     *
     * @param filePath the path to the JWKS file
     */
    public FileJwksLoader(@NonNull String filePath) {
        this.jwksPath = Paths.get(filePath);
        LOGGER.debug("Resolving key loader for JWKS file: %s", jwksPath);
        String jwksContent;
        try {
            jwksContent = new String(Files.readAllBytes(jwksPath));
            LOGGER.debug("Successfully read JWKS from file: %s", jwksPath);
        } catch (IOException e) {
            LOGGER.warn(e, "Failed to read JWKS from file: %s", jwksPath);
            jwksContent = "{}"; // Empty JWKS
        }
        this.delegate = new JWKSKeyLoader(jwksContent);
        LOGGER.debug("Successfully loaded %s keys", delegate.keySet().size());
    }
}
