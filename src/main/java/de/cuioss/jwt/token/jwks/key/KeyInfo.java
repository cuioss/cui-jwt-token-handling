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
package de.cuioss.jwt.token.jwks.key;

import lombok.Getter;
import lombok.NonNull;
import lombok.Value;

import java.security.PublicKey;

/**
 * Class that holds information about a key, including the key itself and its algorithm.
 * <p>
 * This class is used to store keys along with their algorithm information to support
 * cryptographic agility.
 * <p>
 * Implements requirement: {@code CUI-JWT-8.5: Cryptographic Agility}
 * <p>
 * For more details on the security aspects, see the
 * <a href="../../../../../../../doc/specification/security.adoc">Security Specification</a>.
 *
 * @author Oliver Wolff
 */
@Value
public class KeyInfo {

    /**
     * The key.
     */
    @Getter
    @NonNull
    PublicKey key;

    /**
     * The algorithm used by the key.
     */
    @Getter
    @NonNull
    String algorithm;

    @Getter
    @NonNull
    String keyId;
}
