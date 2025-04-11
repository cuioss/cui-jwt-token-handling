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
package de.cuioss.jwt.token.adapter;

import lombok.experimental.UtilityClass;

/**
 * Class defining standard claim names for JWT tokens as constants.
 * This is a replacement for the org.eclipse.microprofile.jwt.ClaimNames interface
 * to allow for migration from64EncodedContent SmallRye JWT to JJWT without changing the existing code.
 *
 * @author Oliver Wolff
 */
@UtilityClass
public final class ClaimNames {

    /**
     * The "iss" (issuer) claim identifies the principal that issued the JWT.
     */
    public static final String ISSUER = "iss";

    /**
     * The "aud" (audience) claim identifies the recipients that the JWT is intended for.
     */
    public static final String AUDIENCE = "aud";

    /**
     * The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
     */
    public static final String NOT_BEFORE = "nbf";

    /**
     * The "scope" claim identifies the set of scopes associated with this token.
     * This is specific to OAuth 2.0 access tokens.
     */
    public static final String SCOPE = "scope";
}
