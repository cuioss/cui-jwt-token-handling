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
package de.cuioss.jwt.token.test.generator;

import de.cuioss.jwt.token.TokenType;
import de.cuioss.jwt.token.domain.token.TokenContent;
import de.cuioss.test.generator.TypedGenerator;

/**
 * Generator for valid TokenContent instances.
 * Can be configured with different {@link TokenType} values to generate
 * appropriate token content with all required claims.
 */
public class ValidTokenContentGenerator implements TypedGenerator<TokenContent> {

    private final TokenType tokenType;

    /**
     * Constructor with token type.
     *
     * @param tokenType the type of token to generate
     */
    public ValidTokenContentGenerator(TokenType tokenType) {
        this.tokenType = tokenType;
    }

    /**
     * Default constructor that creates ACCESS_TOKEN type.
     */
    public ValidTokenContentGenerator() {
        this(TokenType.ACCESS_TOKEN);
    }

    @Override
    public TokenContent next() {
        // Create a new implementation of TokenContent with all valid claims
        // using the default claim control parameter for the token type
        return new TokenContentImpl(tokenType, ClaimControlParameter.defaultForTokenType(tokenType));
    }
}
