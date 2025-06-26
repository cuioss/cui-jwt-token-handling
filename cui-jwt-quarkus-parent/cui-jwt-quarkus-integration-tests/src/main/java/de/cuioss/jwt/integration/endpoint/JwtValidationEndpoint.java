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
package de.cuioss.jwt.integration.endpoint;

import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.tools.logging.CuiLogger;
import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * REST endpoint for JWT validation operations.
 * This endpoint provides the real application functionality that is used by
 * both integration tests and performance benchmarks.
 */
@Path("/jwt")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@ApplicationScoped
public class JwtValidationEndpoint {

    private static final CuiLogger LOGGER = new CuiLogger(JwtValidationEndpoint.class);

    private final TokenValidator tokenValidator;

    @Inject
    public JwtValidationEndpoint(TokenValidator tokenValidator) {
        this.tokenValidator = tokenValidator;
        LOGGER.info("JwtValidationEndpoint created with TokenValidator");
    }
    
    void onStart(@Observes StartupEvent ev) {
        LOGGER.info("JwtValidationEndpoint started and ready at /jwt/validate");
    }

    /**
     * Health check endpoint to verify the service is running.
     *
     * @return Simple OK response
     */
    @GET
    @Path("/health")
    public Response health() {
        return Response.ok(new ValidationResponse(true, "JWT validation endpoint is healthy"))
                .build();
    }

    /**
     * Validates a JWT token - primary endpoint for integration testing and benchmarking.
     *
     * @param token JWT token from Authorization header
     * @return Validation result
     */
    @POST
    @Path("/validate")
    public Response validateToken(@HeaderParam("Authorization") String token) {
        if (token == null || !token.startsWith("Bearer ")) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new ValidationResponse(false, "Missing or invalid Authorization header"))
                    .build();
        }

        String jwtToken = token.substring(7); // Remove "Bearer " prefix

        try {
            tokenValidator.createAccessToken(jwtToken);
            return Response.ok(new ValidationResponse(true, "Token is valid"))
                    .build();
        } catch (Exception e) {
            LOGGER.warn("Token validation error: %s", e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ValidationResponse(false, "Token validation failed: " + e.getMessage()))
                    .build();
        }
    }


    // Response DTOs
    public record ValidationResponse(boolean valid, String message) {
    }
}