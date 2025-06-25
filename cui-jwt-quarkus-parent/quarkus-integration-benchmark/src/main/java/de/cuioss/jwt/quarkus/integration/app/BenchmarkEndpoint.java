package de.cuioss.jwt.quarkus.integration.app;

import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;
import de.cuioss.tools.logging.CuiLogger;

import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

/**
 * REST endpoint for JWT validation benchmarking.
 * Provides endpoints that simulate real-world JWT validation scenarios
 * for integration performance testing.
 */
@Path("/benchmark")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class BenchmarkEndpoint {

    private static final CuiLogger log = new CuiLogger(BenchmarkEndpoint.class);

    @Inject
    TokenValidator tokenValidator;

    /**
     * Validates a JWT token - primary endpoint for benchmarking.
     * 
     * @param token JWT token to validate
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
            AccessTokenContent accessToken = tokenValidator.createAccessToken(jwtToken);
            return Response.ok(new ValidationResponse(true, "Token is valid"))
                    .build();
        } catch (Exception e) {
            log.warn("Token validation error: {}", e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ValidationResponse(false, "Token validation failed: " + e.getMessage()))
                    .build();
        }
    }


    /**
     * Health check endpoint for container readiness.
     */
    @GET
    @Path("/health")
    public Response health() {
        return Response.ok(new ValidationResponse(true, "Benchmark endpoint is ready"))
                .build();
    }

    // Response DTOs
    public static class ValidationResponse {
        public boolean valid;
        public String message;

        public ValidationResponse() {}

        public ValidationResponse(boolean valid, String message) {
            this.valid = valid;
            this.message = message;
        }
    }

}