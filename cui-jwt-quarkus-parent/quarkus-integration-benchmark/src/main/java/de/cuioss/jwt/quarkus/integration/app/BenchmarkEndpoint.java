package de.cuioss.jwt.quarkus.integration.app;

import de.cuioss.jwt.validation.TokenValidator;
import de.cuioss.jwt.validation.domain.token.AccessTokenContent;

import java.util.Optional;
import jakarta.inject.Inject;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import lombok.extern.java.Log;

/**
 * REST endpoint for JWT validation benchmarking.
 * Provides endpoints that simulate real-world JWT validation scenarios
 * for integration performance testing.
 */
@Path("/benchmark")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
@Log
public class BenchmarkEndpoint {

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
            log.warning("Token validation error: " + e.getMessage());
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity(new ValidationResponse(false, "Token validation failed: " + e.getMessage()))
                    .build();
        }
    }

    /**
     * Validates multiple tokens in batch - for throughput testing.
     * 
     * @param request Batch validation request
     * @return Batch validation results
     */
    @POST
    @Path("/validate-batch")
    public Response validateTokens(BatchValidationRequest request) {
        if (request == null || request.getTokens() == null || request.getTokens().isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST)
                    .entity(new BatchValidationResponse(0, 0, "No tokens provided"))
                    .build();
        }

        int totalTokens = request.getTokens().size();
        int validTokens = 0;

        for (String token : request.getTokens()) {
            try {
                AccessTokenContent accessToken = tokenValidator.createAccessToken(token);
                validTokens++;
            } catch (Exception e) {
                log.warning("Batch validation error for token: " + e.getMessage());
            }
        }

        return Response.ok(new BatchValidationResponse(totalTokens, validTokens, "Batch validation completed"))
                .build();
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

    public static class BatchValidationRequest {
        private java.util.List<String> tokens;

        public java.util.List<String> getTokens() {
            return tokens;
        }

        public void setTokens(java.util.List<String> tokens) {
            this.tokens = tokens;
        }
    }

    public static class BatchValidationResponse {
        public int totalTokens;
        public int validTokens;
        public String message;

        public BatchValidationResponse() {}

        public BatchValidationResponse(int totalTokens, int validTokens, String message) {
            this.totalTokens = totalTokens;
            this.validTokens = validTokens;
            this.message = message;
        }
    }
}