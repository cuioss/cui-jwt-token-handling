package de.cuioss.jwt.integration.health;

import jakarta.enterprise.context.ApplicationScoped;
import org.eclipse.microprofile.health.HealthCheck;
import org.eclipse.microprofile.health.HealthCheckResponse;
import org.eclipse.microprofile.health.Liveness;

/**
 * Custom health check for JWT integration testing.
 * This provides a more sophisticated health check than simple endpoint checking.
 */
@Liveness
@ApplicationScoped
public class CustomHealthCheck implements HealthCheck {

    @Override
    public HealthCheckResponse call() {
        boolean isHealthy = performHealthCheck();
        
        if (isHealthy) {
            return HealthCheckResponse.up("JWT Integration Service");
        } else {
            return HealthCheckResponse.down("JWT Integration Service");
        }
    }

    private boolean performHealthCheck() {
        try {
            // Check if certificate files exist
            var keystoreExists = java.nio.file.Files.exists(
                java.nio.file.Paths.get("/app/certificates/keystore.p12"));
            
            // Add more sophisticated checks here:
            // - Database connectivity
            // - Critical service dependencies
            // - Application-specific validations
            
            return keystoreExists;
        } catch (Exception e) {
            return false;
        }
    }
}