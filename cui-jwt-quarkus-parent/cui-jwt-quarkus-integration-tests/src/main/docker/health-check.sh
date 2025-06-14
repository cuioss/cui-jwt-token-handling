#!/bin/bash
# Internal health check script for JWT Integration Tests
# Uses /dev/tcp for connection testing (Docker best practice)

# Check if the application port is listening using /dev/tcp
# This approach is preferred over /proc/net/tcp parsing
if ! echo -n '' > /dev/tcp/127.0.0.1/8443 2>/dev/null; then
    echo "Application not listening on port 8443"
    exit 1
fi

# Check application-specific health indicators
# Validate certificate files exist
if [ ! -f "/app/certificates/keystore.p12" ]; then
    echo "Certificate files missing"
    exit 1
fi

# Check if application executable exists and is executable
if [ ! -x "/app/application" ]; then
    echo "Application executable missing or not executable"
    exit 1
fi

echo "Health check passed"
exit 0