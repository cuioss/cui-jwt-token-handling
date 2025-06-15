#!/bin/bash
# Script to generate certificates for JWT Quarkus integration testing
# Generates localhost certificates with proper SAN for HTTPS testing

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
CERT_DIR="${SCRIPT_DIR}"
KEYSTORE_PASSWORD="integration-test"
TRUSTSTORE_PASSWORD="integration-test"
KEY_PASSWORD="integration-test"
CERT_DNAME="CN=localhost, OU=Integration Testing, O=CUI-JWT, L=Berlin, ST=Berlin, C=DE"
CERT_VALIDITY=730

echo "Generating certificates for JWT integration testing..."
echo "Certificate directory: ${CERT_DIR}"

# Clean up existing certificates
rm -f "${CERT_DIR}/keystore.p12" "${CERT_DIR}/truststore.p12" "${CERT_DIR}/localhost.cer" "${CERT_DIR}/localhost.crt"

# Generate keystore with private key and self-signed certificate
echo "Generating keystore with self-signed certificate..."
keytool -genkeypair \
  -alias localhost \
  -keyalg RSA \
  -keysize 2048 \
  -validity ${CERT_VALIDITY} \
  -dname "${CERT_DNAME}" \
  -ext san=dns:localhost,ip:127.0.0.1,ip:0.0.0.0 \
  -keystore "${CERT_DIR}/keystore.p12" \
  -storetype PKCS12 \
  -storepass "${KEYSTORE_PASSWORD}" \
  -keypass "${KEY_PASSWORD}" 2>&1

# Export certificate
echo "Exporting certificate..."
keytool -exportcert \
  -alias localhost \
  -file "${CERT_DIR}/localhost.cer" \
  -keystore "${CERT_DIR}/keystore.p12" \
  -storetype PKCS12 \
  -storepass "${KEYSTORE_PASSWORD}" 2>&1

# Create truststore
echo "Creating truststore..."
keytool -importcert \
  -alias localhost \
  -file "${CERT_DIR}/localhost.cer" \
  -keystore "${CERT_DIR}/truststore.p12" \
  -storetype PKCS12 \
  -storepass "${TRUSTSTORE_PASSWORD}" \
  -noprompt 2>&1

# Export to PEM format for container usage
echo "Exporting certificate in PEM format..."
keytool -exportcert \
  -alias localhost \
  -file "${CERT_DIR}/localhost.crt" \
  -keystore "${CERT_DIR}/keystore.p12" \
  -storetype PKCS12 \
  -storepass "${KEYSTORE_PASSWORD}" \
  -rfc 2>&1

echo "Certificate generation complete for JWT integration testing!"
echo "Generated files:"
echo "  - keystore.p12: Private key and certificate (password: ${KEYSTORE_PASSWORD})"
echo "  - truststore.p12: Trust store for validation (password: ${TRUSTSTORE_PASSWORD})" 
echo "  - localhost.cer: Certificate in DER format"
echo "  - localhost.crt: Certificate in PEM format"
echo ""
echo "Certificate valid for ${CERT_VALIDITY} days (2 years)"
echo "Subject: ${CERT_DNAME}"
echo "SAN: dns:localhost,ip:127.0.0.1,ip:0.0.0.0"