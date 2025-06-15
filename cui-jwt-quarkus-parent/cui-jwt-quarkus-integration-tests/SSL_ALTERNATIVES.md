# Quarkus SSL/TLS Certificate Alternatives Research

## Summary of Findings

Based on comprehensive research, **Quarkus offers multiple secure alternatives** to password-protected PKCS12 keystores.

## Certificate Format Options

### 1. **PEM Files (Recommended for Production)**
- **Separate certificate and private key files**
- **No password required** for private key files
- **Most secure option** when combined with proper file permissions
- **Supports multiple certificate formats**: PKCS#8, PKCS#1, encrypted PKCS#8

```properties
# Modern TLS Registry configuration (Quarkus 3.x+)
quarkus.tls.key-store.pem.0.cert=/app/certificates/localhost.crt
quarkus.tls.key-store.pem.0.key=/app/certificates/localhost.key

# Optional: Enhanced security settings
quarkus.tls.cipher-suites=TLS_AES_256_GCM_SHA384,TLS_CHACHA20_POLY1305_SHA256
quarkus.tls.protocols=TLSv1.3,TLSv1.2
```

### 2. **PKCS12 with Credential Providers (Most Secure)**
- **Externalize passwords** from configuration files
- **Integrate with secret management** systems
- **Supports HashiCorp Vault, Kubernetes Secrets, custom providers**

```properties
quarkus.tls.key-store.p12.path=/app/certificates/keystore.p12
quarkus.tls.key-store.p12.credentials-provider=vault-provider
```

### 3. **Legacy Configuration (Still Functional)**
- **Current PKCS12 approach** with hardcoded passwords
- **Works but not recommended** for production
- **Security risk**: passwords in plain text configuration

```properties
# Current approach (functional but less secure)
quarkus.http.ssl.certificate.key-store-file=/app/certificates/keystore.p12
quarkus.http.ssl.certificate.key-store-password=integration-test
```

## Security Benefits of Alternatives

### PEM Files Advantages:
1. **No password required** for private key storage
2. **File system permissions** provide security
3. **Easier certificate rotation** and management
4. **Standard format** used by most certificate authorities
5. **Compatible with Let's Encrypt** and cert-manager

### Credential Provider Advantages:
1. **Zero secrets in configuration** files
2. **Integration with enterprise secret management**
3. **Automatic credential rotation** capabilities
4. **Audit trail** for secret access
5. **Kubernetes-native** secret integration

## Production Recommendations

### For Container Environments:
```properties
# Option 1: PEM files with proper file permissions
quarkus.tls.key-store.pem.0.cert=/app/certificates/server.crt
quarkus.tls.key-store.pem.0.key=/app/certificates/server.key

# Option 2: PKCS12 with credential provider
quarkus.tls.key-store.p12.path=/app/certificates/keystore.p12
quarkus.tls.key-store.p12.credentials-provider=k8s-secrets
```

### Security Hardening:
```bash
# Proper file permissions for PEM files
chmod 644 /app/certificates/server.crt  # Certificate (public)
chmod 600 /app/certificates/server.key  # Private key (restricted)
chown nonroot:nonroot /app/certificates/*
```

## External Secret Management Integration

### HashiCorp Vault:
```properties
quarkus.vault.url=https://vault.example.com:8200
quarkus.vault.credentials-provider.ssl.kv-path=secret/ssl
quarkus.tls.key-store.p12.credentials-provider=ssl
```

### Kubernetes Secrets:
```properties
quarkus.kubernetes-config.secrets.enabled=true
quarkus.tls.key-store.p12.credentials-provider=k8s-ssl-secret
```

## Migration Path

1. **Immediate**: Continue using current PKCS12 approach for stability
2. **Short-term**: Extract PEM files and test PEM configuration
3. **Long-term**: Implement credential providers for production deployment
4. **Enterprise**: Integrate with HashiCorp Vault or equivalent

## Conclusion

**Yes, Quarkus can handle SSL certificates without password-protected keystores.** The PEM file approach is **more secure and simpler** for container environments, while credential providers offer **enterprise-grade secret management** integration.

For our integration tests, we should:
1. **Keep current PKCS12** approach for immediate functionality
2. **Add PEM alternative** configurations for demonstration
3. **Document credential provider** options for production guidance
4. **Recommend PEM + proper file permissions** as the preferred approach

The password-protected keystore is **not necessary** and actually **less secure** than modern alternatives when properly implemented.