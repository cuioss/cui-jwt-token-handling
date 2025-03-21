# Log Messages for JWT Token Module

All messages follow the format: JWTToken-[identifier]: [message]

## INFO Level (001-099)

| ID | Component | Message | Description |
|----|-----------|---------|-------------|
| JWTToken-001 | JWKS | Initializing JWKS lookup, jwks-endpoint='%s', refresh-interval='%s', issuer='%s' | Logged during startup when configuring JWKS-based token validation |

## WARN Level (100-199)

| ID | Component | Message | Description |
|----|-----------|---------|-------------|
| JWTToken-100 | TOKEN | Token exceeds maximum size limit of %s bytes, token will be rejected | Logged when a token is rejected due to size constraints |
| JWTToken-101 | TOKEN | The given token was empty, request will be rejected | Logged when an empty or null token is provided |
| JWTToken-102 | TOKEN | Unable to parse token due to ParseException: %s | Logged when token parsing fails due to format or content issues |
| JWTToken-103 | TOKEN | No key found with ID: %s | Logged when a key with the specified ID cannot be found in the JWKS |
| JWTToken-104 | TOKEN | Token issuer '%s' does not match expected issuer '%s' | Logged when the issuer in the token does not match the expected issuer |
| JWTToken-105 | JWKS | Failed to fetch JWKS: HTTP %s | Logged when there is an HTTP error fetching the JWKS |
| JWTToken-106 | JWKS | Error refreshing JWKS: %s | Logged when there is an error refreshing the JWKS |
| JWTToken-107 | JWKS | Failed to parse RSA key with ID %s: %s | Logged when there is an error parsing an RSA key from the JWKS |
| JWTToken-108 | JWKS | Failed to parse JWKS JSON: %s | Logged when there is an error parsing the JWKS JSON |
| JWTToken-109 | TOKEN | Failed to decode JWT token | Logged when the JWT token cannot be decoded |
| JWTToken-110 | JWKS | No keys available in JWKS | Logged when no keys are available in the JWKS |
| JWTToken-111 | TOKEN | Error parsing token: %s | Logged when there is a general error parsing the token |
| JWTToken-112 | TOKEN | Invalid JWT token format: expected 3 parts but got %s | Logged when the JWT token format is invalid |
| JWTToken-113 | TOKEN | Failed to decode header part | Logged when the header part of the JWT token cannot be decoded |
| JWTToken-114 | TOKEN | Failed to decode payload part | Logged when the payload part of the JWT token cannot be decoded |
| JWTToken-115 | TOKEN | Failed to parse token: %s | Logged when there is an error parsing the token |
| JWTToken-116 | TOKEN | Decoded part exceeds maximum size limit of %s bytes | Logged when a decoded part of the token exceeds the maximum size limit |
| JWTToken-117 | TOKEN | Failed to decode part: %s | Logged when a part of the token cannot be decoded |
| JWTToken-118 | JWKS | Failed to fetch JWKS from URL: %s | Logged when there is an error fetching the JWKS from the URL |
| JWTToken-119 | JWKS | JWKS JSON does not contain 'keys' array or 'kty' field | Logged when the JWKS JSON is missing required fields |
| JWTToken-120 | JWKS | JWK is missing required field 'kty' | Logged when a JWK is missing the required 'kty' field |
| JWTToken-121 | TOKEN | Token has a 'not before' claim that is more than 60 seconds in the future | Logged when a token has a 'not before' claim that is too far in the future |
| JWTToken-122 | TOKEN | Unknown token type: %s | Logged when an unknown token type is encountered |
| JWTToken-123 | JWKS | Failed to read JWKS from file: %s | Logged when there is an error reading the JWKS from a file |
