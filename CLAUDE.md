# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

This is a Keycloak SPI (Service Provider Interface) extension that provides a passive JWT-based authenticator. It validates signed JWTs passed in URL query parameters to enable passwordless authentication flows, magic links, and SSO scenarios.

**Target Platform**: Keycloak 26.x, Java 21

## Build Commands

```bash
# Build the provider JAR (produces a shaded JAR with dependencies)
./gradlew shadowJar

# Output location: build/libs/keycloak-jwt-user-authenticator-<version>.jar
```

The build uses the Shadow plugin to produce a single JAR with shaded dependencies (Nimbus JOSE JWT and Google Tink). Keycloak SPIs are marked as `compileOnly` and provided by the Keycloak runtime.

## Architecture

### SPI Implementations

The codebase implements two Keycloak SPI providers:

1. **JWT User Authenticator** (`JwtUserAuthenticator` + `JwtUserAuthenticatorFactory`)
   - Core authentication logic that validates JWT tokens from URL parameters
   - Returns `attempted()` (flow continues) if token is missing/invalid
   - Returns `success()` and sets user if token is valid
   - Validates: signature (JWKS), iss, aud, exp, iat, lifespan, sub, jti uniqueness

2. **URL Parameter Condition** (`UrlParamCondition` + `UrlParamConditionFactory`)
   - Conditional authenticator for flow control based on URL query parameters
   - Used in conditional sub-flows to control execution paths
   - Can check for parameter presence or match specific values

### Provider Registration

Providers are registered via Java SPI mechanism in:
```
src/main/resources/META-INF/services/org.keycloak.authentication.AuthenticatorFactory
```

Both factory classes must be listed in this file for Keycloak to discover them.

### Key Components

**JwtUserAuthenticator** (src/main/java/io/github/stefanmaric/keycloak/jwtuser/JwtUserAuthenticator.java:32)
- Main authentication logic in `authenticate()` method
- JWKS caching via `JWKS_CACHE` ConcurrentHashMap (line 339)
- Signature verification for RSA, ECDSA (P-256/P-384/P-521), and Ed25519 keys (line 355)
- All validation failures return `attempted()` to allow flow continuation

**JwtUserAuthenticatorFactory** (src/main/java/io/github/stefanmaric/keycloak/jwtuser/JwtUserAuthenticatorFactory.java:14)
- Defines configuration properties exposed in Keycloak Admin Console
- Uses singleton pattern for authenticator instance (line 22)
- Configuration keys:
  - `trustedIssuerId`: Expected JWT `iss` claim
  - `trustedJwksJson`: Static JWKS containing public keys
  - `jwtQueryParameterName`: URL parameter name for JWT
  - `maxTokenLifespanSeconds`: Max allowed (exp - iat) in seconds

### JWT Validation Flow

1. Extract JWT from configured query parameter
2. Parse and verify it's a signed JWT (not plain/unsecured)
3. Validate `kid` header is present
4. Match `kid` against configured JWKS
5. Verify signature using appropriate algorithm (RSA/ECDSA/Ed25519)
6. Validate claims:
   - `iss` matches configured Trusted Issuer ID
   - `aud` contains realm issuer URL (`https://<host>/realms/<realm>`)
   - `exp` is in the future
   - `iat` is present
   - `exp - iat ≤ maxTokenLifespanSeconds`
   - `sub` is a valid Keycloak user ID in the realm
   - `jti` is present (uniqueness check not shown in current code)
   - User is enabled
7. Set user and return success

### Security Design

- **Passive authenticator**: Never shows UI or blocks the flow; returns `attempted()` on any failure
- **Signature-only**: Uses signed JWTs (JWS), not encrypted (JWE)
- **Token replay**: `jti` (JWT ID) claim required for one-time use semantics
- **Limited lifespan**: Default max 3 hours (10800 seconds); warns if > 3 days
- **User lookup by ID**: `sub` claim must be Keycloak's internal user ID (UUID), not username

## Development Workflow

### Testing Changes Locally

1. Build the JAR: `./gradlew shadowJar`
2. Copy `build/libs/keycloak-jwt-user-authenticator-<version>.jar` to your Keycloak `providers/` directory
3. Restart Keycloak
4. Check server logs for provider registration or errors
5. Verify "JWT User" appears in Authentication → Add Execution in Admin Console

### Code Style

- Uses modern Java 21 features (pattern matching, records where appropriate)
- Structured logging with jboss-logging (messages include structured fields for parsing)
- Log format: `message=<description>, type=<ERROR_TYPE>, issuer=<iss>, kid=<kid>, jti=<jti>, ...`
- Configuration validation at execution time (not startup) to avoid blocking other flows

### Common Validation Error Types

These appear in logs and help diagnose issues:
- `CONFIG_ISSUE`: Missing or invalid configuration
- `JWT_PARSE_ERROR`: Malformed JWT
- `UNSECURED_TOKEN`: JWT without signature
- `JWT_HEADER_ERROR`: Missing `kid` header
- `INVALID_SIGNATURE`: Signature verification failed
- `ISSUER_MISMATCH`: `iss` claim doesn't match config
- `AUDIENCE_MISMATCH`: `aud` doesn't contain realm URL
- `TOKEN_EXPIRED`: Token past expiration
- `MISSING_IAT`/`MISSING_EXP`: Required time claims absent
- `NEGATIVE_LIFESPAN`: `exp` before `iat`
- `LIFESPAN_EXCEEDS_MAX`: Token lifespan too long
- `MISSING_SUBJECT`: No `sub` claim
- `USER_NOT_FOUND`: `sub` doesn't match any Keycloak user
- `USER_DISABLED`: Matched user account is disabled
- `POLICY_WARN`: Configuration warning (e.g., excessive lifespan)

## Dependencies

Key dependencies (shaded into provider JAR):
- **Nimbus JOSE JWT** (10.5): JWT parsing, signature verification, JWKS support
- **Google Tink** (1.18.0): Cryptographic operations

Keycloak SPIs (provided at runtime):
- `keycloak-server-spi` / `keycloak-server-spi-private` / `keycloak-services`

## Important Notes

- The authenticator is stateless and uses singleton pattern for efficiency
- JWKS is cached in memory by JSON hash; cache persists until Keycloak restart
- No database interaction except user lookup via Keycloak's UserStorageProvider
- JTI replay tracking mentioned in docs but not visible in current code (may be implemented elsewhere or pending)
- Token must be passed in URL parameter (not Authorization header) by design for link-based flows
