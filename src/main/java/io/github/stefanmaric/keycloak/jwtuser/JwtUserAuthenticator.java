package io.github.stefanmaric.keycloak.jwtuser;

import com.nimbusds.jose.PlainObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.Ed25519Verifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKMatcher;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWT;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.JWTParser;
import com.nimbusds.jwt.SignedJWT;
import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

public class JwtUserAuthenticator implements Authenticator {

	private static final Logger LOG = Logger.getLogger(JwtUserAuthenticator.class);

	@Override
	public void authenticate(AuthenticationFlowContext context) {
		Map<String, String> cfg = context.getAuthenticatorConfig().getConfig();
		String expectedIssuer = cfg.get(JwtUserAuthenticatorFactory.CONFIG_TRUSTED_ISSUER_ID);
		String paramName = cfg.get(JwtUserAuthenticatorFactory.CONFIG_JWT_QUERY_PARAM);
		String jwksJson = cfg.get(JwtUserAuthenticatorFactory.CONFIG_TRUSTED_JWKS_JSON);
		String maxAgeStr = cfg.get(JwtUserAuthenticatorFactory.CONFIG_MAX_TOKEN_LIFESPAN_SECONDS);

		if (expectedIssuer == null || expectedIssuer.isBlank()) {
			LOG.warnf("message=missing trustedIssuerId, type=CONFIG_ISSUE");
			context.attempted();
			return;
		}
		if (paramName == null || paramName.isBlank()) {
			LOG.warnf(
				"message=missing jwtQueryParameterName, type=CONFIG_ISSUE, issuer=%s",
				expectedIssuer
			);
			context.attempted();
			return;
		}
		if (maxAgeStr == null || maxAgeStr.isBlank()) {
			LOG.warnf(
				"message=missing maxTokenLifespanSeconds, type=CONFIG_ISSUE, issuer=%s",
				expectedIssuer
			);
			context.attempted();
			return;
		}
		if (jwksJson == null || jwksJson.isBlank()) {
			LOG.warnf("message=missing trustedJwksJson, type=CONFIG_ISSUE, issuer=%s", expectedIssuer);
			context.attempted();
			return;
		}

		String jwt = null;
		try {
			jwt = context.getHttpRequest().getUri().getQueryParameters().getFirst(paramName);
		} catch (Exception e) {
			// do nothing
		}

		// No JWT provided in the Authorization Request: skip this authenticator.
		if (jwt == null || jwt.isBlank()) {
			context.attempted();
			return;
		}

		long maxAgeSec = Long.parseLong(maxAgeStr);
		if (maxAgeSec > 259200) {
			LOG.warnf(
				"message=excessive token lifespan, type=POLICY_WARN, issuer=%s, value=%d, threshold=259200",
				expectedIssuer,
				maxAgeSec
			);
		}
		if (maxAgeSec <= 0) {
			LOG.warnf(
				"message=invalid maxTokenLifespanSeconds value=%s, type=CONFIG_ISSUE, issuer=%s",
				maxAgeStr,
				expectedIssuer
			);
			context.attempted();
			return;
		}

		ImmutableJWKSet<SecurityContext> keys;

		try {
			keys = parseOrCacheJwks(jwksJson);
		} catch (Exception e) {
			LOG.warnf(
				"message=failed to parse JWKS, type=CONFIG_ISSUE, issuer=%s, error=%s",
				expectedIssuer,
				e.getMessage()
			);
			context.attempted();
			return;
		}

		JWT parsed;
		try {
			parsed = JWTParser.parse(jwt);
		} catch (Exception e) {
			LOG.warnf(
				"message=malformed token, type=JWT_PARSE_ERROR, issuer=%s, error=%s",
				expectedIssuer,
				e.getMessage()
			);
			context.attempted();
			return;
		}

		if (parsed instanceof PlainObject) {
			LOG.warnf(
				"message=unsecured tokens are not supported, type=UNSECURED_TOKEN, issuer=%s, header=%s",
				expectedIssuer,
				parsed.getHeader().toString()
			);
			context.attempted();
			return;
		}

		if (!(parsed instanceof SignedJWT signed)) {
			LOG.warnf(
				"message=unsupported JWT type, type=UNSUPPORTED_JWT_TYPE, issuer=%s",
				expectedIssuer
			);
			context.attempted();
			return;
		}

		String kid = signed.getHeader().getKeyID();
		if (kid == null || kid.isBlank()) {
			LOG.warnf("message=missing kid header, type=JWT_HEADER_ERROR, issuer=%s", expectedIssuer);
			context.attempted();
			return;
		}

		JWKMatcher matcher = new JWKMatcher.Builder().keyID(kid).build();
		List<JWK> matches = keys.get(new JWKSelector(matcher), null);
		JWK jwk = matches.size() == 1 ? matches.getFirst() : null;
		if (jwk == null) {
			LOG.warnf(
				"message=no matching JWK, type=CONFIG_ISSUE, issuer=%s, kid=%s",
				expectedIssuer,
				kid
			);
			context.attempted();
			return;
		}

		JWTClaimsSet claims;

		try {
			if (!verifySignature(signed, jwk)) {
				LOG.warnf(
					"message=invalid signature, type=INVALID_SIGNATURE, issuer=%s, kid=%s",
					expectedIssuer,
					kid
				);
				context.attempted();
				return;
			}
		} catch (Exception e) {
			LOG.warnf(
				"message=signature verification error, type=SIGNATURE_ERROR, issuer=%s, kid=%s, error=%s",
				expectedIssuer,
				kid,
				e.getMessage()
			);
			context.attempted();
			return;
		}

		try {
			claims = signed.getJWTClaimsSet();
		} catch (Exception e) {
			LOG.warnf(
				"message=unable to read claims, type=JWT_CLAIMS_ERROR, issuer=%s, kid=%s, error=%s",
				expectedIssuer,
				kid,
				e.getMessage()
			);
			context.attempted();
			return;
		}

		RealmModel realm = context.getRealm();
		URI base = context.getSession().getContext().getUri().getBaseUri();
		String realmUri = base.resolve("realms/" + realm.getName()).toString();
		Instant now = Instant.now();

		List<String> aud = claims.getAudience();
		String iss = claims.getIssuer();
		String jti = claims.getJWTID();
		String sub = claims.getSubject();
		Instant iat = claims.getIssueTime() != null ? claims.getIssueTime().toInstant() : null;
		Instant exp = claims.getExpirationTime() != null
			? claims.getExpirationTime().toInstant()
			: null;

		if (!expectedIssuer.equals(iss)) {
			LOG.warnf(
				"message=issuer mismatch, type=ISSUER_MISMATCH, issuer=%s, kid=%s, jti=%s, expected=%s actual=%s",
				expectedIssuer,
				kid,
				jti,
				expectedIssuer,
				iss
			);
			context.attempted();
			return;
		}
		if (aud == null || !aud.contains(realmUri)) {
			LOG.warnf(
				"message=audience mismatch, type=AUDIENCE_MISMATCH, issuer=%s, kid=%s, jti=%s, aud=%s, realmUri=%s",
				expectedIssuer,
				kid,
				jti,
				aud,
				realmUri
			);
			context.attempted();
			return;
		}
		if (exp == null) {
			LOG.warnf(
				"message=missing exp, type=MISSING_EXP, issuer=%s, kid=%s, jti=%s",
				expectedIssuer,
				kid,
				jti
			);
			context.attempted();
			return;
		}
		if (exp.isBefore(now)) {
			LOG.warnf(
				"message=token expired, type=TOKEN_EXPIRED, issuer=%s, kid=%s, jti=%s, exp=%d, now=%d",
				expectedIssuer,
				kid,
				jti,
				exp.getEpochSecond(),
				now.getEpochSecond()
			);
			context.attempted();
			return;
		}
		if (iat == null) {
			LOG.warnf(
				"message=missing iat, type=MISSING_IAT, issuer=%s, kid=%s, jti=%s",
				expectedIssuer,
				kid,
				jti
			);
			context.attempted();
			return;
		}
		long lifespan = exp.getEpochSecond() - iat.getEpochSecond();
		if (lifespan < 0) {
			LOG.warnf(
				"message=negative lifespan, type=NEGATIVE_LIFESPAN, issuer=%s, kid=%s, jti=%s, lifespan=%d",
				expectedIssuer,
				kid,
				jti,
				lifespan
			);
			context.attempted();
			return;
		}
		if (lifespan > maxAgeSec) {
			LOG.warnf(
				"message=lifespan exceeds configured max lifespan, type=LIFESPAN_EXCEEDS_MAX, issuer=%s, kid=%s, jti=%s, lifespan=%d, max=%d",
				expectedIssuer,
				kid,
				jti,
				lifespan,
				maxAgeSec
			);
			context.attempted();
			return;
		}
		if (sub == null || sub.isBlank()) {
			LOG.warnf(
				"message=missing subject in token claims, type=MISSING_SUBJECT, issuer=%s, kid=%s, jti=%s",
				expectedIssuer,
				kid,
				jti
			);
			context.attempted();
			return;
		}

		UserModel user = context.getSession().users().getUserById(realm, sub);
		if (user == null) {
			LOG.warnf(
				"message=user not found, type=USER_NOT_FOUND, issuer=%s, kid=%s, jti=%s, sub=%s",
				expectedIssuer,
				kid,
				jti,
				sub
			);
			context.attempted();
			return;
		}

		if (!user.isEnabled()) {
			LOG.warnf(
				"message=disabled user, type=USER_DISABLED, issuer=%s, kid=%s, jti=%s, sub=%s",
				expectedIssuer,
				kid,
				jti,
				sub
			);
			context.attempted();
			return;
		}

		context.setUser(user);
		context.success();
	}

	// ---- JWKS support ----
	private static final java.util.concurrent.ConcurrentHashMap<
		Integer,
		ImmutableJWKSet<SecurityContext>
	> JWKS_CACHE = new java.util.concurrent.ConcurrentHashMap<>();

	private static ImmutableJWKSet<SecurityContext> parseOrCacheJwks(String json) throws Exception {
		int key = json.hashCode();
		ImmutableJWKSet<SecurityContext> existing = JWKS_CACHE.get(key);
		if (existing != null) return existing;
		JWKSet parsed = JWKSet.parse(json);
		ImmutableJWKSet<SecurityContext> wrapped = new ImmutableJWKSet<>(parsed);

		JWKS_CACHE.put(key, wrapped);
		return wrapped;
	}

	private static boolean verifySignature(SignedJWT jwt, JWK jwk) throws Exception {
		if (jwk instanceof RSAKey rsa) {
			return jwt.verify(new RSASSAVerifier(rsa.toRSAPublicKey()));
		} else if (jwk instanceof ECKey ec) {
			return jwt.verify(new ECDSAVerifier(ec));
		} else if (jwk instanceof OctetKeyPair okp) {
			if (Curve.Ed25519.equals(okp.getCurve())) {
				return jwt.verify(new Ed25519Verifier(okp));
			}
			throw new IllegalArgumentException("Unsupported OKP curve: " + okp.getCurve());
		}
		throw new IllegalArgumentException("Unsupported JWK type: " + jwk.getKeyType());
	}

	@Override
	public void action(AuthenticationFlowContext context) {}

	@Override
	public boolean requiresUser() {
		return false;
	}

	@Override
	public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
		return true;
	}

	@Override
	public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {}

	@Override
	public void close() {}
}
