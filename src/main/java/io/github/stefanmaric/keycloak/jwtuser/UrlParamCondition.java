package io.github.stefanmaric.keycloak.jwtuser;

import java.util.Map;
import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;

/**
 * Conditional authenticator that matches based on a URL query parameter.
 *
 * Configuration:
 * - param: required query parameter name
 * - value: optional value to match; if empty, presence of the parameter is enough
 */
public class UrlParamCondition implements ConditionalAuthenticator {

	public static final UrlParamCondition SINGLETON = new UrlParamCondition();

	private static final Logger LOG = Logger.getLogger(UrlParamCondition.class);

	@Override
	public boolean matchCondition(AuthenticationFlowContext context) {
		Map<String, String> cfg = context.getAuthenticatorConfig() != null
			? context.getAuthenticatorConfig().getConfig()
			: null;

		if (cfg == null) {
			LOG.debug("UrlParamCondition: no config provided; condition will not match");
			return false;
		}

		String param = cfg.get(UrlParamConditionFactory.CONFIG_PARAM_NAME);
		String expectedValue = cfg.get(UrlParamConditionFactory.CONFIG_PARAM_VALUE);

		if (param == null || param.isBlank()) {
			LOG.debug("UrlParamCondition: missing 'param' in config; condition will not match");
			return false;
		}

		String actual = null;
		boolean contains = false;
		try {
			var query = context.getHttpRequest().getUri().getQueryParameters();
			contains = query.containsKey(param);
			actual = query.getFirst(param);
		} catch (Exception ignored) {
			// ignore
		}

		// If no value configured, only presence is required
		if (expectedValue == null || expectedValue.isBlank()) {
			LOG.debugf("UrlParamCondition: param=%s present=%s (value not required)", param, contains);
			return contains;
		}

		boolean match = expectedValue.equals(actual);
		LOG.debugf(
			"UrlParamCondition: param=%s expected=%s actual=%s match=%s",
			param,
			expectedValue,
			actual,
			match
		);
		return match;
	}

	@Override
	public void action(AuthenticationFlowContext context) {
		// not used for conditions
	}

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
