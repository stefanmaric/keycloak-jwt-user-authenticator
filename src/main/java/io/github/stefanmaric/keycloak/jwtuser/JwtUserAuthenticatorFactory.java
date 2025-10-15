package io.github.stefanmaric.keycloak.jwtuser;

import java.util.Collections;
import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class JwtUserAuthenticatorFactory implements AuthenticatorFactory {

	public static final String ID = "jwt-user-authenticator";
	public static final String CONFIG_TRUSTED_ISSUER_ID = "trustedIssuerId";
	public static final String CONFIG_TRUSTED_JWKS_JSON = "trustedJwksJson";
	public static final String CONFIG_JWT_QUERY_PARAM = "jwtQueryParameterName";
	public static final String CONFIG_MAX_TOKEN_LIFESPAN_SECONDS = "maxTokenLifespanSeconds";

	private static final JwtUserAuthenticator SINGLETON = new JwtUserAuthenticator();
	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES =
		Collections.unmodifiableList(
			ProviderConfigurationBuilder.create()
				.property()
				.name(CONFIG_TRUSTED_ISSUER_ID)
				.label("Trusted Issuer ID")
				.helpText("Expected 'iss' claim value. Required.")
				.type(ProviderConfigProperty.STRING_TYPE)
				.required(true)
				.add()
				.property()
				.name(CONFIG_TRUSTED_JWKS_JSON)
				.label("Trusted JWKS (JSON)")
				.helpText("Static JSON Web Key Set containing one or more keys. Required.")
				.type(ProviderConfigProperty.TEXT_TYPE)
				.required(true)
				.add()
				.property()
				.name(CONFIG_JWT_QUERY_PARAM)
				.label("JWT Query Parameter Name")
				.helpText("Name of the query parameter that carries the JWT. Required.")
				.type(ProviderConfigProperty.STRING_TYPE)
				.required(true)
				.add()
				.property()
				.name(CONFIG_MAX_TOKEN_LIFESPAN_SECONDS)
				.label("Max Token Lifespan (seconds)")
				.helpText("Maximum allowed lifespan calculated as (exp - iat). Default is 10800 (3 hours).")
				.type(ProviderConfigProperty.INTEGER_TYPE)
				.defaultValue("10800")
				.add()
				.build()
		);

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public String getDisplayType() {
		return "JWT User";
	}

	@Override
	public String getHelpText() {
		return "Authenticate a user by validating a signed JWT from a URL query parameter (pre-signed link).";
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return new AuthenticationExecutionModel.Requirement[] {
			AuthenticationExecutionModel.Requirement.ALTERNATIVE,
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED,
		};
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public String getReferenceCategory() {
		return "jwt-user";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	@Override
	public Authenticator create(KeycloakSession session) {
		return SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {}

	@Override
	public void postInit(KeycloakSessionFactory factory) {}

	@Override
	public void close() {}
}
