package io.github.stefanmaric.keycloak.jwtuser;

import java.util.List;
import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticator;
import org.keycloak.authentication.authenticators.conditional.ConditionalAuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.provider.ProviderConfigurationBuilder;

public class UrlParamConditionFactory implements ConditionalAuthenticatorFactory {

	public static final String ID = "conditional-url-param";
	public static final String CONFIG_PARAM_NAME = "param";
	public static final String CONFIG_PARAM_VALUE = "value";

	private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES =
		new AuthenticationExecutionModel.Requirement[] {
			AuthenticationExecutionModel.Requirement.REQUIRED,
			AuthenticationExecutionModel.Requirement.DISABLED,
		};

	private static final List<ProviderConfigProperty> CONFIG_PROPERTIES =
		ProviderConfigurationBuilder.create()
			.property()
			.name(CONFIG_PARAM_NAME)
			.label("URL parameter name")
			.helpText("Query parameter key to check on the authentication request URL.")
			.type(ProviderConfigProperty.STRING_TYPE)
			.required(true)
			.add()
			.property()
			.name(CONFIG_PARAM_VALUE)
			.label("Expected value (optional)")
			.helpText("If set, the parameter must equal this value. If empty, only presence is required.")
			.type(ProviderConfigProperty.STRING_TYPE)
			.add()
			.build();

	@Override
	public Authenticator create(KeycloakSession session) {
		return UrlParamCondition.SINGLETON;
	}

	@Override
	public void init(Config.Scope config) {}

	@Override
	public void postInit(KeycloakSessionFactory factory) {}

	@Override
	public void close() {}

	@Override
	public String getId() {
		return ID;
	}

	@Override
	public String getDisplayType() {
		return "Condition - URL parameter";
	}

	@Override
	public boolean isConfigurable() {
		return true;
	}

	@Override
	public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
		return REQUIREMENT_CHOICES;
	}

	@Override
	public boolean isUserSetupAllowed() {
		return false;
	}

	@Override
	public String getHelpText() {
		return "Executes the sub-flow only if a URL query parameter is present and optionally matches a value.";
	}

	@Override
	public List<ProviderConfigProperty> getConfigProperties() {
		return CONFIG_PROPERTIES;
	}

	@Override
	public ConditionalAuthenticator getSingleton() {
		return UrlParamCondition.SINGLETON;
	}
}
