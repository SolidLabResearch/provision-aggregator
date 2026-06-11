package httpapi

import "testing"

func TestApplyConfigFileLoadsAuthorizationServerEndpoints(t *testing.T) {
	cfg, err := applyConfigFile([]byte(`{
		"authorization_server": "https://as.example/uma",
		"authorization_server_token_endpoint": "https://as.example/uma/token",
		"authorization_server_permission_endpoint": "https://as.example/uma/permission",
		"authorization_server_introspection_endpoint": "https://as.example/uma/introspect",
		"authorization_server_resource_registration_endpoint": "https://as.example/uma/resources",
		"authorization_server_registration_endpoint": "https://as.example/uma/register",
		"uas_derivation_resources_endpoint": "https://uas.example/derivation-resources"
	}`), DefaultConfig("https://aggregator.example"))
	if err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if cfg.AuthorizationServerURL != "https://as.example/uma" ||
		cfg.AuthorizationServerTokenEndpoint != "https://as.example/uma/token" ||
		cfg.AuthorizationServerPermissionEndpoint != "https://as.example/uma/permission" ||
		cfg.AuthorizationServerIntrospectionEndpoint != "https://as.example/uma/introspect" ||
		cfg.AuthorizationServerResourceRegistrationEndpoint != "https://as.example/uma/resources" ||
		cfg.AuthorizationServerRegistrationEndpoint != "https://as.example/uma/register" ||
		cfg.UASDerivationResourcesEndpoint != "https://uas.example/derivation-resources" {
		t.Fatalf("config = %#v", cfg)
	}
}
