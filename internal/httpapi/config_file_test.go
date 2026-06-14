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

func TestApplyConfigFileLoadsMediaProfileTransformationConfig(t *testing.T) {
	cfg, err := applyConfigFile([]byte(`{
		"transformation_fragment": "CustomAggregation",
		"transformation_label": "Custom Aggregation",
		"transformation_description": "Custom description",
		"transformation_comment": "Custom comment",
		"transformation_source_fragment": "InputIndex",
		"transformation_source_label": "Input index",
		"transformation_output_fragment": "OutputProfile",
		"transformation_output_label": "Output profile",
		"media_profile_index_query": "SELECT ?profile WHERE { ?index <http://example.com/includes> ?profile }",
		"media_profile_query": "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }",
		"upstream_derivation_resource_name": "Custom derived profile",
		"minimum_accessible_sources": 3,
		"minimum_accessible_source_ratio": 0.8
	}`), DefaultConfig("https://aggregator.example"))
	if err != nil {
		t.Fatalf("apply config: %v", err)
	}
	if supportedTransformationURL(cfg) != "https://aggregator.example/transformations#CustomAggregation" ||
		transformationSourceParameterURL(cfg) != "https://aggregator.example/transformations#InputIndex" ||
		transformationOutputURL(cfg) != "https://aggregator.example/transformations#OutputProfile" ||
		cfg.transformationLabel() != "Custom Aggregation" ||
		cfg.transformationDescription() != "Custom description" ||
		cfg.transformationComment() != "Custom comment" ||
		cfg.transformationSourceLabel() != "Input index" ||
		cfg.transformationOutputLabel() != "Output profile" ||
		cfg.mediaProfileIndexQuery() != "SELECT ?profile WHERE { ?index <http://example.com/includes> ?profile }" ||
		cfg.mediaProfileQuery() != "CONSTRUCT { ?s ?p ?o } WHERE { ?s ?p ?o }" ||
		cfg.upstreamDerivationResourceName() != "Custom derived profile" ||
		cfg.minimumAccessibleSources() != 3 ||
		cfg.minimumAccessibleSourceRatio() != 0.8 {
		t.Fatalf("config = %#v", cfg)
	}
}
