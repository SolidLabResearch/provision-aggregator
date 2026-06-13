package httpapi

import (
	"encoding/json"
	"errors"
	"os"
)

type fileConfig struct {
	BaseURL                                         *string  `json:"base_url"`
	Version                                         *string  `json:"version"`
	ClientID                                        *string  `json:"client_id"`
	Subject                                         *string  `json:"subject"`
	AccountServerURL                                *string  `json:"account_server"`
	AccountEmail                                    *string  `json:"email"`
	AccountPassword                                 *string  `json:"password"`
	AccountWebID                                    *string  `json:"web_id"`
	AuthorizationServerURL                          *string  `json:"authorization_server"`
	AuthorizationServerTokenEndpoint                *string  `json:"authorization_server_token_endpoint"`
	AuthorizationServerPermissionEndpoint           *string  `json:"authorization_server_permission_endpoint"`
	AuthorizationServerIntrospectionEndpoint        *string  `json:"authorization_server_introspection_endpoint"`
	AuthorizationServerResourceRegistrationEndpoint *string  `json:"authorization_server_resource_registration_endpoint"`
	AuthorizationServerRegistrationEndpoint         *string  `json:"authorization_server_registration_endpoint"`
	AASIssuer                                       *string  `json:"aas_issuer"`
	UASDerivationResourcesEndpoint                  *string  `json:"uas_derivation_resources_endpoint"`
	DerivationResourceIDPrefix                      *string  `json:"derivation_resource_id_prefix"`
	OutputReadScope                                 *string  `json:"output_read_scope"`
	ValidOutputRPTs                                 []string `json:"valid_output_rpts"`
	UpstreamRPT                                     *string  `json:"upstream_rpt"`
	OxigraphBinary                                  *string  `json:"oxigraph_binary"`
	OxigraphWorkdir                                 *string  `json:"oxigraph_workdir"`
	OutputsDirectory                                *string  `json:"outputs_directory"`
	ClientIdentifierPath                            *string  `json:"client_identifier_path"`
	ManagementEndpointPath                          *string  `json:"management_endpoint_path"`
	TransformationCatalogPath                       *string  `json:"transformation_catalog_path"`
	SupportedManagementFlows                        []string `json:"supported_management_flows"`
	SupportedManagementFormats                      []string `json:"supported_management_formats"`
}

func LoadOptionalConfigFile(path string, cfg Config) (Config, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return cfg, err
	}
	return applyConfigFile(body, cfg)
}

func applyConfigFile(body []byte, cfg Config) (Config, error) {
	var file fileConfig
	if err := json.Unmarshal(body, &file); err != nil {
		return cfg, err
	}

	setString(file.BaseURL, &cfg.BaseURL)
	setString(file.Version, &cfg.Version)
	setString(file.ClientID, &cfg.ClientID)
	setString(file.Subject, &cfg.Subject)
	setString(file.AccountServerURL, &cfg.AccountServerURL)
	setString(file.AccountEmail, &cfg.AccountEmail)
	setString(file.AccountPassword, &cfg.AccountPassword)
	setString(file.AccountWebID, &cfg.AccountWebID)
	setString(file.AuthorizationServerURL, &cfg.AuthorizationServerURL)
	setString(file.AuthorizationServerTokenEndpoint, &cfg.AuthorizationServerTokenEndpoint)
	setString(file.AuthorizationServerPermissionEndpoint, &cfg.AuthorizationServerPermissionEndpoint)
	setString(file.AuthorizationServerIntrospectionEndpoint, &cfg.AuthorizationServerIntrospectionEndpoint)
	setString(file.AuthorizationServerResourceRegistrationEndpoint, &cfg.AuthorizationServerResourceRegistrationEndpoint)
	setString(file.AuthorizationServerRegistrationEndpoint, &cfg.AuthorizationServerRegistrationEndpoint)
	setString(file.AASIssuer, &cfg.AASIssuer)
	setString(file.UASDerivationResourcesEndpoint, &cfg.UASDerivationResourcesEndpoint)
	setString(file.DerivationResourceIDPrefix, &cfg.DerivationResourceIDPrefix)
	setString(file.OutputReadScope, &cfg.OutputReadScope)
	setString(file.UpstreamRPT, &cfg.UpstreamRPT)
	setString(file.OxigraphBinary, &cfg.OxigraphBinary)
	setString(file.OxigraphWorkdir, &cfg.OxigraphWorkdir)
	setString(file.OutputsDirectory, &cfg.OutputsDirectory)
	setString(file.ClientIdentifierPath, &cfg.ClientIdentifierPath)
	setString(file.ManagementEndpointPath, &cfg.ManagementEndpointPath)
	setString(file.TransformationCatalogPath, &cfg.TransformationCatalogPath)

	if file.ValidOutputRPTs != nil {
		cfg.ValidOutputRPTs = append([]string(nil), file.ValidOutputRPTs...)
	}
	if file.SupportedManagementFlows != nil {
		cfg.SupportedManagementFlows = append([]string(nil), file.SupportedManagementFlows...)
	}
	if file.SupportedManagementFormats != nil {
		cfg.SupportedManagementFormats = append([]string(nil), file.SupportedManagementFormats...)
	}
	return cfg, nil
}

func setString(value *string, target *string) {
	if value != nil {
		*target = *value
	}
}
