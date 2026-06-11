package httpapi

import (
	"net/http"
	"strings"
)

type Config struct {
	BaseURL                                         string
	Version                                         string
	ClientID                                        string
	IDPIssuer                                       string
	Subject                                         string
	AccountServerURL                                string
	AccountEmail                                    string
	AccountPassword                                 string
	AccountWebID                                    string
	AuthorizationServerURL                          string
	AuthorizationServerTokenEndpoint                string
	AuthorizationServerPermissionEndpoint           string
	AuthorizationServerIntrospectionEndpoint        string
	AuthorizationServerResourceRegistrationEndpoint string
	AuthorizationServerRegistrationEndpoint         string
	AASIssuer                                       string
	UASIssuer                                       string
	UASDerivationResourcesEndpoint                  string
	DerivationResourceIDPrefix                      string
	FailDerivedFromUpdate                           bool
	OutputReadScope                                 string
	ValidOutputRPTs                                 []string
	UpstreamRPT                                     string
	AccountHTTPClient                               *http.Client
	SourceHTTPClient                                *http.Client
	OxigraphBinary                                  string
	OxigraphWorkdir                                 string
	OutputsDirectory                                string
	ClientIdentifierPath                            string
	ManagementEndpointPath                          string
	TransformationCatalogPath                       string
	SupportedManagementFlows                        []string
	SupportedManagementFormats                      []string
}

func DefaultConfig(baseURL string) Config {
	return Config{
		BaseURL:                    strings.TrimRight(baseURL, "/"),
		Version:                    "0.1.0",
		ClientID:                   "aggregator-provision",
		IDPIssuer:                  "https://idp.example",
		Subject:                    "https://aggregator.example/profile/card#me",
		AASIssuer:                  "https://aas.example",
		UASIssuer:                  "https://uas.example",
		DerivationResourceIDPrefix: "derivation-resource",
		OutputReadScope:            "read",
		ValidOutputRPTs:            []string{"valid-output-rpt"},
		UpstreamRPT:                "valid-upstream-rpt",
		OxigraphBinary:             "oxigraph",
		OxigraphWorkdir:            "./data/oxigraph-workspaces",
		OutputsDirectory:           "./data/outputs",
		ClientIdentifierPath:       "/client.jsonld",
		ManagementEndpointPath:     "/registration",
		TransformationCatalogPath:  "/transformations",
		SupportedManagementFlows:   []string{"provision"},
		SupportedManagementFormats: []string{"application/json"},
	}
}

func (c Config) absolute(path string) string {
	baseURL := strings.TrimRight(c.BaseURL, "/")
	if path == "" {
		return baseURL
	}
	return baseURL + "/" + strings.TrimLeft(path, "/")
}

func (c Config) provisionSubject() string {
	if c.AccountWebID != "" {
		return c.AccountWebID
	}
	return c.Subject
}

func (c Config) hasAccountCredentials() bool {
	return c.AccountServerURL != "" && c.AccountEmail != "" && c.AccountPassword != "" && c.AccountWebID != ""
}

func (c Config) authorizationServerURL() string {
	if c.AuthorizationServerURL != "" {
		return strings.TrimRight(c.AuthorizationServerURL, "/")
	}
	return strings.TrimRight(c.AASIssuer, "/")
}
