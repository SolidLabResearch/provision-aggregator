package httpapi

import (
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL                                         string
	Version                                         string
	ClientID                                        string
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
	UASDerivationResourcesEndpoint                  string
	DerivationResourceIDPrefix                      string
	TransformationFragment                          string
	TransformationLabel                             string
	TransformationDescription                       string
	TransformationComment                           string
	TransformationSourceFragment                    string
	TransformationSourceLabel                       string
	TransformationOutputFragment                    string
	TransformationOutputLabel                       string
	MediaProfileIndexQuery                          string
	MediaProfileQuery                               string
	UpstreamDerivationResourceName                  string
	MinimumAccessibleSources                        int
	MinimumAccessibleSourceRatio                    float64
	SourceAvailabilityPollInterval                  time.Duration
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
		BaseURL:                      strings.TrimRight(baseURL, "/"),
		Version:                      "0.1.0",
		ClientID:                     "aggregator-provision",
		Subject:                      "https://aggregator.example/profile/card#me",
		AASIssuer:                    "https://aas.example",
		DerivationResourceIDPrefix:   "derivation-resource",
		TransformationFragment:       "MediaProfileAggregation",
		TransformationLabel:          "Media Profile Aggregation",
		TransformationDescription:    "Aggregates multiple media profiles and psuedomizes them and generates one aggreagted media profile.",
		TransformationComment:        "Aggregates multiple media profiles and psuedomizes them and generates one aggreagted media profile.",
		TransformationSourceFragment: "Source",
		TransformationSourceLabel:    "Source",
		TransformationOutputFragment: "MediaProfile",
		TransformationOutputLabel:    "MediaProfile",
		MediaProfileIndexQuery: `SELECT DISTINCT ?object WHERE {
  ?subject <http://example.com/includes> ?object
}`,
		MediaProfileQuery: `SELECT * WHERE {
  ?s ?p ?o .
}`,
		UpstreamDerivationResourceName: "Aggregator Media Profile",
		MinimumAccessibleSources:       2,
		MinimumAccessibleSourceRatio:   0.7,
		OutputReadScope:                "read",
		ValidOutputRPTs:                []string{"valid-output-rpt"},
		UpstreamRPT:                    "valid-upstream-rpt",
		OxigraphBinary:                 "oxigraph",
		OxigraphWorkdir:                "./data/oxigraph-workspaces",
		OutputsDirectory:               "./data/outputs",
		ClientIdentifierPath:           "/client.jsonld",
		ManagementEndpointPath:         "/registration",
		TransformationCatalogPath:      "/transformations",
		SupportedManagementFlows:       []string{"provision"},
		SupportedManagementFormats:     []string{"application/json"},
	}
}

func (c Config) absolute(path string) string {
	baseURL := strings.TrimRight(c.BaseURL, "/")
	if path == "" {
		return baseURL
	}
	return baseURL + "/" + strings.TrimLeft(path, "/")
}

func (c Config) routePrefix() string {
	parsed, err := url.Parse(c.BaseURL)
	if err != nil {
		return ""
	}
	prefix := "/" + strings.Trim(parsed.EscapedPath(), "/")
	if prefix == "/" {
		return ""
	}
	return prefix
}

func (c Config) provisionSubject() string {
	if c.AccountWebID != "" {
		return c.AccountWebID
	}
	return c.Subject
}

func (c Config) provisionIDP() string {
	return strings.TrimRight(c.AccountServerURL, "/")
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

func (c Config) transformationFragment() string {
	return defaultString(c.TransformationFragment, "MediaProfileAggregation")
}

func (c Config) transformationLabel() string {
	return defaultString(c.TransformationLabel, "Media Profile Aggregation")
}

func (c Config) transformationDescription() string {
	return defaultString(c.TransformationDescription, "Aggregates multiple media profiles and psuedomizes them and generates one aggreagted media profile.")
}

func (c Config) transformationComment() string {
	return defaultString(c.TransformationComment, c.transformationDescription())
}

func (c Config) transformationSourceFragment() string {
	return defaultString(c.TransformationSourceFragment, "Source")
}

func (c Config) transformationSourceLabel() string {
	return defaultString(c.TransformationSourceLabel, "Source")
}

func (c Config) transformationOutputFragment() string {
	return defaultString(c.TransformationOutputFragment, "MediaProfile")
}

func (c Config) transformationOutputLabel() string {
	return defaultString(c.TransformationOutputLabel, "MediaProfile")
}

func (c Config) mediaProfileIndexQuery() string {
	return defaultString(c.MediaProfileIndexQuery, `SELECT DISTINCT ?object WHERE {
  ?subject <http://example.com/includes> ?object
}`)
}

func (c Config) mediaProfileQuery() string {
	return defaultString(c.MediaProfileQuery, `SELECT * WHERE {
  ?s ?p ?o .
}`)
}

func (c Config) upstreamDerivationResourceName() string {
	return defaultString(c.UpstreamDerivationResourceName, "Aggregator Media Profile")
}

func (c Config) minimumAccessibleSources() int {
	if c.MinimumAccessibleSources < 0 {
		return 0
	}
	return c.MinimumAccessibleSources
}

func (c Config) minimumAccessibleSourceRatio() float64 {
	if c.MinimumAccessibleSourceRatio < 0 {
		return 0
	}
	return c.MinimumAccessibleSourceRatio
}

func (c Config) sourceAvailabilityPollInterval() time.Duration {
	if c.SourceAvailabilityPollInterval > 0 {
		return c.SourceAvailabilityPollInterval
	}
	return 2 * time.Second
}

func defaultString(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}
