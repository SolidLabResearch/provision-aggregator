package httpapi

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Config struct {
	BaseURL                                         string
	Port                                            int
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
		Port:                         8080,
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
  $sourceIndex$ <http://example.com/includes> ?object
}`,
		MediaProfileQuery: `SELECT * WHERE {
  ?s ?p ?o .
}`,
		UpstreamDerivationResourceName: "Aggregated Media Profile",
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

// listenPort is the local TCP port the HTTP server binds to. It is independent
// of BaseURL, which is the public address advertised behind a reverse proxy
// (e.g. https://example.org/aggregator).
func (c Config) listenPort() int {
	if c.Port == 0 {
		return 8080
	}
	return c.Port
}

// ListenAddr returns the address passed to http.Server.Addr (e.g. ":8080").
func (c Config) ListenAddr() string {
	return fmt.Sprintf(":%d", c.listenPort())
}

// LocalURL is the loopback URL the server is reachable on locally, used for
// startup logging since BaseURL points at the public reverse-proxy address.
func (c Config) LocalURL() string {
	return fmt.Sprintf("http://localhost:%d", c.listenPort())
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
  $sourceIndex$ <http://example.com/includes> ?object
}`)
}

func (c Config) mediaProfileQuery() string {
	return defaultString(c.MediaProfileQuery, `SELECT * WHERE {
  ?s ?p ?o .
}`)
}

func (c Config) upstreamDerivationResourceName() string {
	return defaultString(c.UpstreamDerivationResourceName, "Aggregated Media Profile")
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
