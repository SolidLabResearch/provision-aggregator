package httpapi

import "time"

// Hosted JSON-LD contexts for the Aggregator Server Description and the
// Aggregator Description. The inline contexts were replaced by references to
// these hosted documents (see the spec sections on aggregator-server and
// aggregator metadata).
const (
	serverDescriptionContext     = "https://w3id.org/aggregator/contexts/aggregator-server-description.jsonld"
	aggregatorDescriptionContext = "https://w3id.org/aggregator/contexts/aggregator-description.jsonld"
)

type ServerDescription struct {
	Context                           string   `json:"@context"`
	ID                                string   `json:"aggregator_server_base_url"`
	Type                              string   `json:"type"`
	ManagementEndpoint                string   `json:"management_endpoint"`
	SupportedManagementFlows          []string `json:"supported_management_flows"`
	SupportedManagementRequestFormats []string `json:"supported_management_request_formats"`
	Version                           string   `json:"version"`
	ClientIdentifier                  string   `json:"client_identifier"`
	TransformationCatalog             string   `json:"transformation_catalog"`
}

func BuildServerDescription(cfg Config) ServerDescription {
	return ServerDescription{
		Context:                           serverDescriptionContext,
		ID:                                cfg.absolute("/"),
		Type:                              "AggregatorServer",
		ManagementEndpoint:                cfg.absolute(cfg.ManagementEndpointPath),
		SupportedManagementFlows:          append([]string(nil), cfg.SupportedManagementFlows...),
		SupportedManagementRequestFormats: append([]string(nil), cfg.SupportedManagementFormats...),
		Version:                           cfg.Version,
		ClientIdentifier:                  cfg.absolute(cfg.ClientIdentifierPath),
		TransformationCatalog:             cfg.absolute(cfg.TransformationCatalogPath),
	}
}

type AggregatorDescription struct {
	Context                   string `json:"@context"`
	ID                        string `json:"aggregator_base_url"`
	Type                      string `json:"type"`
	// Subject is not part of the Aggregator Description proper, but the
	// provision management flow reuses this representation and MUST report the
	// subject (WebID or Client_ID) the OIDC tokens were created for. The spec
	// permits additional members, so it is emitted as an extra field.
	Subject                   string `json:"subject,omitempty"`
	CreatedAt                 string `json:"created_at"`
	LoginStatus               bool   `json:"login_status"`
	TokenExpiry               string `json:"token_expiry,omitempty"`
	TransformationCatalog     string `json:"transformation_catalog"`
	ServiceCollectionEndpoint string `json:"service_collection_endpoint"`
}

type aggregatorInstance struct {
	ID          string
	Subject     string
	OwnerToken  string
	CreatedAt   time.Time
	TokenExpiry time.Time
}

func BuildAggregatorDescription(cfg Config, agg aggregatorInstance) AggregatorDescription {
	aggregatorURL := cfg.absolute("/aggregators/" + agg.ID)
	return AggregatorDescription{
		Context:                   aggregatorDescriptionContext,
		ID:                        aggregatorURL,
		Type:                      "Aggregator",
		Subject:                   agg.Subject,
		CreatedAt:                 agg.CreatedAt.UTC().Format(time.RFC3339),
		LoginStatus:               true,
		TokenExpiry:               agg.TokenExpiry.UTC().Format(time.RFC3339),
		TransformationCatalog:     cfg.absolute("/aggregators/" + agg.ID + "/transformations"),
		ServiceCollectionEndpoint: cfg.absolute("/aggregators/" + agg.ID + "/services"),
	}
}

type ServiceCollection struct {
	Context    map[string]any `json:"@context"`
	ID         string         `json:"@id"`
	Type       string         `json:"@type"`
	HasService []string       `json:"hasService"`
}

type ServiceDescription struct {
	Context        map[string]any `json:"@context"`
	ID             string         `json:"@id"`
	Type           []string       `json:"@type"`
	Transformation string         `json:"performs"`
	Status         string         `json:"status"`
	StatusDetail   string         `json:"statusDetail"`
	CreatedAt      string         `json:"createdAt"`
	ConformsTo     string         `json:"conformsTo"`
	Applies        string         `json:"applies"`
	Dataset        ServiceDataset `json:"servesDataset"`
}

type SourceMetadata struct {
	URL                 string `json:"url"`
	MediaType           string `json:"media_type"`
	SHA256              string `json:"sha256"`
	ETag                string `json:"etag,omitempty"`
	Protected           bool   `json:"protected"`
	AuthorizationServer string `json:"authorization_server,omitempty"`
	PermissionTicket    string `json:"permission_ticket,omitempty"`
}

type Derivation struct {
	Issuer               string `json:"issuer"`
	DerivationResourceID string `json:"derivation_resource_id"`
}

func (d Derivation) hasData() bool {
	return d.Issuer != "" && d.DerivationResourceID != ""
}

type ServiceDataset struct {
	ID           string              `json:"@id"`
	Type         string              `json:"@type"`
	ForOutput    string              `json:"forOutput"`
	Distribution ServiceDistribution `json:"distribution"`
}

type ServiceDistribution struct {
	ID            string `json:"@id"`
	Type          string `json:"@type"`
	AccessURL     string `json:"accessURL"`
	AccessService string `json:"accessService"`
	MediaType     string `json:"mediaType,omitempty"`
	ConformsTo    string `json:"conformsTo,omitempty"`
}

type serviceInstance struct {
	ID                  string
	AggregatorID        string
	Transformation      string
	Query               string
	QueryType           string
	SourceURLs          []string
	SourceMetadata      []SourceMetadata
	Status              string
	OutputMediaType     string
	OutputPath          string
	AASIssuer           string
	AASResourceID       string
	DerivedFrom         []Derivation
	UpstreamDerivation  upstreamDerivationEvidence
	UpstreamDerivations []upstreamDerivationEvidence
	ErrorMessage        string
	CreatedAt           time.Time
}

func BuildServiceCollection(cfg Config, aggID string, services []serviceInstance) ServiceCollection {
	serviceURLs := make([]string, 0, len(services))
	for _, svc := range services {
		serviceURLs = append(serviceURLs, serviceURL(cfg, aggID, svc.ID))
	}
	return ServiceCollection{
		Context: map[string]any{
			"aggr": "https://w3id.org/aggregator#",
			"hasService": map[string]string{
				"@id":   "aggr:hasService",
				"@type": "@id",
			},
		},
		ID:         cfg.absolute("/aggregators/" + aggID + "/services"),
		Type:       "aggr:ServiceCollection",
		HasService: serviceURLs,
	}
}

func BuildServiceDescription(cfg Config, svc serviceInstance) ServiceDescription {
	url := serviceURL(cfg, svc.AggregatorID, svc.ID)
	outputURL := url + "/output"
	datasetURL := url + "#dataset"
	distributionURL := url + "#distribution"
	return ServiceDescription{
		Context: map[string]any{
			"aggr": "https://w3id.org/aggregator#",
			"dcat": "http://www.w3.org/ns/dcat#",
			"dct":  "http://purl.org/dc/terms/",
			"performs": map[string]string{
				"@id":   "aggr:performs",
				"@type": "@id",
			},
			"servesDataset": map[string]string{
				"@id":   "dcat:servesDataset",
				"@type": "@id",
			},
			"status":       "aggr:status",
			"statusDetail": "aggr:statusDetail",
			"createdAt":    "aggr:createdAt",
			"conformsTo": map[string]string{
				"@id":   "dct:conformsTo",
				"@type": "@id",
			},
			"applies": map[string]string{
				"@id":   "aggr:applies",
				"@type": "@id",
			},
			"forOutput": map[string]string{
				"@id":   "aggr:forOutput",
				"@type": "@id",
			},
			"distribution": map[string]string{
				"@id":   "dcat:distribution",
				"@type": "@id",
			},
			"accessURL": map[string]string{
				"@id":   "dcat:accessURL",
				"@type": "@id",
			},
			"accessService": map[string]string{
				"@id":   "dcat:accessService",
				"@type": "@id",
			},
			"mediaType": map[string]string{
				"@id":   "dcat:mediaType",
				"@type": "@id",
			},
		},
		ID:             url,
		Type:           []string{"aggr:Service", "dcat:DataService", "prov:SoftwareAgent"},
		Transformation: svc.Transformation,
		Status:         svc.Status,
		StatusDetail:   svc.ErrorMessage,
		CreatedAt:      svc.CreatedAt.UTC().Format(time.RFC3339),
		ConformsTo:     "https://w3id.org/aggregator#",
		Applies:        instanceAppliedFunctionURL(cfg, svc.AggregatorID, svc),
		Dataset: ServiceDataset{
			ID:        datasetURL,
			Type:      "dcat:Dataset",
			ForOutput: transformationOutputURL(cfg),
			Distribution: ServiceDistribution{
				ID:            distributionURL,
				Type:          "dcat:Distribution",
				AccessURL:     outputURL,
				AccessService: url,
				MediaType:     ianaMediaTypeURL(svc.OutputMediaType),
				ConformsTo:    outputConformanceURL(svc.OutputMediaType),
			},
		},
	}
}

func serviceURL(cfg Config, aggID, serviceID string) string {
	return cfg.absolute("/aggregators/" + aggID + "/services/" + serviceID)
}

func cloneSourceMetadata(source []SourceMetadata) []SourceMetadata {
	cloned := make([]SourceMetadata, len(source))
	copy(cloned, source)
	return cloned
}

func cloneDerivations(derivations []Derivation) []Derivation {
	cloned := make([]Derivation, len(derivations))
	copy(cloned, derivations)
	return cloned
}

func ianaMediaTypeURL(mediaType string) string {
	if mediaType == "" {
		return ""
	}
	return "http://www.iana.org/assignments/media-types/" + mediaType
}

func outputConformanceURL(mediaType string) string {
	switch mediaType {
	case "application/sparql-results+json":
		return "https://www.w3.org/TR/sparql11-results-json/"
	case "text/turtle":
		return "https://www.w3.org/TR/turtle/"
	default:
		return ""
	}
}
