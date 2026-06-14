package httpapi

import "time"

type ServerDescription struct {
	Context                           map[string]any `json:"@context"`
	ID                                string         `json:"@id"`
	Type                              string         `json:"@type"`
	ManagementEndpoint                string         `json:"registrationEndpoint"`
	SupportedManagementFlows          []string       `json:"supportedRegistrationType"`
	SupportedManagementRequestFormats []string       `json:"registrationRequestFormatSupported"`
	Version                           string         `json:"specVersion"`
	ClientIdentifier                  string         `json:"clientIdentifier"`
	TransformationCatalog             string         `json:"transformationCatalog"`
}

func BuildServerDescription(cfg Config) ServerDescription {
	return ServerDescription{
		Context: map[string]any{
			"aggr": "https://w3id.org/aggregator#",
			"registrationEndpoint": map[string]string{
				"@id":   "aggr:registrationEndpoint",
				"@type": "@id",
			},
			"supportedRegistrationType":          "aggr:supportedRegistrationType",
			"registrationRequestFormatSupported": "aggr:registrationRequestFormatSupported",
			"specVersion":                        "aggr:specVersion",
			"clientIdentifier": map[string]string{
				"@id":   "aggr:clientIdentifier",
				"@type": "@id",
			},
			"transformationCatalog": map[string]string{
				"@id":   "aggr:transformationCatalog",
				"@type": "@id",
			},
		},
		ID:                                cfg.absolute("/"),
		Type:                              "aggr:AggregatorServer",
		ManagementEndpoint:                cfg.absolute(cfg.ManagementEndpointPath),
		SupportedManagementFlows:          append([]string(nil), cfg.SupportedManagementFlows...),
		SupportedManagementRequestFormats: append([]string(nil), cfg.SupportedManagementFormats...),
		Version:                           cfg.Version,
		ClientIdentifier:                  cfg.absolute(cfg.ClientIdentifierPath),
		TransformationCatalog:             cfg.absolute(cfg.TransformationCatalogPath),
	}
}

type AggregatorDescription struct {
	Context                   map[string]any `json:"@context"`
	ID                        string         `json:"@id"`
	Type                      string         `json:"@type"`
	Subject                   string         `json:"subject"`
	CreatedAt                 string         `json:"createdAt"`
	LoginStatus               bool           `json:"loginStatus"`
	TokenExpiry               string         `json:"tokenExpiry,omitempty"`
	TransformationCatalog     string         `json:"transformationsEndpoint"`
	ServiceCollectionEndpoint string         `json:"serviceCollectionEndpoint"`
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
		Context: map[string]any{
			"aggr":        "https://w3id.org/aggregator#",
			"subject":     "aggr:subject",
			"createdAt":   "aggr:createdAt",
			"loginStatus": "aggr:loginStatus",
			"tokenExpiry": "aggr:tokenExpiry",
			"transformationsEndpoint": map[string]string{
				"@id":   "aggr:transformationsEndpoint",
				"@type": "@id",
			},
			"serviceCollectionEndpoint": map[string]string{
				"@id":   "aggr:serviceCollectionEndpoint",
				"@type": "@id",
			},
		},
		ID:                        aggregatorURL,
		Type:                      "aggr:Aggregator",
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
	Context         map[string]any   `json:"@context"`
	ID              string           `json:"@id"`
	Type            []string         `json:"@type"`
	AggregatorID    string           `json:"aggregator_id"`
	OutputURL       string           `json:"output_url"`
	OutputMediaType string           `json:"output_media_type,omitempty"`
	AASIssuer       string           `json:"aas_issuer,omitempty"`
	AASResourceID   string           `json:"aas_resource_id,omitempty"`
	DerivedFrom     []Derivation     `json:"derived_from,omitempty"`
	Transformation  string           `json:"performs"`
	Query           string           `json:"query"`
	QueryType       string           `json:"query_type"`
	SourceURLs      []string         `json:"source_urls"`
	SourceMetadata  []SourceMetadata `json:"source_metadata,omitempty"`
	Status          string           `json:"status"`
	StatusDetail    string           `json:"statusDetail"`
	CreatedAt       string           `json:"createdAt"`
	ConformsTo      string           `json:"conformsTo"`
	Applies         string           `json:"applies"`
	Dataset         ServiceDataset   `json:"servesDataset"`
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
		ID:              url,
		Type:            []string{"aggr:Service", "dcat:DataService", "prov:SoftwareAgent"},
		AggregatorID:    svc.AggregatorID,
		OutputURL:       outputURL,
		OutputMediaType: svc.OutputMediaType,
		AASIssuer:       svc.AASIssuer,
		AASResourceID:   svc.AASResourceID,
		DerivedFrom:     cloneDerivations(svc.DerivedFrom),
		Transformation:  svc.Transformation,
		Query:           svc.Query,
		QueryType:       svc.QueryType,
		SourceURLs:      append([]string(nil), svc.SourceURLs...),
		SourceMetadata:  cloneSourceMetadata(svc.SourceMetadata),
		Status:          svc.Status,
		StatusDetail:    svc.ErrorMessage,
		CreatedAt:       svc.CreatedAt.UTC().Format(time.RFC3339),
		ConformsTo:      "https://w3id.org/aggregator#",
		Applies:         instanceAppliedFunctionURL(cfg, svc.AggregatorID, svc),
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
