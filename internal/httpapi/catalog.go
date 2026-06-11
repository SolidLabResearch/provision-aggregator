package httpapi

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"
)

const (
	transformationQueryViewFragment = "QueryView"
	transformationResultFragment    = "Result"
)

type ClientIdentifierDocument struct {
	Context  []string `json:"@context"`
	ClientID string   `json:"client_id"`
	Name     string   `json:"client_name"`
}

type TransformationCatalog struct {
	Context map[string]any       `json:"@context"`
	Graph   []TransformationNode `json:"@graph"`
}

type TransformationNode struct {
	ID                 string                    `json:"@id"`
	Type               any                       `json:"@type"`
	Label              string                    `json:"label,omitempty"`
	Description        string                    `json:"description,omitempty"`
	Comment            string                    `json:"comment,omitempty"`
	HasTransformation  string                    `json:"hasTransformation,omitempty"`
	HasAppliedFunction []string                  `json:"hasAppliedFunction,omitempty"`
	Expects            []string                  `json:"expects,omitempty"`
	Returns            []string                  `json:"returns,omitempty"`
	Applies            string                    `json:"applies,omitempty"`
	ParameterBindings  []AppliedParameterBinding `json:"parameterBindings,omitempty"`
	Predicate          string                    `json:"predicate,omitempty"`
	Required           *bool                     `json:"required,omitempty"`
	ValueType          string                    `json:"valueType,omitempty"`
}

type AppliedParameterBinding struct {
	BoundParameter string `json:"boundParameter"`
	BoundToTerm    string `json:"boundToTerm"`
}

func BuildClientIdentifierDocument(cfg Config) ClientIdentifierDocument {
	return ClientIdentifierDocument{
		Context:  []string{"https://www.w3.org/ns/solid/oidc-context.jsonld"},
		ClientID: cfg.absolute(cfg.ClientIdentifierPath),
		Name:     "Aggregator",
	}
}

func BuildTransformationCatalog(cfg Config) TransformationCatalog {
	catalogURL := cfg.absolute(cfg.TransformationCatalogPath)
	queryViewURL := catalogURL + "#" + transformationQueryViewFragment
	sourceParameterURL := catalogURL + "#SourceParameter"
	queryParameterURL := catalogURL + "#QueryParameter"
	resultURL := catalogURL + "#" + transformationResultFragment
	sourcePredicateURL := catalogURL + "#source"
	queryPredicateURL := catalogURL + "#query"
	resultPredicateURL := catalogURL + "#result"
	required := true

	return TransformationCatalog{
		Context: transformationCatalogContext(),
		Graph: []TransformationNode{
			{
				ID:                catalogURL,
				Type:              "aggr:TransformationCatalog",
				HasTransformation: queryViewURL,
			},
			{
				ID:          queryViewURL,
				Type:        "fno:Function",
				Label:       "SPARQL query transformation",
				Description: "Materializes local RDF sources with a SPARQL CONSTRUCT or SELECT query.",
				Comment:     "Materializes CONSTRUCT results as Turtle and SELECT results as SPARQL Results JSON.",
				Expects:     []string{sourceParameterURL, queryParameterURL},
				Returns:     []string{resultURL},
			},
			{
				ID:        sourceParameterURL,
				Type:      "fno:Parameter",
				Label:     "RDF source document",
				Predicate: sourcePredicateURL,
				Required:  &required,
				ValueType: "http://www.w3.org/ns/dcat#Dataset",
			},
			{
				ID:        queryParameterURL,
				Type:      "fno:Parameter",
				Label:     "SPARQL query string",
				Predicate: queryPredicateURL,
				Required:  &required,
				ValueType: "http://www.w3.org/2001/XMLSchema#string",
			},
			{
				ID:        resultURL,
				Type:      "fno:Output",
				Label:     "Materialized query result",
				Predicate: resultPredicateURL,
				ValueType: "http://www.w3.org/ns/dcat#Dataset",
			},
		},
	}
}

func BuildInstanceTransformationCatalog(cfg Config, aggID string, services []serviceInstance) TransformationCatalog {
	catalogURL := cfg.absolute("/aggregators/" + aggID + "/transformations")
	catalog := TransformationCatalog{
		Context: transformationCatalogContext(),
		Graph: []TransformationNode{
			{
				ID:   catalogURL,
				Type: "aggr:TransformationCatalog",
			},
		},
	}

	appliedFunctions := equivalentAppliedFunctions(services)
	for _, applied := range appliedFunctions {
		id := instanceAppliedFunctionURL(cfg, aggID, applied)
		catalog.Graph[0].HasAppliedFunction = append(catalog.Graph[0].HasAppliedFunction, id)
		catalog.Graph = append(catalog.Graph, TransformationNode{
			ID:      id,
			Type:    "fno:AppliedFunction",
			Applies: applied.Transformation,
			ParameterBindings: []AppliedParameterBinding{
				{BoundParameter: cfg.absolute(cfg.TransformationCatalogPath) + "#QueryParameter", BoundToTerm: applied.Query},
				{BoundParameter: cfg.absolute(cfg.TransformationCatalogPath) + "#SourceParameter", BoundToTerm: strings.Join(applied.SourceURLs, " ")},
			},
		})
	}
	return catalog
}

func instanceAppliedFunctionURL(cfg Config, aggID string, svc serviceInstance) string {
	sum := sha256.Sum256([]byte(appliedFunctionKey(svc)))
	return fmt.Sprintf("%s#AppliedFunction-%s", cfg.absolute("/aggregators/"+aggID+"/transformations"), hex.EncodeToString(sum[:8]))
}

func transformationCatalogContext() map[string]any {
	return map[string]any{
		"aggr": "https://w3id.org/aggregator#",
		"dcat": "http://www.w3.org/ns/dcat#",
		"dct":  "http://purl.org/dc/terms/",
		"fno":  "https://w3id.org/function/ontology#",
		"label": map[string]string{
			"@id": "http://www.w3.org/2000/01/rdf-schema#label",
		},
		"description": "dct:description",
		"comment": map[string]string{
			"@id": "http://www.w3.org/2000/01/rdf-schema#comment",
		},
		"hasTransformation": map[string]string{
			"@id":   "aggr:hasTransformation",
			"@type": "@id",
		},
		"hasAppliedFunction": map[string]string{
			"@id":   "aggr:hasAppliedFunction",
			"@type": "@id",
		},
		"applies": map[string]string{
			"@id":   "fnoc:applies",
			"@type": "@id",
		},
		"parameterBindings": "fnoc:parameterBindings",
		"boundParameter": map[string]string{
			"@id":   "fnoc:boundParameter",
			"@type": "@id",
		},
		"boundToTerm": "fnoc:boundToTerm",
		"expects": map[string]string{
			"@id":        "fno:expects",
			"@type":      "@id",
			"@container": "@list",
		},
		"returns": map[string]string{
			"@id":        "fno:returns",
			"@type":      "@id",
			"@container": "@list",
		},
		"predicate": map[string]string{
			"@id":   "fno:predicate",
			"@type": "@id",
		},
		"required": "fno:required",
		"valueType": map[string]string{
			"@id":   "fno:type",
			"@type": "@id",
		},
	}
}

func equivalentAppliedFunctions(services []serviceInstance) []serviceInstance {
	seen := map[string]bool{}
	var applied []serviceInstance
	for _, svc := range services {
		key := appliedFunctionKey(svc)
		if seen[key] {
			continue
		}
		seen[key] = true
		applied = append(applied, svc)
	}
	return applied
}

func appliedFunctionKey(svc serviceInstance) string {
	sources := append([]string(nil), svc.SourceURLs...)
	sort.Strings(sources)
	return svc.Transformation + "\x00" + svc.Query + "\x00" + strings.Join(sources, "\x00")
}
