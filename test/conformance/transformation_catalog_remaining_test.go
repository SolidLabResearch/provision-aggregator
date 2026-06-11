package conformance_test

import (
	"net/url"
	"strings"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRRDF004(t *testing.T) {
	catalog, fn := transformationFunction(t)

	if len(fn.Expects) == 0 {
		t.Fatalf("transformation function must declare fno:expects parameters")
	}
	for _, parameterID := range fn.Expects {
		node := catalogNode(t, catalog, parameterID)
		if !contains(nodeTypes(node), "fno:Parameter") {
			t.Fatalf("fno:expects member %q has types %#v, want fno:Parameter", parameterID, nodeTypes(node))
		}
	}
}

func TestAGGRRDF005(t *testing.T) {
	catalog, fn := transformationFunction(t)

	if len(fn.Returns) == 0 {
		t.Fatalf("transformation function must declare fno:returns outputs")
	}
	for _, outputID := range fn.Returns {
		node := catalogNode(t, catalog, outputID)
		if !contains(nodeTypes(node), "fno:Output") {
			t.Fatalf("fno:returns member %q has types %#v, want fno:Output", outputID, nodeTypes(node))
		}
	}
}

func TestAGGRRDF006(t *testing.T) {
	catalog, fn := transformationFunction(t)

	for _, parameterID := range fn.Expects {
		node := catalogNode(t, catalog, parameterID)
		if !strings.HasPrefix(node.Predicate, catalog.Graph[0].ID+"#") {
			t.Fatalf("parameter %q predicate = %q, want local catalog IRI", parameterID, node.Predicate)
		}
		if strings.HasSuffix(parameterID, "#SourceParameter") && node.Predicate != catalog.Graph[0].ID+"#source" {
			t.Fatalf("source parameter predicate = %q, want local source term", node.Predicate)
		}
		if strings.HasSuffix(parameterID, "#QueryParameter") && node.Predicate != catalog.Graph[0].ID+"#query" {
			t.Fatalf("query parameter predicate = %q, want local query term", node.Predicate)
		}
		if strings.Contains(node.Predicate, "https://w3id.org/aggregator#") {
			t.Fatalf("parameter %q predicate uses aggregator vocabulary term %q; want local term", parameterID, node.Predicate)
		}
	}
}

func TestAGGRRDF007(t *testing.T) {
	catalog, fn := transformationFunction(t)

	for _, outputID := range fn.Returns {
		node := catalogNode(t, catalog, outputID)
		if node.Predicate != catalog.Graph[0].ID+"#result" {
			t.Fatalf("output %q predicate = %q, want local result term", outputID, node.Predicate)
		}
	}
}

func TestAGGRRDF008(t *testing.T) {
	catalog, fn := transformationFunction(t)

	for _, outputID := range fn.Returns {
		node := catalogNode(t, catalog, outputID)
		if node.ValueType != "http://www.w3.org/ns/dcat#Dataset" {
			t.Fatalf("output %q fno:type = %q, want dcat:Dataset", outputID, node.ValueType)
		}
	}
}

func TestAGGRRDF009(t *testing.T) {
	catalog, fn := transformationFunction(t)
	forbidden := map[string]bool{
		"http://www.w3.org/1999/02/22-rdf-syntax-ns#type": true,
		"https://w3id.org/function/ontology#executes":     true,
	}

	for _, nodeID := range append(append([]string{}, fn.Expects...), fn.Returns...) {
		node := catalogNode(t, catalog, nodeID)
		if forbidden[node.Predicate] {
			t.Fatalf("%q uses forbidden fno:predicate %q", nodeID, node.Predicate)
		}
	}
}

func TestAGGRRDF010(t *testing.T) {
	catalog, fn := transformationFunction(t)

	requiredFlagCount := 0
	for _, parameterID := range fn.Expects {
		node := catalogNode(t, catalog, parameterID)
		if node.Required == nil {
			continue
		}
		requiredFlagCount++
	}
	if requiredFlagCount == 0 {
		t.Fatalf("transformation parameters should advertise boolean fno:required flags")
	}
}

func TestAGGRRDF011(t *testing.T) {
	_, fn := transformationFunction(t)

	if fn.Description == "" {
		t.Fatalf("transformation function should include a human-readable dct:description")
	}
}

func TestAGGRRDF012(t *testing.T) {
	catalog, fn := transformationFunction(t)

	for _, parameterID := range fn.Expects {
		node := catalogNode(t, catalog, parameterID)
		if node.ValueType == "" {
			continue
		}
		if !isAbsoluteIRI(node.ValueType) {
			t.Fatalf("parameter %q fno:type = %q, want absolute IRI", parameterID, node.ValueType)
		}
	}
}

func transformationFunction(t *testing.T) (httpapi.TransformationCatalog, httpapi.TransformationNode) {
	t.Helper()

	catalog := httpapi.BuildTransformationCatalog(httpapi.DefaultConfig("https://aggregator.example"))
	if len(catalog.Graph) == 0 || catalog.Graph[0].HasTransformation == "" {
		t.Fatalf("catalog must link to an advertised transformation function: %#v", catalog.Graph)
	}
	return catalog, catalogNode(t, catalog, catalog.Graph[0].HasTransformation)
}

func catalogNode(t *testing.T, catalog httpapi.TransformationCatalog, id string) httpapi.TransformationNode {
	t.Helper()

	for _, node := range catalog.Graph {
		if node.ID == id {
			return node
		}
	}
	t.Fatalf("catalog does not describe node %q in graph %#v", id, catalog.Graph)
	return httpapi.TransformationNode{}
}

func nodeTypes(node httpapi.TransformationNode) []string {
	switch value := node.Type.(type) {
	case string:
		return []string{value}
	case []string:
		return append([]string(nil), value...)
	case []any:
		types := make([]string, 0, len(value))
		for _, item := range value {
			if text, ok := item.(string); ok {
				types = append(types, text)
			}
		}
		return types
	default:
		return nil
	}
}

func isAbsoluteIRI(value string) bool {
	parsed, err := url.Parse(value)
	return err == nil && parsed.Scheme != "" && parsed.Host != ""
}
