package httpapi

import "testing"

func TestBuildTransformationCatalogUsesMediaProfileAggregationDefaults(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	catalog := BuildTransformationCatalog(cfg)

	transformationURL := "https://aggregator.example/transformations#MediaProfileAggregation"
	sourceURL := "https://aggregator.example/transformations#Source"
	outputURL := "https://aggregator.example/transformations#MediaProfile"

	if len(catalog.Graph) != 4 {
		t.Fatalf("catalog graph nodes = %d, want catalog, function, source, output", len(catalog.Graph))
	}
	if catalog.Graph[0].HasTransformation != transformationURL {
		t.Fatalf("hasTransformation = %q, want %q", catalog.Graph[0].HasTransformation, transformationURL)
	}

	function := catalog.Graph[1]
	if function.ID != transformationURL ||
		function.Label != "Media Profile Aggregation" ||
		function.Description != "Aggregates multiple media profiles and psuedomizes them and generates one aggreagted media profile." ||
		function.Comment != function.Description {
		t.Fatalf("function node = %#v", function)
	}
	if len(function.Expects) != 1 || function.Expects[0] != sourceURL {
		t.Fatalf("function expects = %#v, want source only", function.Expects)
	}
	if len(function.Returns) != 1 || function.Returns[0] != outputURL {
		t.Fatalf("function returns = %#v, want media profile output", function.Returns)
	}
	if catalog.Graph[2].ID != sourceURL || catalog.Graph[2].Label != "Source" {
		t.Fatalf("source node = %#v", catalog.Graph[2])
	}
	if catalog.Graph[3].ID != outputURL || catalog.Graph[3].Label != "MediaProfile" {
		t.Fatalf("output node = %#v", catalog.Graph[3])
	}
}
