package httpapi

import "testing"

const userJSONLDServiceRequest = `{"@context":{"aggr":"https://w3id.org/aggregator#","fno":"https://w3id.org/function/ontology#","fnoc":"https://fno.io/vocabulary/composition/0.1.0/"},"@type":"aggr:Service","aggr:performs":{"@id":"http://localhost:8080/transformations#MediaProfileAggregation"},"aggr:applies":{"@type":"fno:AppliedFunction","fnoc:applies":{"@id":"http://localhost:8080/transformations#MediaProfileAggregation"},"fnoc:parameterBindings":{"@list":[{"fnoc:boundParameter":{"@id":"http://localhost:8080/transformations#Source"},"fnoc:boundToTerm":"http://rs.local:3000/bob/MediaProfileIndex"}]}}}`

func TestParseCreateServiceRequestJSONLD(t *testing.T) {
	cfg := DefaultConfig("http://localhost:8080")

	req, err := parseCreateServiceRequestJSONLD(cfg, []byte(userJSONLDServiceRequest))
	if err != nil {
		t.Fatalf("parse JSON-LD service request: %v", err)
	}
	if want := supportedTransformationURL(cfg); req.Transformation != want {
		t.Fatalf("transformation = %q, want %q", req.Transformation, want)
	}
	if len(req.SourceURLs) != 1 || req.SourceURLs[0] != "http://rs.local:3000/bob/MediaProfileIndex" {
		t.Fatalf("source_urls = %#v, want single MediaProfileIndex URL", req.SourceURLs)
	}
}

func TestParseCreateServiceRequestJSONLDWithGraphAndArray(t *testing.T) {
	cfg := DefaultConfig("http://localhost:8080")

	graphForm := `{"@context":{"aggr":"https://w3id.org/aggregator#","fno":"https://w3id.org/function/ontology#","fnoc":"https://fno.io/vocabulary/composition/0.1.0/"},"@graph":[` + userJSONLDServiceRequest + `]}`
	if _, err := parseCreateServiceRequestJSONLD(cfg, []byte(graphForm)); err != nil {
		t.Fatalf("@graph form should parse: %v", err)
	}

	arrayForm := `[` + userJSONLDServiceRequest + `]`
	if _, err := parseCreateServiceRequestJSONLD(cfg, []byte(arrayForm)); err != nil {
		t.Fatalf("array form should parse: %v", err)
	}
}

func TestParseCreateServiceRequestJSONLDRejectsMissingSource(t *testing.T) {
	cfg := DefaultConfig("http://localhost:8080")

	noBinding := `{"@context":{"aggr":"https://w3id.org/aggregator#","fno":"https://w3id.org/function/ontology#","fnoc":"https://fno.io/vocabulary/composition/0.1.0/"},"@type":"aggr:Service","aggr:performs":{"@id":"http://localhost:8080/transformations#MediaProfileAggregation"},"aggr:applies":{"@type":"fno:AppliedFunction","fnoc:applies":{"@id":"http://localhost:8080/transformations#MediaProfileAggregation"},"fnoc:parameterBindings":{"@list":[]}}}`
	if _, err := parseCreateServiceRequestJSONLD(cfg, []byte(noBinding)); err == nil {
		t.Fatalf("expected error for missing source binding")
	}
}

func TestLooksLikeJSONLD(t *testing.T) {
	cases := map[string]bool{
		userJSONLDServiceRequest: true,
		`[{"@type":"aggr:Service"}]`:                                  true,
		`{"@graph":[]}`:                                               true,
		`{"transformation":"x","source_urls":["y"]}`:                  false,
		`{"source_urls":["y"]}`:                                       false,
		`not json`:                                                    false,
	}
	for body, want := range cases {
		if got := looksLikeJSONLD([]byte(body)); got != want {
			t.Fatalf("looksLikeJSONLD(%s) = %t, want %t", body, got, want)
		}
	}
}

