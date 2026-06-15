package conformance_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRSVC010(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	first := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	second := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if first.ID == second.ID {
		t.Fatalf("server allocated duplicate service IDs: %q", first.ID)
	}
}

func TestAGGRSVC024(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	before := request(server, http.MethodGet, mustPath(agg.TransformationCatalog), "", nil)
	createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	after := request(server, http.MethodGet, mustPath(agg.TransformationCatalog), "", nil)

	if before.Code != http.StatusOK || after.Code != http.StatusOK {
		t.Fatalf("transformation catalog status before/after = %d/%d, want 200/200", before.Code, after.Code)
	}
	if !strings.Contains(after.Body.String(), "MediaProfileAggregation") {
		t.Fatalf("instance transformation catalog does not advertise MediaProfileAggregation: %s", after.Body.String())
	}
}

func TestAGGRSVC024InitialInstanceTransformationCatalogIsEmpty(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodGet, mustPath(agg.TransformationCatalog), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET instance transformation catalog status = %d, want 200", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "http://localhost:8080/transformations#MediaProfileAggregation") ||
		strings.Contains(rec.Body.String(), "https://aggregator.example/transformations#MediaProfileAggregation") {
		t.Fatalf("initial instance transformation catalog must not include server-level MediaProfileAggregation: %s", rec.Body.String())
	}
	var catalog httpapi.TransformationCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &catalog); err != nil {
		t.Fatalf("instance transformation catalog must be JSON-LD: %v", err)
	}
	if len(catalog.Graph) != 1 || catalog.Graph[0].HasTransformation != "" || len(catalog.Graph[0].HasAppliedFunction) != 0 {
		t.Fatalf("initial instance transformation catalog = %#v, want only empty catalog node", catalog.Graph)
	}
}

func TestAGGRSVC025(t *testing.T) {
	catalog := httpapi.BuildTransformationCatalog(httpapi.DefaultConfig("https://aggregator.example"))
	if len(catalog.Graph) < 2 || len(catalog.Graph[1].Expects) == 0 || len(catalog.Graph[1].Returns) == 0 {
		t.Fatalf("catalog must advertise applied SPARQL function metadata: %#v", catalog.Graph)
	}
}

func TestAGGRSVC026(t *testing.T) {
	catalog := httpapi.BuildTransformationCatalog(httpapi.DefaultConfig("https://aggregator.example"))
	seen := map[string]bool{}
	for _, node := range catalog.Graph {
		if node.ID == "" {
			continue
		}
		if seen[node.ID] {
			t.Fatalf("duplicate catalog entry for %q", node.ID)
		}
		seen[node.ID] = true
	}
}

func TestAGGRSVC027(t *testing.T) {
	catalog := httpapi.BuildTransformationCatalog(httpapi.DefaultConfig("https://aggregator.example"))
	if catalog.Graph[0].HasTransformation == "" {
		t.Fatalf("catalog must advertise composed transformation entry")
	}
}

func TestAGGRSVC028(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if desc.Transformation == "" || desc.Query == "" || desc.QueryType != "SELECT" {
		t.Fatalf("service does not perform configured transformation: %#v", desc)
	}
}

func TestAGGRSVC031(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("service output status = %d, want 200", rec.Code)
	}
	if rec.Body.Len() == 0 {
		t.Fatalf("service output body is empty")
	}
}

func TestAGGRPROV001(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	rec := createServiceRaw(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	var desc map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("service create response must be JSON-LD: %v", err)
	}
	if value, ok := desc["provenance_url"]; ok {
		t.Fatalf("service description exposes optional provenance_url = %#v", value)
	}
}

func TestAGGRPROV002(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	rec := request(server, http.MethodGet, mustPath(desc.ID)+"/provenance", "", nil)
	if rec.Code != http.StatusNotFound {
		t.Fatalf("provenance status = %d, want 404 when optional provenance is not exposed", rec.Code)
	}
}
