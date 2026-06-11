package conformance_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRINST001(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	rec := request(server, http.MethodGet, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET aggregator description status = %d, want 200", rec.Code)
	}
	var fetched httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("aggregator description must be JSON: %v", err)
	}
}

func TestAggregatorWorksBehindBaseURLPathPrefix(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://example.org/aggregator/"))

	rec := requestWithBearer(server, http.MethodPost, "/aggregator/registration", "application/json", []byte(`{"management_flow":"provision"}`), "valid-management-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("prefixed provision status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	var desc httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("decode aggregator description: %v", err)
	}
	if desc.ServiceCollectionEndpoint != "https://example.org/aggregator/aggregators/agg-1/services" {
		t.Fatalf("service collection endpoint = %q, want prefixed public URL", desc.ServiceCollectionEndpoint)
	}

	fetched := request(server, http.MethodGet, mustPath(desc.ServiceCollectionEndpoint), "", nil)
	if fetched.Code != http.StatusOK {
		t.Fatalf("GET prefixed service collection status = %d, want 200; body: %s", fetched.Code, fetched.Body.String())
	}
}

func TestAGGRINST002(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	if desc.ID == "" {
		t.Fatalf("id is required")
	}
	if desc.Type != "aggr:Aggregator" {
		t.Fatalf("@type = %q, want aggr:Aggregator", desc.Type)
	}
	if desc.CreatedAt == "" {
		t.Fatalf("created_at is required")
	}
	if desc.TransformationCatalog == "" {
		t.Fatalf("transformation_catalog is required")
	}
	if desc.ServiceCollectionEndpoint == "" {
		t.Fatalf("service_collection_endpoint is required")
	}
}

func TestAGGRINST003(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	for name, value := range map[string]string{
		"id":                          desc.ID,
		"transformation_catalog":      desc.TransformationCatalog,
		"service_collection_endpoint": desc.ServiceCollectionEndpoint,
	} {
		parsed, err := url.Parse(value)
		if err != nil {
			t.Fatalf("%s is not a URL: %v", name, err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			t.Fatalf("%s = %q, want absolute HTTPS URL", name, value)
		}
	}
}

func TestAGGRINST004(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	if desc.CreatedAt == "" || !strings.Contains(desc.CreatedAt, "T") || !strings.HasSuffix(desc.CreatedAt, "Z") {
		t.Fatalf("created_at = %q, want RFC3339 UTC timestamp", desc.CreatedAt)
	}
	if desc.TokenExpiry == "" || !strings.Contains(desc.TokenExpiry, "T") || !strings.HasSuffix(desc.TokenExpiry, "Z") {
		t.Fatalf("token_expiry = %q, want RFC3339 UTC timestamp", desc.TokenExpiry)
	}
}

func TestAGGRINST005(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	if !desc.LoginStatus {
		t.Fatalf("login_status = false, want true for configured provision identity")
	}
}

func TestAGGRMGMT000(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))

	parsed, err := url.Parse(desc.ManagementEndpoint)
	if err != nil {
		t.Fatalf("management endpoint is not a URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		t.Fatalf("management endpoint = %q, want absolute HTTPS URL", desc.ManagementEndpoint)
	}
}

func TestAGGRMGMT001(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := requestWithBearer(server, http.MethodPost, "/registration", "text/plain", []byte(`management_flow=provision`), "valid-management-token")

	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("status = %d, want 415", rec.Code)
	}
}

func TestAGGRMGMT002(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := requestWithBearer(server, http.MethodPost, "/registration", "application/json", []byte(`{`), "valid-management-token")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAGGRMGMT003(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := requestWithBearer(server, http.MethodPost, "/registration", "application/json", []byte(`{"management_flow":"device_code"}`), "valid-management-token")

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", rec.Code)
	}
}

func TestAGGRMGMT004(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	provision(t, server)

	rec := request(server, http.MethodGet, "/registration", "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET /registration status = %d, want 200", rec.Code)
	}
	var aggregators []httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &aggregators); err != nil {
		t.Fatalf("management GET must return JSON array: %v", err)
	}
	if len(aggregators) != 1 {
		t.Fatalf("management GET returned %d aggregators, want 1", len(aggregators))
	}
}

func TestAGGRMGMT007(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := provisionRaw(t, server)

	body := strings.ToLower(rec.Body.String())
	for _, forbidden := range []string{"access_token", "refresh_token", "client_secret", "password", "credential"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("provision response leaks confidential field %q: %s", forbidden, rec.Body.String())
		}
	}
}

func TestAGGRMGMT011(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))

	if !contains(desc.SupportedManagementFlows, "provision") {
		t.Fatalf("server description must advertise provision flow")
	}
}

func TestAGGRMGMT012(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	rec := provisionRaw(t, server)

	if rec.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201", rec.Code)
	}
	if rec.Header().Get("Location") == "" {
		t.Fatalf("provision response must include Location header")
	}
	var desc httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("provision response must be aggregator description JSON: %v", err)
	}
	if desc.ID == "" {
		t.Fatalf("provision response must include aggregator description URL")
	}
}

func TestAGGRMGMT013(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	if desc.Subject != "https://aggregator.example/profile/card#me" {
		t.Fatalf("subject = %q, want configured provision subject", desc.Subject)
	}
}

func TestAGGRMGMT014(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	desc := provision(t, server)

	rec := request(server, http.MethodGet, "/registration", "", nil)
	var aggregators []httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &aggregators); err != nil {
		t.Fatalf("management GET must return JSON array: %v", err)
	}
	if len(aggregators) != 1 || aggregators[0].ID != desc.ID {
		t.Fatalf("management GET did not list provisioned aggregator %q: %#v", desc.ID, aggregators)
	}
}

func provision(t *testing.T, server *httpapi.Server) httpapi.AggregatorDescription {
	t.Helper()

	rec := provisionRaw(t, server)
	var desc httpapi.AggregatorDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("provision response must be JSON: %v", err)
	}
	return desc
}

func provisionRaw(t *testing.T, server *httpapi.Server) *httptest.ResponseRecorder {
	t.Helper()

	rec := requestWithBearer(server, http.MethodPost, "/registration", "application/json", []byte(`{"management_flow":"provision"}`), "valid-management-token")
	if rec.Code != http.StatusCreated {
		t.Fatalf("provision status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	return rec
}

func request(server *httpapi.Server, method, path, contentType string, body []byte) *httptest.ResponseRecorder {
	return requestWithBearer(server, method, path, contentType, body, "")
}

func requestWithBearer(server *httpapi.Server, method, path, contentType string, body []byte, token string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	server.Routes().ServeHTTP(rec, req)
	return rec
}

func mustPath(rawURL string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		panic(err)
	}
	return parsed.RequestURI()
}
