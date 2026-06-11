package conformance_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRSERVER001(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))

	if desc.ID != "https://aggregator.example/" {
		t.Fatalf("@id = %q, want absolute server URL", desc.ID)
	}
	if desc.Type != "aggr:AggregatorServer" {
		t.Fatalf("@type = %q, want aggr:AggregatorServer", desc.Type)
	}
	if _, err := json.Marshal(desc); err != nil {
		t.Fatalf("server description must be JSON serializable: %v", err)
	}
}

func TestAGGRSERVER002(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))

	required := map[string]string{
		"management_endpoint":    desc.ManagementEndpoint,
		"version":                desc.Version,
		"client_identifier":      desc.ClientIdentifier,
		"transformation_catalog": desc.TransformationCatalog,
	}
	for field, value := range required {
		if value == "" {
			t.Fatalf("%s is required", field)
		}
	}
	if !contains(desc.SupportedManagementFlows, "provision") {
		t.Fatalf("supported_management_flows must include provision")
	}
	if !contains(desc.SupportedManagementRequestFormats, "application/json") {
		t.Fatalf("supported_management_request_formats must include application/json")
	}
}

func TestAGGRSERVER003(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))

	urls := map[string]string{
		"@id":                    desc.ID,
		"management_endpoint":    desc.ManagementEndpoint,
		"client_identifier":      desc.ClientIdentifier,
		"transformation_catalog": desc.TransformationCatalog,
	}
	for field, value := range urls {
		parsed, err := url.Parse(value)
		if err != nil {
			t.Fatalf("%s is not parseable as URL %q: %v", field, value, err)
		}
		if parsed.Scheme != "https" || parsed.Host == "" {
			t.Fatalf("%s = %q, want absolute HTTPS URL", field, value)
		}
	}
}

func TestAGGRSERVER004(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))
	defined := map[string]bool{
		"none":               true,
		"provision":          true,
		"authorization_code": true,
		"device_code":        true,
	}

	for _, flow := range desc.SupportedManagementFlows {
		if !defined[flow] {
			t.Fatalf("unsupported management flow token %q", flow)
		}
	}
}

func TestAGGRSERVER005(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))

	if !contains(desc.SupportedManagementRequestFormats, "application/json") &&
		!contains(desc.SupportedManagementRequestFormats, "application/x-www-form-urlencoded") {
		t.Fatalf("supported request formats must include application/json or application/x-www-form-urlencoded")
	}
}

func TestAGGRSERVER006(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))
	semver := regexp.MustCompile(`^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$`)

	if !semver.MatchString(desc.Version) {
		t.Fatalf("version %q is not semantic version", desc.Version)
	}
}

func TestAGGRSERVER007(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))
	rec := get(mustPath(desc.ClientIdentifier))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET client_identifier status = %d, want 200", rec.Code)
	}
	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("client_identifier document must be parseable JSON: %v", err)
	}
}

func TestAGGRSERVER008(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))
	rec := get(mustPath(desc.ClientIdentifier))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET client_identifier status = %d, want 200", rec.Code)
	}
	var metadata map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &metadata); err != nil {
		t.Fatalf("client_identifier document must be JSON object: %v", err)
	}
	if metadata["client_id"] != desc.ClientIdentifier {
		t.Fatalf("client_id = %#v, want client_identifier URL %q", metadata["client_id"], desc.ClientIdentifier)
	}
	context, ok := metadata["@context"].([]any)
	if !ok || len(context) != 1 || context[0] != "https://www.w3.org/ns/solid/oidc-context.jsonld" {
		t.Fatalf("@context = %#v, want Solid OIDC client identifier context", metadata["@context"])
	}
	if metadata["client_name"] != "Aggregator" {
		t.Fatalf("client_name = %#v, want Aggregator", metadata["client_name"])
	}
	if _, ok := metadata["@type"]; ok {
		t.Fatalf("client metadata must not use aggregator-specific @type")
	}
	if redirectURIs, ok := metadata["redirect_uris"]; ok {
		values, ok := redirectURIs.([]any)
		if !ok {
			t.Fatalf("redirect_uris = %#v, want array when present", redirectURIs)
		}
		for _, value := range values {
			if _, ok := value.(string); !ok {
				t.Fatalf("redirect_uris contains non-string value %#v", value)
			}
		}
	}
	for _, forbidden := range []string{"client_secret", "client_secret_expires_at", "client_secret_post", "client_secret_basic", "client_secret_jwt"} {
		if _, ok := metadata[forbidden]; ok {
			t.Fatalf("client metadata must not include secret-based field %q", forbidden)
		}
	}
}

func TestAGGRRDF001(t *testing.T) {
	rec := get("/transformations")

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /transformations status = %d, want 200", rec.Code)
	}
}

func TestAGGRRDF002(t *testing.T) {
	rec := get("/transformations")

	if contentType := rec.Header().Get("Content-Type"); contentType != "application/ld+json" {
		t.Fatalf("Content-Type = %q, want application/ld+json", contentType)
	}
	var catalog httpapi.TransformationCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &catalog); err != nil {
		t.Fatalf("transformation catalog must be parseable JSON-LD: %v", err)
	}
}

func TestAGGRRDF003(t *testing.T) {
	catalog := httpapi.BuildTransformationCatalog(httpapi.DefaultConfig("https://aggregator.example"))

	if len(catalog.Graph) < 2 {
		t.Fatalf("catalog graph has %d nodes, want catalog and SPARQL transformation nodes", len(catalog.Graph))
	}
	if catalog.Graph[0].Type != "aggr:TransformationCatalog" {
		t.Fatalf("first catalog node type = %v, want aggr:TransformationCatalog", catalog.Graph[0].Type)
	}
	if catalog.Graph[0].HasTransformation == "" {
		t.Fatalf("catalog must reference at least one transformation")
	}
	if catalog.Graph[1].ID != catalog.Graph[0].HasTransformation {
		t.Fatalf("catalog transformation link = %q, but function node is %q", catalog.Graph[0].HasTransformation, catalog.Graph[1].ID)
	}
	if !contains(nodeTypes(catalog.Graph[1]), "fno:Function") {
		t.Fatalf("SPARQL transformation node types = %#v, want fno:Function", nodeTypes(catalog.Graph[1]))
	}
	if len(catalog.Graph[1].Expects) == 0 || len(catalog.Graph[1].Returns) == 0 {
		t.Fatalf("SPARQL transformation must advertise FnO expects and returns metadata")
	}
}

func TestClientIdentifierDocumentRoute(t *testing.T) {
	desc := httpapi.BuildServerDescription(httpapi.DefaultConfig("https://aggregator.example"))
	rec := get(mustPath(desc.ClientIdentifier))

	if rec.Code != http.StatusOK {
		t.Fatalf("GET client_identifier status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/ld+json" {
		t.Fatalf("Content-Type = %q, want application/ld+json", contentType)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func get(path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	httpapi.NewMux(httpapi.DefaultConfig("https://aggregator.example")).ServeHTTP(rec, req)
	return rec
}
