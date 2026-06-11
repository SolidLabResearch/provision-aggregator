package conformance_test

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRSVC001(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	parsed, err := url.Parse(agg.ServiceCollectionEndpoint)
	if err != nil {
		t.Fatalf("service collection endpoint is not a URL: %v", err)
	}
	if parsed.Scheme != "https" || parsed.Host == "" {
		t.Fatalf("service collection endpoint = %q, want absolute HTTPS URL", agg.ServiceCollectionEndpoint)
	}
}

func TestAGGRSVC002(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodHead, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("HEAD service collection status = %d, want 200", rec.Code)
	}
	if rec.Header().Get("ETag") == "" {
		t.Fatalf("HEAD service collection must include ETag")
	}
}

func TestAGGRSVC003(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	head := request(server, http.MethodHead, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	get := request(server, http.MethodGet, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	if get.Code != http.StatusOK {
		t.Fatalf("GET service collection status = %d, want 200", get.Code)
	}
	if get.Header().Get("ETag") != head.Header().Get("ETag") {
		t.Fatalf("GET ETag = %q, want HEAD ETag %q", get.Header().Get("ETag"), head.Header().Get("ETag"))
	}
	if get.Body.Len() == 0 {
		t.Fatalf("GET service collection must include a response body")
	}
}

func TestAGGRSVC004(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	rec := createServiceRaw(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if rec.Code != http.StatusCreated {
		t.Fatalf("service create status = %d, want 201", rec.Code)
	}
	if rec.Header().Get("Location") == "" {
		t.Fatalf("service create must include Location header")
	}
}

func TestAGGRSVC005(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if desc.ID == "" {
		t.Fatalf("service description @id is required")
	}
	if !contains(desc.Type, "aggr:Service") || !contains(desc.Type, "dcat:DataService") || !contains(desc.Type, "prov:SoftwareAgent") {
		t.Fatalf("service description types = %#v, want aggr:Service, dcat:DataService, prov:SoftwareAgent", desc.Type)
	}
	if desc.Transformation == "" || desc.Dataset.ForOutput == "" || desc.Dataset.Distribution.AccessURL == "" {
		t.Fatalf("service description is missing transformation, output, or access URL: %#v", desc)
	}
}

func TestAGGRSVC006(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	before := request(server, http.MethodHead, mustPath(agg.ServiceCollectionEndpoint), "", nil).Header().Get("ETag")
	createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	after := request(server, http.MethodHead, mustPath(agg.ServiceCollectionEndpoint), "", nil).Header().Get("ETag")
	if before == after {
		t.Fatalf("service collection ETag did not change after service creation: %q", before)
	}
}

func TestAGGRSVC007(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE service status = %d, want 204", rec.Code)
	}
	fetched := request(server, http.MethodGet, mustPath(desc.ID), "", nil)
	if fetched.Code != http.StatusNotFound {
		t.Fatalf("GET deleted service status = %d, want 404", fetched.Code)
	}
}

func TestAGGRSVC008(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	before := request(server, http.MethodHead, mustPath(agg.ServiceCollectionEndpoint), "", nil).Header().Get("ETag")
	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE service status = %d, want 204", rec.Code)
	}
	after := request(server, http.MethodHead, mustPath(agg.ServiceCollectionEndpoint), "", nil).Header().Get("ETag")
	if before == after {
		t.Fatalf("service collection ETag did not change after service deletion: %q", before)
	}
}

func TestAGGRSVC009(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	for name, body := range map[string]string{
		"unsupported transformation": `{"transformation":"https://aggregator.example/transformations#Other","query":"SELECT * WHERE { ?s ?p ?o }","source_urls":["https://source.example/data.ttl"]}`,
		"missing query":              `{"transformation":"https://aggregator.example/transformations#QueryView","source_urls":["https://source.example/data.ttl"]}`,
		"missing sources":            `{"transformation":"https://aggregator.example/transformations#QueryView","query":"SELECT * WHERE { ?s ?p ?o }"}`,
	} {
		rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(body))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s status = %d, want 400", name, rec.Code)
		}
	}
}

func TestAGGRSVC011(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/plain", []byte("not json"))
	if rec.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("unsupported service content type status = %d, want 415", rec.Code)
	}
}

func TestAGGRSVC012(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodGet, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	acceptPost := rec.Header().Get("Accept-Post")
	if !strings.Contains(acceptPost, "application/json") || !strings.Contains(acceptPost, "text/turtle") {
		t.Fatalf("Accept-Post = %q, want application/json and text/turtle", acceptPost)
	}
}

func TestAGGRSVC013(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodGet, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	var collection httpapi.ServiceCollection
	if err := json.Unmarshal(rec.Body.Bytes(), &collection); err != nil {
		t.Fatalf("service collection must be parseable JSON-LD: %v", err)
	}
	if collection.Type != "aggr:ServiceCollection" {
		t.Fatalf("service collection @type = %q, want aggr:ServiceCollection", collection.Type)
	}
}

func TestAGGRSVC014(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	created := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodGet, mustPath(created.ID), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET service description status = %d, want 200", rec.Code)
	}
	var fetched httpapi.ServiceDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &fetched); err != nil {
		t.Fatalf("service description must be parseable JSON-LD: %v", err)
	}
	if fetched.ID != created.ID {
		t.Fatalf("fetched service ID = %q, want %q", fetched.ID, created.ID)
	}
}

func TestAGGRSVC015(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if desc.Dataset.Distribution.AccessURL != desc.OutputURL {
		t.Fatalf("distribution accessURL = %q, want output URL %q", desc.Dataset.Distribution.AccessURL, desc.OutputURL)
	}
	if desc.Dataset.Distribution.AccessService != desc.ID {
		t.Fatalf("distribution accessService = %q, want service URL %q", desc.Dataset.Distribution.AccessService, desc.ID)
	}
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if link := rec.Header().Get("Link"); !strings.Contains(link, desc.ID) || !strings.Contains(link, "aggr:fromService") {
		t.Fatalf("output Link header = %q, want service backlink", link)
	}
}

func TestAGGRSVC016(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if desc.Status != "ready" || desc.CreatedAt == "" {
		t.Fatalf("service operational metadata status=%q createdAt=%q, want status and creation time", desc.Status, desc.CreatedAt)
	}
	if _, err := time.Parse(time.RFC3339, desc.CreatedAt); err != nil {
		t.Fatalf("service createdAt = %q, want RFC3339 time: %v", desc.CreatedAt, err)
	}
	if desc.ConformsTo != "https://w3id.org/aggregator#" {
		t.Fatalf("service conformsTo = %q, want aggregator protocol", desc.ConformsTo)
	}
}

func TestAGGRSVC017(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodGet, mustPath(agg.TransformationCatalog), "", nil)
	var catalog httpapi.TransformationCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &catalog); err != nil {
		t.Fatalf("instance transformation catalog must be JSON-LD: %v", err)
	}
	if desc.Applies == "" || len(catalog.Graph) == 0 || !contains(catalog.Graph[0].HasAppliedFunction, desc.Applies) {
		t.Fatalf("service applies = %q, want IRI advertised by instance catalog %#v", desc.Applies, catalog.Graph)
	}
	applied := catalogNode(t, catalog, desc.Applies)
	if applied.Type != "fno:AppliedFunction" || applied.Applies != desc.Transformation {
		t.Fatalf("catalog applied function = %#v, want fno:AppliedFunction for %q", applied, desc.Transformation)
	}
}

func TestAGGRSVC018(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	distribution := desc.Dataset.Distribution
	if distribution.MediaType != "http://www.iana.org/assignments/media-types/application/sparql-results+json" {
		t.Fatalf("distribution mediaType = %q, want IANA media type URL", distribution.MediaType)
	}
	if distribution.ConformsTo != "https://www.w3.org/TR/sparql11-results-json/" {
		t.Fatalf("distribution conformsTo = %q, want SPARQL Results JSON spec", distribution.ConformsTo)
	}
}

func TestAGGRSVC029(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	first := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	second := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodGet, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	var collection httpapi.ServiceCollection
	if err := json.Unmarshal(rec.Body.Bytes(), &collection); err != nil {
		t.Fatalf("service collection must be parseable JSON-LD: %v", err)
	}
	if collection.ID != agg.ServiceCollectionEndpoint {
		t.Fatalf("service collection @id = %q, want endpoint %q", collection.ID, agg.ServiceCollectionEndpoint)
	}
	if collection.Type != "aggr:ServiceCollection" {
		t.Fatalf("service collection @type = %q, want aggr:ServiceCollection", collection.Type)
	}
	if !jsonLDTermIsID(collection.Context, "hasService") {
		t.Fatalf("service collection context hasService = %#v, want @type @id so hasService objects are IRIs", collection.Context["hasService"])
	}
	for _, endpoint := range []string{first.ID, second.ID} {
		if !contains(collection.HasService, endpoint) {
			t.Fatalf("service collection hasService = %#v, want service description endpoint %q", collection.HasService, endpoint)
		}
	}
	if len(collection.HasService) != 2 {
		t.Fatalf("service collection hasService = %#v, want exactly the two service description endpoints", collection.HasService)
	}
}

func jsonLDTermIsID(context map[string]any, term string) bool {
	definition, ok := context[term].(map[string]any)
	if !ok {
		return false
	}
	return definition["@type"] == "@id"
}

func TestAGGRSVC030(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE service status = %d, want 204", rec.Code)
	}
	collectionRec := request(server, http.MethodGet, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	var collection httpapi.ServiceCollection
	if err := json.Unmarshal(collectionRec.Body.Bytes(), &collection); err != nil {
		t.Fatalf("service collection must be parseable JSON-LD: %v", err)
	}
	if contains(collection.HasService, desc.ID) {
		t.Fatalf("service collection still references deleted service %q: %#v", desc.ID, collection.HasService)
	}
}

func TestMilestone5ConstructProducesTurtleOutput(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequest(t, "CONSTRUCT WHERE { ?s ?p ?o }"))

	if desc.Status != "ready" {
		t.Fatalf("service status = %q, want ready", desc.Status)
	}
	if desc.OutputMediaType != "text/turtle" {
		t.Fatalf("output media type = %q, want text/turtle", desc.OutputMediaType)
	}
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("output status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "text/turtle" {
		t.Fatalf("output Content-Type = %q, want text/turtle", contentType)
	}
	if !strings.Contains(rec.Body.String(), "<https://example.test/s1>") {
		t.Fatalf("CONSTRUCT output does not contain source triples: %s", rec.Body.String())
	}
}

func TestMilestone5SelectProducesSPARQLResultsJSON(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequest(t, "SELECT * WHERE { ?s ?p ?o }"))

	if desc.Status != "ready" {
		t.Fatalf("service status = %q, want ready", desc.Status)
	}
	if desc.OutputMediaType != "application/sparql-results+json" {
		t.Fatalf("output media type = %q, want application/sparql-results+json", desc.OutputMediaType)
	}
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("output status = %d, want 200", rec.Code)
	}
	if contentType := rec.Header().Get("Content-Type"); contentType != "application/sparql-results+json" {
		t.Fatalf("output Content-Type = %q, want application/sparql-results+json", contentType)
	}
	if !strings.Contains(rec.Body.String(), `"vars"`) || !strings.Contains(rec.Body.String(), "https://example.test/s1") {
		t.Fatalf("SELECT output does not look like SPARQL Results JSON: %s", rec.Body.String())
	}
}

func TestMilestone5TurtleServiceDeploymentCreatesService(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(turtleServiceRequest(t, "SELECT * WHERE { ?s ?p ?o }")))
	if rec.Code != http.StatusCreated {
		t.Fatalf("Turtle service create status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	var desc httpapi.ServiceDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("Turtle service create response must be JSON-LD: %v", err)
	}
	if desc.Transformation != "https://aggregator.example/transformations#QueryView" || desc.QueryType != "SELECT" || len(desc.SourceURLs) != 1 {
		t.Fatalf("Turtle deployment mapped to unexpected service description: %#v", desc)
	}
}

func TestMilestone5RejectsUnsupportedQueries(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	for name, query := range map[string]string{
		"ASK":            "ASK WHERE { ?s ?p ?o }",
		"DESCRIBE":       "DESCRIBE ?s WHERE { ?s ?p ?o }",
		"UPDATE":         "INSERT DATA { <urn:s> <urn:p> <urn:o> }",
		"remote SERVICE": "SELECT * WHERE { SERVICE <https://remote.example/sparql> { ?s ?p ?o } }",
	} {
		rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(serviceRequest(t, query)))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s query status = %d, want 400", name, rec.Code)
		}
	}
}

func TestAGGRSEC001(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if desc.AASIssuer != "https://aas.example" {
		t.Fatalf("aas_issuer = %q, want configured AAS issuer", desc.AASIssuer)
	}
	if desc.AASResourceID == "" {
		t.Fatalf("service description must include aas_resource_id")
	}
}

func TestAGGRSEC002(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodGet, mustPath(desc.OutputURL), "", nil)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("output without RPT status = %d, want 401", rec.Code)
	}
}

func TestAGGRSEC003(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodGet, mustPath(desc.OutputURL), "", nil)
	challenge := rec.Header().Get("WWW-Authenticate")
	if !strings.HasPrefix(challenge, "UMA ") || !strings.Contains(challenge, `as_uri="https://aas.example"`) || !strings.Contains(challenge, `ticket="`) {
		t.Fatalf("WWW-Authenticate = %q, want UMA challenge with as_uri and ticket", challenge)
	}

	requests := server.PermissionRequests()
	if len(requests) != 1 {
		t.Fatalf("permission requests = %d, want 1", len(requests))
	}
	if requests[0].ResourceID != desc.AASResourceID {
		t.Fatalf("permission resource_id = %q, want service aas_resource_id %q", requests[0].ResourceID, desc.AASResourceID)
	}
	if !contains(requests[0].ResourceScopes, "read") {
		t.Fatalf("permission resource_scopes = %#v, want read", requests[0].ResourceScopes)
	}
}

func TestMilestone10OutputPermissionTicketComesFromAuthorizationServer(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "my-email@example.com"
	cfg.AccountPassword = "my-password"
	cfg.AccountWebID = "https://pod.example/alice#me"
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.UASIssuer = "https://uas.example"
	cfg.UASDerivationResourcesEndpoint = "https://uas.example/derivation-resources"
	sourceBody := []byte(`<https://example.test/protected> <https://example.test/p> "protected" .`)
	sourceURL := "https://source.example/source.nt"
	serviceCollectionResourceURL := "https://aggregator.example/aggregators/agg-1/services"
	serviceCollectionResourceID := "uma-" + serviceCollectionResourceURL
	var outputResourceURL string
	var outputResourceID string
	var updatedUASDerivationResource bool
	var updatedAASOutputResource bool
	cfg.SourceHTTPClient = &http.Client{Transport: protectedSourceTransportWithToken{body: sourceBody, token: "upstream-access-token"}}
	cfg.AccountHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.Host + req.URL.Path {
		case "css.example/.account/":
			return jsonResponse(req, map[string]any{
				"controls": map[string]any{
					"password": map[string]string{"login": "https://css.example/.account/login"},
					"account":  map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
				},
			}), nil
		case "css.example/.account/login":
			return jsonResponse(req, map[string]string{"authorization": "account-authorization"}), nil
		case "css.example/.account/client-credentials":
			return jsonResponse(req, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "css.example/.well-known/openid-configuration":
			return jsonResponse(req, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "css.example/token":
			return jsonResponse(req, map[string]any{"access_token": "css-account-access-token", "expires_in": 3600}), nil
		case "as.example/uma/.well-known/uma2-configuration":
			return jsonResponse(req, map[string]string{
				"issuer":                         "https://as.example/uma",
				"token_endpoint":                 "https://as.example/uma/token",
				"permission_endpoint":            "https://as.example/uma/permission",
				"introspection_endpoint":         "https://as.example/uma/introspect",
				"resource_registration_endpoint": "https://as.example/uma/resources",
				"registration_endpoint":          "https://as.example/uma/register",
			}), nil
		case "as.example/uma/register":
			if req.Header.Get("Authorization") != "WebID "+url.QueryEscape("https://pod.example/alice#me") {
				t.Fatalf("AS client registration authorization = %q", req.Header.Get("Authorization"))
			}
			return statusJSONResponse(req, http.StatusCreated, map[string]string{"client_id": "rs-client", "client_secret": "rs-secret"}), nil
		case "as.example/uma/token":
			want := "Basic " + base64.StdEncoding.EncodeToString([]byte("rs-client:rs-secret"))
			if req.Header.Get("Authorization") != want {
				t.Fatalf("PAT authorization = %q, want %q", req.Header.Get("Authorization"), want)
			}
			if err := req.ParseForm(); err != nil {
				t.Fatalf("parse PAT form: %v", err)
			}
			if req.Form.Get("grant_type") != "client_credentials" || req.Form.Get("scope") != "uma_protection" {
				t.Fatalf("PAT form = %#v", req.Form)
			}
			return statusJSONResponse(req, http.StatusCreated, map[string]any{
				"access_token": "pat-token",
				"token_type":   "Bearer",
				"expires_in":   3600,
			}), nil
		case "as.example/uma/resource-owner/assets":
			if req.Header.Get("Authorization") != "Bearer css-account-access-token" {
				t.Fatalf("asset discovery authorization = %q", req.Header.Get("Authorization"))
			}
			if req.URL.RawQuery != "include=description,scopes,policy_uri,policies" {
				t.Fatalf("asset discovery query = %q", req.URL.RawQuery)
			}
			return jsonResponse(req, map[string]any{"assets": []any{}}), nil
		case "uas.example/.well-known/uma2-configuration":
			return jsonResponse(req, map[string]string{
				"issuer":                         "https://uas.example",
				"token_endpoint":                 "https://uas.example/uma/token",
				"permission_endpoint":            "https://uas.example/uma/permission",
				"introspection_endpoint":         "https://uas.example/uma/introspect",
				"resource_registration_endpoint": "https://uas.example/uma/resources",
				"registration_endpoint":          "https://uas.example/uma/register",
			}), nil
		case "uas.example/uma/.well-known/uma2-configuration":
			return jsonResponse(req, map[string]string{
				"issuer":                         "https://uas.example/uma",
				"token_endpoint":                 "https://uas.example/uma/token",
				"permission_endpoint":            "https://uas.example/uma/permission",
				"introspection_endpoint":         "https://uas.example/uma/introspect",
				"resource_registration_endpoint": "https://uas.example/uma/resources",
				"registration_endpoint":          "https://uas.example/uma/register",
			}), nil
		case "uas.example/uma/token":
			if strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
				var body map[string]any
				if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
					t.Fatalf("decode UAS token JSON: %v", err)
				}
				if body["grant_type"] != "urn:ietf:params:oauth:grant-type:uma-ticket" ||
					body["ticket"] != "source-ticket" ||
					body["scope"] != "urn:knows:uma:scopes:derivation-creation" ||
					body["claim_token"] != "css-account-access-token" ||
					body["claim_token_format"] != "http://openid.net/specs/openid-connect-core-1_0.html#IDToken" {
					t.Fatalf("UAS token JSON = %#v", body)
				}
			} else {
				if err := req.ParseForm(); err != nil {
					t.Fatalf("parse UAS token form: %v", err)
				}
				if req.Form.Get("grant_type") != "urn:ietf:params:oauth:grant-type:uma-ticket" ||
					req.Form.Get("ticket") != "source-ticket" ||
					req.Form.Get("scope") != "urn:knows:uma:scopes:derivation-creation" ||
					req.Form.Get("claim_token") != "css-account-access-token" ||
					req.Form.Get("claim_token_format") != "http://openid.net/specs/openid-connect-core-1_0.html#IDToken" {
					t.Fatalf("UAS token form = %#v", req.Form)
				}
			}
			return statusJSONResponse(req, http.StatusOK, map[string]any{
				"access_token":           "upstream-access-token",
				"token_type":             "Bearer",
				"derivation_resource_id": "derivation-resource-service-1",
				"management_access_token": map[string]any{
					"access_token": "upstream-management-token",
					"token_type":   "Bearer",
				},
			}), nil
		case "as.example/uma/resources":
			if req.Header.Get("Authorization") != "Bearer pat-token" {
				t.Fatalf("resource registration authorization = %q", req.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode resource registration: %v", err)
			}
			resourceURL, _ := body["name"].(string)
			resourceID := "uma-" + resourceURL
			if strings.HasSuffix(resourceURL, "/output") {
				outputResourceURL = resourceURL
				outputResourceID = resourceID
			}
			return statusJSONResponse(req, http.StatusCreated, map[string]string{"_id": resourceID}), nil
		case "uas.example/uma/resources/derivation-resource-service-1":
			if req.Method != http.MethodPut {
				t.Fatalf("UAS derivation resource method = %s, want PUT", req.Method)
			}
			if req.Header.Get("Authorization") != "Bearer upstream-management-token" {
				t.Fatalf("UAS derivation resource authorization = %q", req.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode UAS derivation resource: %v", err)
			}
			scopes, _ := body["resource_scopes"].([]any)
			if body["name"] != "Derived resource" ||
				len(scopes) != 1 || scopes[0] != "urn:knows:uma:scopes:read" {
				t.Fatalf("UAS derivation resource body = %#v", body)
			}
			updatedUASDerivationResource = true
			return statusJSONResponse(req, http.StatusOK, map[string]string{"id": "derivation-resource-service-1"}), nil
		case "as.example/uma/resources/" + outputResourceID:
			if req.Method != http.MethodPut {
				t.Fatalf("AAS output resource update method = %s, want PUT", req.Method)
			}
			if req.Header.Get("Authorization") != "Bearer pat-token" {
				t.Fatalf("AAS output resource update authorization = %q", req.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode AAS output resource update: %v", err)
			}
			derivedFrom, _ := body["derived_from"].([]any)
			scopes, _ := body["resource_scopes"].([]any)
			if body["name"] != outputResourceURL ||
				len(scopes) != 1 || scopes[0] != "urn:example:css:modes:read" ||
				len(derivedFrom) != 1 {
				t.Fatalf("AAS output resource update body = %#v", body)
			}
			relation, _ := derivedFrom[0].(map[string]any)
			if relation["issuer"] != "https://uas.example/uma" || relation["derivation_resource_id"] != "derivation-resource-service-1" {
				t.Fatalf("AAS output derived_from = %#v", relation)
			}
			updatedAASOutputResource = true
			return statusJSONResponse(req, http.StatusOK, map[string]string{"_id": outputResourceID}), nil
		case "as.example/uma/permission":
			if req.Header.Get("Authorization") != "Bearer pat-token" {
				t.Fatalf("permission authorization = %q", req.Header.Get("Authorization"))
			}
			var body []map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode permission request: %v", err)
			}
			if len(body) != 1 {
				t.Fatalf("permission request body = %#v", body)
			}
			scopes, _ := body[0]["resource_scopes"].([]any)
			if body[0]["resource_id"] == serviceCollectionResourceID && len(scopes) == 1 && scopes[0] == "urn:example:css:modes:create" {
				return statusJSONResponse(req, http.StatusCreated, map[string]string{"ticket": "as-issued-create-ticket"}), nil
			}
			if body[0]["resource_id"] == outputResourceID && len(scopes) == 1 && scopes[0] == "urn:example:css:modes:read" {
				return statusJSONResponse(req, http.StatusCreated, map[string]string{"ticket": "as-issued-ticket"}), nil
			}
			t.Fatalf("permission request body = %#v, service collection = %q, output = %q", body, serviceCollectionResourceID, outputResourceID)
			return nil, nil
		case "as.example/uma/introspect":
			if req.Header.Get("Authorization") != "Bearer pat-token" {
				t.Fatalf("introspection authorization = %q", req.Header.Get("Authorization"))
			}
			if err := req.ParseForm(); err != nil {
				t.Fatalf("parse introspection form: %v", err)
			}
			switch req.Form.Get("token") {
			case "as-issued-create-rpt":
				return jsonResponse(req, map[string]any{
					"active": true,
					"permissions": []map[string]any{{
						"resource_id":     serviceCollectionResourceID,
						"resource_scopes": []string{"urn:example:css:modes:create"},
					}},
				}), nil
			case "as-issued-rpt":
				return jsonResponse(req, map[string]any{
					"active": true,
					"permissions": []map[string]any{{
						"resource_id":     outputResourceID,
						"resource_scopes": []string{"urn:example:css:modes:read"},
					}},
				}), nil
			default:
				t.Fatalf("introspection token = %q", req.Form.Get("token"))
			}
			return nil, nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)

	createChallenge := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(validServiceRequest(t)))
	if createChallenge.Code != http.StatusUnauthorized || !strings.Contains(createChallenge.Header().Get("WWW-Authenticate"), `ticket="as-issued-create-ticket"`) {
		t.Fatalf("service create challenge = %d %q, want AS-issued create ticket", createChallenge.Code, createChallenge.Header().Get("WWW-Authenticate"))
	}

	createResponse := requestWithBearer(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", sourceURL)), "as-issued-create-rpt")
	if createResponse.Code != http.StatusCreated {
		t.Fatalf("authorized service create status = %d, want 201; body: %s", createResponse.Code, createResponse.Body.String())
	}
	var desc httpapi.ServiceDescription
	if err := json.Unmarshal(createResponse.Body.Bytes(), &desc); err != nil {
		t.Fatalf("service create response must be JSON-LD: %v", err)
	}
	if len(desc.DerivedFrom) != 1 || desc.DerivedFrom[0].Issuer != "https://uas.example/uma" || desc.DerivedFrom[0].DerivationResourceID != "derivation-resource-service-1" {
		t.Fatalf("service derived_from = %#v, want upstream UAS issuer and derivation resource ID", desc.DerivedFrom)
	}

	rec := request(server, http.MethodGet, mustPath(desc.OutputURL), "", nil)
	challenge := rec.Header().Get("WWW-Authenticate")
	if rec.Code != http.StatusUnauthorized || !strings.Contains(challenge, `ticket="as-issued-ticket"`) {
		t.Fatalf("output challenge = %d %q, want AS-issued ticket", rec.Code, challenge)
	}
	if outputResourceURL != desc.AASResourceID {
		t.Fatalf("registered UMA resource = %q, want service aas_resource_id %q", outputResourceURL, desc.AASResourceID)
	}
	if !updatedUASDerivationResource {
		t.Fatalf("UAS derivation resource metadata was not updated")
	}
	if !updatedAASOutputResource {
		t.Fatalf("AAS output resource registration was not updated with derived_from")
	}
	requests := server.PermissionRequests()
	if len(requests) != 2 || requests[0].Ticket != "as-issued-create-ticket" || requests[1].Ticket != "as-issued-ticket" || !requests[0].LiveAuthorizationAsk || !requests[1].LiveAuthorizationAsk {
		t.Fatalf("permission evidence = %#v, want live AS ticket", requests)
	}

	output := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "as-issued-rpt")
	if output.Code != http.StatusOK {
		t.Fatalf("output with AS-issued RPT status = %d, want 200: %s", output.Code, output.Body.String())
	}
}

func TestAGGRSEC004(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "invalid-rpt")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("output with invalid RPT status = %d, want 401", rec.Code)
	}
	if challenge := rec.Header().Get("WWW-Authenticate"); !strings.HasPrefix(challenge, "UMA ") {
		t.Fatalf("invalid RPT challenge = %q, want UMA challenge", challenge)
	}
}

func TestAGGRSEC005(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("output with valid RPT status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "https://example.test/s1") {
		t.Fatalf("authorized output does not include materialized data: %s", rec.Body.String())
	}
}

func TestMilestone7ProtectedSourceIsFetchedUsingUMA(t *testing.T) {
	sourceBody := []byte(`<https://example.test/protected> <https://example.test/p> "protected" .`)
	sourceURL := "https://source.example/source.nt"

	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.SourceHTTPClient = &http.Client{Transport: protectedSourceTransport{body: sourceBody}}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", sourceURL))

	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("output with valid RPT status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "https://example.test/protected") {
		t.Fatalf("authorized output does not include protected source data: %s", rec.Body.String())
	}

	accesses := server.UpstreamAccesses()
	if len(accesses) != 1 {
		t.Fatalf("upstream access exchanges = %d, want 1", len(accesses))
	}
	if accesses[0].AuthorizationServer != "https://uas.example" || accesses[0].Ticket != "source-ticket" || accesses[0].Token != "valid-upstream-rpt" {
		t.Fatalf("upstream access evidence = %#v, want UAS, ticket, and RPT", accesses[0])
	}
}

func TestMilestone7SourceMetadataRecordsHash(t *testing.T) {
	sourceBody := []byte(`<https://example.test/protected> <https://example.test/p> "protected" .`)
	sourceURL := "https://source.example/source.nt"

	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.SourceHTTPClient = &http.Client{Transport: protectedSourceTransport{body: sourceBody}}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", sourceURL))

	if len(desc.SourceMetadata) != 1 {
		t.Fatalf("source metadata length = %d, want 1", len(desc.SourceMetadata))
	}
	metadata := desc.SourceMetadata[0]
	expectedHash := fmt.Sprintf("%x", sha256.Sum256(sourceBody))
	if metadata.URL != sourceURL || metadata.SHA256 != expectedHash {
		t.Fatalf("source metadata = %#v, want URL %q and sha256 %q", metadata, sourceURL, expectedHash)
	}
	if !metadata.Protected || metadata.AuthorizationServer != "https://uas.example" || metadata.PermissionTicket != "source-ticket" {
		t.Fatalf("source metadata must record protected UMA challenge details: %#v", metadata)
	}
}

func TestOutputReusesMaterializationWhenSourceETagIsUnchanged(t *testing.T) {
	sourceBody := []byte(`<https://example.test/source> <https://example.test/p> "first" .`)
	sourceURL := "https://source.example/source.nt"
	gets := 0
	heads := 0

	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.SourceHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			gets++
			resp := response(req, http.StatusOK, "application/n-triples", "", sourceBody)
			resp.Header.Set("ETag", `"v1"`)
			return resp, nil
		case http.MethodHead:
			heads++
			resp := response(req, http.StatusOK, "application/n-triples", "", nil)
			resp.Header.Set("ETag", `"v1"`)
			return resp, nil
		default:
			t.Fatalf("source method = %s, want GET or HEAD", req.Method)
			return nil, nil
		}
	})}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", sourceURL))

	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("output status = %d, want 200", rec.Code)
	}
	if gets != 1 || heads != 1 {
		t.Fatalf("source requests GET=%d HEAD=%d, want one initial GET and one freshness HEAD", gets, heads)
	}
}

func TestOutputRematerializesWhenSourceETagChanges(t *testing.T) {
	sourceURL := "https://source.example/source.nt"
	etag := `"v1"`
	body := []byte(`<https://example.test/source> <https://example.test/p> "first" .`)
	gets := 0

	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.SourceHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.Method {
		case http.MethodGet:
			gets++
			resp := response(req, http.StatusOK, "application/n-triples", "", body)
			resp.Header.Set("ETag", etag)
			return resp, nil
		case http.MethodHead:
			resp := response(req, http.StatusOK, "application/n-triples", "", nil)
			resp.Header.Set("ETag", etag)
			return resp, nil
		default:
			t.Fatalf("source method = %s, want GET or HEAD", req.Method)
			return nil, nil
		}
	})}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", sourceURL))

	etag = `"v2"`
	body = []byte(`<https://example.test/source> <https://example.test/p> "second" .`)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("output status = %d, want 200", rec.Code)
	}
	if gets != 2 {
		t.Fatalf("source GETs = %d, want initial GET and rematerialization GET", gets)
	}
	if !strings.Contains(rec.Body.String(), "second") {
		t.Fatalf("rematerialized output does not include changed source data: %s", rec.Body.String())
	}
}

func TestMilestone7FailedUpstreamAuthorizationFailsServiceCreation(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.UpstreamRPT = ""
	cfg.SourceHTTPClient = &http.Client{Transport: protectedSourceTransport{body: []byte(`<urn:s> <urn:p> <urn:o> .`)}}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", "https://source.example/source.nt")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("failed upstream authorization status = %d, want 400", rec.Code)
	}
}

func TestMilestone7FailedLiveUpstreamTokenRequestSubmitsAccessRequest(t *testing.T) {
	const ownerWebID = "https://pod.example/alice#me"
	sourceURL := "https://source.example/source.nt"
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = ownerWebID
	cfg.SourceHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(req, http.StatusUnauthorized, "text/plain", `UMA as_uri="https://uas.example/uma", ticket="source-ticket"`, []byte(http.StatusText(http.StatusUnauthorized))), nil
	})}

	tokenRequests := 0
	accessRequestSubmitted := false
	cfg.AccountHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://css.example/.account/":
			if req.Header.Get("Authorization") == "" {
				return jsonResponse(req, map[string]any{
					"controls": map[string]any{
						"password": map[string]string{"login": "https://css.example/.account/login"},
					},
				}), nil
			}
			return jsonResponse(req, map[string]any{
				"controls": map[string]any{
					"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
				},
			}), nil
		case "https://css.example/.account/login":
			return jsonResponse(req, map[string]string{"authorization": "account-authorization"}), nil
		case "https://css.example/.account/client-credentials":
			return jsonResponse(req, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "https://css.example/.well-known/openid-configuration":
			return jsonResponse(req, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "https://css.example/token":
			return jsonResponse(req, map[string]any{"access_token": "account-token"}), nil
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return jsonResponse(req, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			tokenRequests++
			return response(req, http.StatusForbidden, "application/json", "", []byte(`{"error":"request_denied"}`)), nil
		case "https://uas.example/uma/requests":
			if req.Method != http.MethodPost {
				t.Fatalf("access request method = %s, want POST", req.Method)
			}
			wantAuthorization := "WebID " + base64.StdEncoding.EncodeToString([]byte(ownerWebID))
			if req.Header.Get("Authorization") != wantAuthorization {
				t.Fatalf("access request authorization = %q, want %q", req.Header.Get("Authorization"), wantAuthorization)
			}
			if req.Header.Get("Content-Type") != "text/turtle" {
				t.Fatalf("access request content-type = %q", req.Header.Get("Content-Type"))
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			text := string(body)
			for _, want := range []string{
				"a sotw:EvaluationRequest",
				"sotw:requestedTarget <" + sourceURL + ">",
				"sotw:requestedAction odrl:read",
				"sotw:requestingParty <" + ownerWebID + ">",
				"ex:requestStatus ex:requested",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("access request body missing %q:\n%s", want, text)
				}
			}
			accessRequestSubmitted = true
			return response(req, http.StatusCreated, "text/plain", "", nil), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	server := httpapi.NewServer(cfg)
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", sourceURL)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("failed upstream authorization status = %d, want 400", rec.Code)
	}
	if tokenRequests != 2 {
		t.Fatalf("token requests = %d, want JSON and form attempts", tokenRequests)
	}
	if !accessRequestSubmitted {
		t.Fatalf("access request was not submitted")
	}
	requests := server.UpstreamAccessRequests()
	if len(requests) != 1 || requests[0].AuthorizationServer != "https://uas.example/uma" || requests[0].Action != "odrl:read" || requests[0].RequestURL != "https://uas.example/uma/requests" {
		t.Fatalf("access request evidence = %#v", requests)
	}
}

func TestMilestone7RejectsNonRDFSource(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.SourceHTTPClient = &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(req, http.StatusOK, "text/plain", "", []byte("not rdf")), nil
	})}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "application/json", []byte(serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", "https://source.example/source.txt")))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("non-RDF source status = %d, want 400", rec.Code)
	}
}

func TestMilestone8ServiceCreationUpdatesAASDerivedFrom(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	updates := server.DerivedFromUpdates()
	if len(updates) != 1 {
		t.Fatalf("derived_from updates = %d, want 1", len(updates))
	}
	if updates[0].AASResourceID != desc.AASResourceID {
		t.Fatalf("derived_from update resource = %q, want %q", updates[0].AASResourceID, desc.AASResourceID)
	}
	if len(updates[0].DerivedFrom) != 1 {
		t.Fatalf("derived_from update entries = %#v, want one entry", updates[0].DerivedFrom)
	}
}

func TestMilestone8DerivedFromContainsUASIssuer(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if len(desc.DerivedFrom) != 1 {
		t.Fatalf("derived_from entries = %#v, want one entry", desc.DerivedFrom)
	}
	if desc.DerivedFrom[0].Issuer != "https://uas.example" {
		t.Fatalf("derived_from issuer = %q, want upstream UAS issuer", desc.DerivedFrom[0].Issuer)
	}
}

func TestMilestone8DerivedFromContainsDerivationResourceID(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if len(desc.DerivedFrom) != 1 {
		t.Fatalf("derived_from entries = %#v, want one entry", desc.DerivedFrom)
	}
	if desc.DerivedFrom[0].DerivationResourceID == "" || !strings.HasPrefix(desc.DerivedFrom[0].DerivationResourceID, "derivation-resource-service-") {
		t.Fatalf("derivation_resource_id = %q, want generated derivation resource ID", desc.DerivedFrom[0].DerivationResourceID)
	}
}

func TestMilestone8ServiceRemainsFailedIfAASUpdateFails(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.FailDerivedFromUpdate = true
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	if desc.Status != "failed" {
		t.Fatalf("service status = %q, want failed when AAS derived_from update fails", desc.Status)
	}
	if len(desc.DerivedFrom) != 0 {
		t.Fatalf("failed service derived_from = %#v, want no committed derived_from", desc.DerivedFrom)
	}
	if updates := server.DerivedFromUpdates(); len(updates) != 0 {
		t.Fatalf("derived_from updates = %#v, want none after failed update", updates)
	}
}

func TestMilestone8PreviousOutputTokensAreExpiredWhenSupported(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	updates := server.DerivedFromUpdates()
	if len(updates) != 1 {
		t.Fatalf("derived_from updates = %d, want 1", len(updates))
	}
	if !updates[0].PreviousTokensExpired {
		t.Fatalf("previous output tokens must be marked expired after derived_from update")
	}
}

func TestMilestone9DeletesMaterializedOutput(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE service status = %d, want 204", rec.Code)
	}
	output := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if output.Code != http.StatusNotFound {
		t.Fatalf("GET deleted output status = %d, want 404", output.Code)
	}
}

func TestMilestone9RemovesAASAssetAndDerivedFrom(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE service status = %d, want 204", rec.Code)
	}
	cleanups := server.ServiceCleanups()
	if len(cleanups) != 1 {
		t.Fatalf("service cleanups = %d, want 1", len(cleanups))
	}
	if !cleanups[0].RemovedAASAsset || cleanups[0].AASResourceID != desc.AASResourceID {
		t.Fatalf("cleanup AAS evidence = %#v, want removed asset %q", cleanups[0], desc.AASResourceID)
	}
	if len(cleanups[0].RemovedDerivedFrom) != 1 || cleanups[0].RemovedDerivedFrom[0].DerivationResourceID != desc.DerivedFrom[0].DerivationResourceID {
		t.Fatalf("cleanup removed derived_from = %#v, want service derived_from %#v", cleanups[0].RemovedDerivedFrom, desc.DerivedFrom)
	}
}

func TestMilestone9DeletesUASDerivationResource(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("DELETE service status = %d, want 204", rec.Code)
	}
	cleanups := server.ServiceCleanups()
	if len(cleanups) != 1 {
		t.Fatalf("service cleanups = %d, want 1", len(cleanups))
	}
	if !contains(cleanups[0].DeletedDerivationResourceIDs, desc.DerivedFrom[0].DerivationResourceID) {
		t.Fatalf("deleted derivation resources = %#v, want %q", cleanups[0].DeletedDerivationResourceIDs, desc.DerivedFrom[0].DerivationResourceID)
	}
}

func createService(t *testing.T, server *httpapi.Server, collectionURL string, body string) httpapi.ServiceDescription {
	t.Helper()

	rec := createServiceRaw(t, server, collectionURL, body)
	var desc httpapi.ServiceDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("service create response must be JSON-LD: %v", err)
	}
	return desc
}

func createServiceRaw(t *testing.T, server *httpapi.Server, collectionURL string, body string) *httptest.ResponseRecorder {
	t.Helper()

	rec := request(server, http.MethodPost, mustPath(collectionURL), "application/json", []byte(body))
	if rec.Code != http.StatusCreated {
		t.Fatalf("service create status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	return rec
}

func validServiceRequest(t *testing.T) string {
	t.Helper()
	return serviceRequest(t, "SELECT * WHERE { ?s ?p ?o }")
}

func serviceRequest(t *testing.T, query string) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	sourcePath := filepath.Join(wd, "..", "fixtures", "source.nt")
	sourceURL := url.URL{Scheme: "file", Path: sourcePath}
	return serviceRequestWithSource(query, sourceURL.String())
}

func serviceRequestWithSource(query, sourceURL string) string {
	return fmt.Sprintf(`{"transformation":"https://aggregator.example/transformations#QueryView","query":%q,"source_urls":[%q]}`, query, sourceURL)
}

func turtleServiceRequest(t *testing.T, query string) string {
	t.Helper()

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	sourcePath := filepath.Join(wd, "..", "fixtures", "source.nt")
	sourceURL := url.URL{Scheme: "file", Path: sourcePath}
	return fmt.Sprintf(`@prefix aggr: <https://w3id.org/aggregator#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix fnoc: <https://w3id.org/function/vocabulary/composition#> .
@prefix : <https://aggregator.example/transformations#> .

[] a aggr:Service ;
   aggr:performs <https://aggregator.example/transformations#QueryView> ;
   aggr:applies [
     a fno:AppliedFunction ;
     fnoc:applies <https://aggregator.example/transformations#QueryView> ;
     fnoc:parameterBindings (
       [
         fnoc:boundParameter <https://aggregator.example/transformations#QueryParameter> ;
         fnoc:boundToTerm %q
       ]
       [
         fnoc:boundParameter <https://aggregator.example/transformations#SourceParameter> ;
         fnoc:boundToTerm <%s>
       ]
     )
   ] .
`, query, sourceURL.String())
}

type protectedSourceTransport struct {
	body []byte
}

func (t protectedSourceTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "Bearer valid-upstream-rpt" {
		return response(req, http.StatusUnauthorized, "text/plain", `UMA as_uri="https://uas.example", ticket="source-ticket"`, []byte(http.StatusText(http.StatusUnauthorized))), nil
	}
	return response(req, http.StatusOK, "application/n-triples", "", t.body), nil
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func response(req *http.Request, status int, contentType, challenge string, body []byte) *http.Response {
	header := http.Header{}
	if contentType != "" {
		header.Set("Content-Type", contentType)
	}
	if challenge != "" {
		header.Set("WWW-Authenticate", challenge)
	}
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     header,
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Request:    req,
	}
}
