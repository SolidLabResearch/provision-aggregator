package conformance_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRSVC032(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	valid := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{})))
	if valid.Code != http.StatusCreated {
		t.Fatalf("valid RDF deployment status = %d, want 201; body: %s", valid.Code, valid.Body.String())
	}
	malformed := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte("@prefix aggr: <https://w3id.org/aggregator#> .\n[] a aggr:Service ;"))
	if malformed.Code != http.StatusBadRequest {
		t.Fatalf("malformed RDF deployment status = %d, want 400", malformed.Code)
	}
}

func TestAGGRSVC033(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	zero := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specAppliedOnlyRequest(t)))
	if zero.Code != http.StatusBadRequest {
		t.Fatalf("zero aggr:Service deployment status = %d, want 400", zero.Code)
	}
	multiple := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specMultipleServicesRequest(t)))
	if multiple.Code != http.StatusBadRequest {
		t.Fatalf("multiple aggr:Service deployment status = %d, want 400", multiple.Code)
	}
}

func TestAGGRSVC034(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	blank := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{})))
	if blank.Code != http.StatusCreated {
		t.Fatalf("blank-node service deployment status = %d, want 201; body: %s", blank.Code, blank.Body.String())
	}
	uri := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{ServiceSubject: "<https://aggregator.example/requested-service>"})))
	if uri.Code != http.StatusCreated {
		t.Fatalf("URI service deployment status = %d, want 201; body: %s", uri.Code, uri.Body.String())
	}
	invalid := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{ServiceSubject: "<requested-service>"})))
	if invalid.Code != http.StatusBadRequest {
		t.Fatalf("invalid URI service deployment status = %d, want 400", invalid.Code)
	}
}

func TestAGGRSVC035(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{OmitPerforms: true})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing aggr:performs deployment status = %d, want 400", rec.Code)
	}
}

func TestAGGRSVC036(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{Transformation: "https://aggregator.example/transformations#Other"})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown transformation deployment status = %d, want 400", rec.Code)
	}
}

func TestAGGRSVC037(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{AppliedTransformation: "https://aggregator.example/transformations#Other"})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("mismatched applied transformation deployment status = %d, want 400", rec.Code)
	}
}

func TestAGGRSVC038(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{OmitApplies: true})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing aggr:applies deployment status = %d, want 400", rec.Code)
	}
}

func TestAGGRSVC039(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{OmitSourceBinding: true})))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("missing required binding deployment status = %d, want 400", rec.Code)
	}
}

func TestAGGRSVC040(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	first := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{})))
	if first.Code != http.StatusCreated {
		t.Fatalf("first applied-function deployment status = %d, want 201; body: %s", first.Code, first.Body.String())
	}
	second := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{ReverseBindings: true})))
	if second.Code != http.StatusCreated {
		t.Fatalf("second equivalent applied-function deployment status = %d, want 201; body: %s", second.Code, second.Body.String())
	}

	rec := request(server, http.MethodGet, mustPath(agg.TransformationCatalog), "", nil)
	var catalog httpapi.TransformationCatalog
	if err := json.Unmarshal(rec.Body.Bytes(), &catalog); err != nil {
		t.Fatalf("instance transformation catalog must be JSON-LD: %v", err)
	}
	if len(catalog.Graph) == 0 || len(catalog.Graph[0].HasAppliedFunction) != 1 {
		t.Fatalf("hasAppliedFunction = %#v, want one equivalent applied function", catalog.Graph[0].HasAppliedFunction)
	}
}

func TestAGGRSVC041(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	create := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{})))
	if create.Code != http.StatusCreated {
		t.Fatalf("service deployment status = %d, want 201; body: %s", create.Code, create.Body.String())
	}
	location := create.Header().Get("Location")
	if location == "" {
		t.Fatalf("service deployment must include Location header")
	}

	fetch := request(server, http.MethodGet, mustPath(location), "", nil)
	if fetch.Code != http.StatusOK {
		t.Fatalf("GET created service status = %d, want 200", fetch.Code)
	}
	var desc httpapi.ServiceDescription
	if err := json.Unmarshal(fetch.Body.Bytes(), &desc); err != nil {
		t.Fatalf("created service description must be JSON-LD: %v", err)
	}
	if desc.ID != location || !contains(desc.Type, "aggr:Service") || desc.Dataset.Distribution.AccessService != location {
		t.Fatalf("created service description does not model service data model: %#v", desc)
	}
}

func TestAGGRSVC042(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.OxigraphBinary = "missing-oxigraph-for-conformance"
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{})))
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("post-validation deployment failure status = %d, want 500; body: %s", rec.Code, rec.Body.String())
	}
}

func TestMilestone5TurtleServiceDeploymentAcceptsAppliedFunctionVocabularyNamespace(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{
		FnOCNamespace: "https://fno.io/vocabulary/composition/0.1.0/",
	})))
	if rec.Code != http.StatusCreated {
		t.Fatalf("legacy fnoc namespace deployment status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
}

func TestMilestone5TurtleServiceDeploymentAcceptsTypedQueryLiteral(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)

	rec := request(server, http.MethodPost, mustPath(agg.ServiceCollectionEndpoint), "text/turtle", []byte(specServiceRequest(t, specServiceOptions{
		TypedQueryLiteral: true,
	})))
	if rec.Code != http.StatusCreated {
		t.Fatalf("typed query literal deployment status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAGGRSEC026(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	registration := resourceRegistration(server.ResourceRegistrations(), desc.ID)
	if registration.Kind != "service_description" || !contains(registration.Scopes, "read") || !contains(registration.Scopes, "delete") {
		t.Fatalf("service resource registration = %#v, want read and delete scopes", registration)
	}
}

func TestAGGRSEC027(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	registration := resourceRegistration(server.ResourceRegistrations(), desc.OutputURL)
	if registration.Kind != "service_output" || !contains(registration.Scopes, "read") {
		t.Fatalf("output resource registration = %#v, want read scope", registration)
	}
}

func TestMilestone10ProvisionRegistersAggregatorResourcesAtConfiguredAS(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.AuthorizationServerURL = "https://configured-as.example"
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)

	for resourceURL, expectedKind := range map[string]string{
		agg.ID:                        "aggregator_description",
		agg.TransformationCatalog:     "instance_transformation_catalog",
		agg.ServiceCollectionEndpoint: "service_collection",
	} {
		registration := resourceRegistration(server.ResourceRegistrations(), resourceURL)
		if registration.Kind == "" || registration.AuthorizationServer != cfg.AuthorizationServerURL || registration.Kind != expectedKind {
			t.Fatalf("registration for %q = %#v, want kind %q at configured AS", resourceURL, registration, expectedKind)
		}
	}
}

func TestMilestone10ServiceResourcesRegisterAtConfiguredAS(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.AuthorizationServerURL = "https://configured-as.example"
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))

	for _, resourceURL := range []string{desc.ID, desc.OutputURL} {
		registration := resourceRegistration(server.ResourceRegistrations(), resourceURL)
		if registration.AuthorizationServer != cfg.AuthorizationServerURL {
			t.Fatalf("registration for %q = %#v, want configured AS", resourceURL, registration)
		}
	}
}

type specServiceOptions struct {
	ServiceSubject        string
	Transformation        string
	AppliedTransformation string
	OmitPerforms          bool
	OmitApplies           bool
	OmitSourceBinding     bool
	ReverseBindings       bool
	FnOCNamespace         string
	TypedQueryLiteral     bool
}

func specServiceRequest(t *testing.T, options specServiceOptions) string {
	t.Helper()
	subject := options.ServiceSubject
	if subject == "" {
		subject = "[]"
	}
	transformation := options.Transformation
	if transformation == "" {
		transformation = "https://aggregator.example/transformations#MediaProfileAggregation"
	}
	appliedTransformation := options.AppliedTransformation
	if appliedTransformation == "" {
		appliedTransformation = transformation
	}

	predicates := []string{"a aggr:Service"}
	if !options.OmitPerforms {
		predicates = append(predicates, fmt.Sprintf("aggr:performs <%s>", transformation))
	}
	if !options.OmitApplies {
		predicates = append(predicates, specAppliedFunction(t, appliedTransformation, options))
	}
	return specPrefixes(options) + "\n" + subject + " " + strings.Join(predicates, " ;\n   ") + " .\n"
}

func specAppliedOnlyRequest(t *testing.T) string {
	t.Helper()
	return specPrefixes(specServiceOptions{}) + "\n" + specAppliedFunction(t, "https://aggregator.example/transformations#MediaProfileAggregation", specServiceOptions{}) + " .\n"
}

func specMultipleServicesRequest(t *testing.T) string {
	t.Helper()
	first := specServiceRequest(t, specServiceOptions{})
	second := specServiceRequest(t, specServiceOptions{ServiceSubject: "<https://aggregator.example/requested-service-2>"})
	return first + "\n" + second
}

func specAppliedFunction(t *testing.T, transformation string, options specServiceOptions) string {
	t.Helper()
	bindings := []string{specQueryBinding(t, options)}
	if !options.OmitSourceBinding {
		bindings = append(bindings, specSourceBinding(t))
	}
	if options.ReverseBindings {
		for i, j := 0, len(bindings)-1; i < j; i, j = i+1, j-1 {
			bindings[i], bindings[j] = bindings[j], bindings[i]
		}
	}
	return fmt.Sprintf(`aggr:applies [
     a fno:AppliedFunction ;
     fnoc:applies <%s> ;
     fnoc:parameterBindings (
       %s
     )
   ]`, transformation, strings.Join(bindings, "\n       "))
}

func specQueryBinding(t *testing.T, options specServiceOptions) string {
	t.Helper()
	if options.TypedQueryLiteral {
		return `[
         fnoc:boundParameter <https://aggregator.example/transformations#QueryParameter> ;
         fnoc:boundToTerm """
           CONSTRUCT {
             ?s ?p ?o .
           }
           WHERE {
             ?s ?p ?o .
           }
         """^^xsd:string
       ]`
	}
	return `[
         fnoc:boundParameter <https://aggregator.example/transformations#QueryParameter> ;
         fnoc:boundToTerm "SELECT * WHERE { ?s ?p ?o }"
       ]`
}

func specSourceBinding(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("get working directory: %v", err)
	}
	sourcePath := filepath.Join(wd, "..", "fixtures", "source.nt")
	sourceURL := url.URL{Scheme: "file", Path: sourcePath}
	return fmt.Sprintf(`[
         fnoc:boundParameter <https://aggregator.example/transformations#SourceParameter> ;
         fnoc:boundToTerm <%s>
       ]`, sourceURL.String())
}

func specPrefixes(options specServiceOptions) string {
	fnocNamespace := options.FnOCNamespace
	if fnocNamespace == "" {
		fnocNamespace = "https://w3id.org/function/vocabulary/composition#"
	}
	return fmt.Sprintf(`@prefix aggr: <https://w3id.org/aggregator#> .
@prefix fno: <https://w3id.org/function/ontology#> .
@prefix xsd: <http://www.w3.org/2001/XMLSchema#> .
@prefix fnoc: <%s> .`, fnocNamespace)
}

func resourceRegistration(registrations []httpapi.ResourceRegistrationEvidence, resourceURL string) httpapi.ResourceRegistrationEvidence {
	for _, registration := range registrations {
		if registration.ResourceURL == resourceURL {
			return registration
		}
	}
	return httpapi.ResourceRegistrationEvidence{}
}
