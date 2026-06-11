package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

func TestConfiguredAuthorizationServerMetadataUsesEndpointConfigWithoutDiscovery(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerTokenEndpoint = "https://as.example/uma/token"
	cfg.AuthorizationServerPermissionEndpoint = "https://as.example/uma/permission"
	cfg.AuthorizationServerIntrospectionEndpoint = "https://as.example/uma/introspect"
	cfg.AuthorizationServerResourceRegistrationEndpoint = "https://as.example/uma/resources"
	cfg.AuthorizationServerRegistrationEndpoint = "https://as.example/uma/register"

	calledDiscovery := false
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		calledDiscovery = true
		return nil, errors.New("discovery should not be called")
	})}

	metadata, err := cfg.discoverAuthorizationServerMetadata("https://as.example/uma")
	if err != nil {
		t.Fatalf("discover metadata: %v", err)
	}
	if calledDiscovery {
		t.Fatalf("configured AS endpoints should not call discovery")
	}
	if metadata.Issuer != "https://as.example/uma" ||
		metadata.TokenEndpoint != "https://as.example/uma/token" ||
		metadata.PermissionEndpoint != "https://as.example/uma/permission" ||
		metadata.IntrospectionEndpoint != "https://as.example/uma/introspect" ||
		metadata.ResourceRegistrationEndpoint != "https://as.example/uma/resources" ||
		metadata.RegistrationEndpoint != "https://as.example/uma/register" {
		t.Fatalf("metadata = %#v", metadata)
	}
}

func TestAuthorizationServerEndpointOverridesDiscoveredMetadata(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerPermissionEndpoint = "https://override.example/permission"
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		return testJSONResponse(req, map[string]string{
			"issuer":                         "https://as.example/uma",
			"token_endpoint":                 "https://as.example/uma/token",
			"permission_endpoint":            "https://as.example/uma/permission",
			"introspection_endpoint":         "https://as.example/uma/introspect",
			"resource_registration_endpoint": "https://as.example/uma/resources",
			"registration_endpoint":          "https://as.example/uma/register",
		}), nil
	})}

	metadata, err := cfg.discoverAuthorizationServerMetadata("https://as.example/uma")
	if err != nil {
		t.Fatalf("discover metadata: %v", err)
	}
	if metadata.PermissionEndpoint != "https://override.example/permission" {
		t.Fatalf("permission endpoint = %q, want override", metadata.PermissionEndpoint)
	}
	if metadata.TokenEndpoint != "https://as.example/uma/token" {
		t.Fatalf("token endpoint = %q, want discovered value", metadata.TokenEndpoint)
	}
}

func TestConfiguredAuthorizationServerTokenEndpointIsUsedWithoutDiscovery(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerTokenEndpoint = "https://as.example/uma/token"
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		t.Fatalf("token endpoint discovery should not be called")
		return nil, nil
	})}

	tokenEndpoint, err := cfg.discoverAuthorizationServerTokenEndpoint("https://as.example/uma")
	if err != nil {
		t.Fatalf("discover token endpoint: %v", err)
	}
	if tokenEndpoint != "https://as.example/uma/token" {
		t.Fatalf("token endpoint = %q", tokenEndpoint)
	}
}

func TestShutdownDeletesRegisteredAuthorizationServerResources(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://pod.example/alice#me"
	cfg.Subject = "https://aggregator.example/profile/agg#me"
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerTokenEndpoint = "https://as.example/uma/token"
	cfg.AuthorizationServerPermissionEndpoint = "https://as.example/uma/permission"
	cfg.AuthorizationServerIntrospectionEndpoint = "https://as.example/uma/introspect"
	cfg.AuthorizationServerResourceRegistrationEndpoint = "https://as.example/uma/resources"
	cfg.AuthorizationServerRegistrationEndpoint = "https://as.example/uma/register"

	deleted := false
	clientDeleted := false
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://css.example/.account/":
			if req.Header.Get("Authorization") == "" {
				return testJSONResponse(req, map[string]any{
					"controls": map[string]any{
						"password": map[string]string{"login": "https://css.example/.account/login"},
					},
				}), nil
			}
			return testJSONResponse(req, map[string]any{
				"controls": map[string]any{
					"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
				},
			}), nil
		case "https://css.example/.account/login":
			return testJSONResponse(req, map[string]string{"authorization": "account-authorization"}), nil
		case "https://css.example/.account/client-credentials":
			return testJSONResponse(req, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "https://css.example/.well-known/openid-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "https://css.example/token":
			return testJSONResponse(req, map[string]any{"access_token": "account-token"}), nil
		case "https://as.example/uma/register":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]string{"client_id": "rs-client", "client_secret": "rs-secret"}), nil
		case "https://as.example/uma/token":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]any{"access_token": "pat-token", "token_type": "Bearer", "expires_in": 3600}), nil
		case "https://as.example/uma/resources":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]string{"_id": "uma-resource-1"}), nil
		case "https://as.example/uma/resource-owner/assets?include=description,scopes,policy_uri,policies":
			if req.Header.Get("Authorization") != "Bearer account-token" {
				t.Fatalf("asset discovery authorization = %q", req.Header.Get("Authorization"))
			}
			return testJSONResponse(req, map[string]any{"assets": []any{}}), nil
		case "https://as.example/uma/resources/" + url.PathEscape("uma-resource-1"):
			if req.Method != http.MethodDelete {
				t.Fatalf("resource cleanup method = %s, want DELETE", req.Method)
			}
			if req.Header.Get("Authorization") != "Bearer pat-token" {
				t.Fatalf("resource cleanup authorization = %q", req.Header.Get("Authorization"))
			}
			deleted = true
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		case "https://as.example/uma/register/" + url.PathEscape("rs-client"):
			if req.Method != http.MethodDelete {
				t.Fatalf("client cleanup method = %s, want DELETE", req.Method)
			}
			if req.Header.Get("Authorization") != "WebID "+url.QueryEscape("https://pod.example/alice#me") {
				t.Fatalf("client cleanup authorization = %q", req.Header.Get("Authorization"))
			}
			clientDeleted = true
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	server := NewServer(cfg)
	if err := server.registerConfiguredAuthorizationResource("https://aggregator.example/resource", []string{scopeRead}, "test_resource"); err != nil {
		t.Fatalf("register resource: %v", err)
	}
	if err := server.Shutdown(); err != nil {
		t.Fatalf("shutdown: %v", err)
	}
	if !deleted {
		t.Fatalf("shutdown did not delete AS resource registration")
	}
	if !clientDeleted {
		t.Fatalf("shutdown did not delete AS client registration")
	}
}

func TestAuthorizationServerClientRegistrationConflictDeletesStaleClientAndRetries(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://pod.example/alice#me"
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerTokenEndpoint = "https://as.example/uma/token"
	cfg.AuthorizationServerPermissionEndpoint = "https://as.example/uma/permission"
	cfg.AuthorizationServerIntrospectionEndpoint = "https://as.example/uma/introspect"
	cfg.AuthorizationServerResourceRegistrationEndpoint = "https://as.example/uma/resources"
	cfg.AuthorizationServerRegistrationEndpoint = "https://as.example/uma/register"

	registrationPosts := 0
	staleDeleted := false
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://css.example/.account/":
			if req.Header.Get("Authorization") == "" {
				return testJSONResponse(req, map[string]any{
					"controls": map[string]any{
						"password": map[string]string{"login": "https://css.example/.account/login"},
					},
				}), nil
			}
			return testJSONResponse(req, map[string]any{
				"controls": map[string]any{
					"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
				},
			}), nil
		case "https://css.example/.account/login":
			return testJSONResponse(req, map[string]string{"authorization": "account-authorization"}), nil
		case "https://css.example/.account/client-credentials":
			return testJSONResponse(req, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "https://css.example/.well-known/openid-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "https://css.example/token":
			return testJSONResponse(req, map[string]any{"access_token": "account-token"}), nil
		case "https://as.example/uma/register":
			switch req.Method {
			case http.MethodPost:
				registrationPosts++
				if registrationPosts == 1 {
					return testStatusJSONResponse(req, http.StatusConflict, map[string]string{"message": "already registered"}), nil
				}
				return testStatusJSONResponse(req, http.StatusCreated, map[string]string{"client_id": "new-client", "client_secret": "new-secret"}), nil
			case http.MethodGet:
				return testJSONResponse(req, []map[string]string{{
					"id":  "stale-client",
					"uri": "https://aggregator.example",
				}}), nil
			default:
				t.Fatalf("registration method = %s", req.Method)
			}
		case "https://as.example/uma/register/" + url.PathEscape("stale-client"):
			if req.Method != http.MethodDelete {
				t.Fatalf("stale client cleanup method = %s, want DELETE", req.Method)
			}
			staleDeleted = true
			return &http.Response{
				StatusCode: http.StatusNoContent,
				Body:       io.NopCloser(strings.NewReader("")),
				Request:    req,
			}, nil
		case "https://as.example/uma/token":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]any{"access_token": "pat-token", "token_type": "Bearer", "expires_in": 3600}), nil
		case "https://as.example/uma/resource-owner/assets?include=description,scopes,policy_uri,policies":
			return testJSONResponse(req, map[string]any{"assets": []any{}}), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
		return nil, nil
	})}

	server := NewServer(cfg)
	if server.authorizationServerError != nil {
		t.Fatalf("authorization server initialization error: %v", server.authorizationServerError)
	}
	if registrationPosts != 2 {
		t.Fatalf("registration posts = %d, want initial POST and retry", registrationPosts)
	}
	if !staleDeleted {
		t.Fatalf("stale client registration was not deleted")
	}
}

func TestLivePermissionRequestReturnsEmptyTicketWhenResourceIsPublic(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://pod.example/alice#me"
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerTokenEndpoint = "https://as.example/uma/token"
	cfg.AuthorizationServerPermissionEndpoint = "https://as.example/uma/permission"
	cfg.AuthorizationServerIntrospectionEndpoint = "https://as.example/uma/introspect"
	cfg.AuthorizationServerResourceRegistrationEndpoint = "https://as.example/uma/resources"
	cfg.AuthorizationServerRegistrationEndpoint = "https://as.example/uma/register"

	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://css.example/.account/":
			if req.Header.Get("Authorization") == "" {
				return testJSONResponse(req, map[string]any{
					"controls": map[string]any{
						"password": map[string]string{"login": "https://css.example/.account/login"},
					},
				}), nil
			}
			return testJSONResponse(req, map[string]any{
				"controls": map[string]any{
					"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
				},
			}), nil
		case "https://css.example/.account/login":
			return testJSONResponse(req, map[string]string{"authorization": "account-authorization"}), nil
		case "https://css.example/.account/client-credentials":
			return testJSONResponse(req, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "https://css.example/.well-known/openid-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "https://css.example/token":
			return testJSONResponse(req, map[string]any{"access_token": "account-token"}), nil
		case "https://as.example/uma/register":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]string{"client_id": "rs-client", "client_secret": "rs-secret"}), nil
		case "https://as.example/uma/token":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]any{"access_token": "pat-token", "token_type": "Bearer", "expires_in": 3600}), nil
		case "https://as.example/uma/resource-owner/assets?include=description,scopes,policy_uri,policies":
			return testJSONResponse(req, map[string]any{"assets": []any{}}), nil
		case "https://as.example/uma/permission":
			if req.Method != http.MethodPost {
				t.Fatalf("permission method = %s, want POST", req.Method)
			}
			return testStatusJSONResponse(req, http.StatusOK, map[string]any{"active": true}), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	server := NewServer(cfg)
	ticket, err := server.requestLivePermission("public-resource", []string{scopeRead})
	if err != nil {
		t.Fatalf("request permission: %v", err)
	}
	if ticket != "" {
		t.Fatalf("ticket = %q, want empty ticket for public resource", ticket)
	}
}

func TestStartupSynchronizesAuthorizationPoliciesForManagedAssets(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://pod.example/alice#me"
	cfg.AuthorizationServerURL = "https://as.example/uma"
	cfg.AuthorizationServerTokenEndpoint = "https://as.example/uma/token"
	cfg.AuthorizationServerPermissionEndpoint = "https://as.example/uma/permission"
	cfg.AuthorizationServerIntrospectionEndpoint = "https://as.example/uma/introspect"
	cfg.AuthorizationServerResourceRegistrationEndpoint = "https://as.example/uma/resources"
	cfg.AuthorizationServerRegistrationEndpoint = "https://as.example/uma/register"

	var patchedPublicRead bool
	var createdAgreement bool
	var patchedAggregatorDelete bool
	resourceID := "https://aggregator.example/aggregators/agg-1/services"
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://css.example/.account/":
			if req.Header.Get("Authorization") == "" {
				return testJSONResponse(req, map[string]any{
					"controls": map[string]any{
						"password": map[string]string{"login": "https://css.example/.account/login"},
					},
				}), nil
			}
			return testJSONResponse(req, map[string]any{
				"controls": map[string]any{
					"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
				},
			}), nil
		case "https://css.example/.account/login":
			return testJSONResponse(req, map[string]string{"authorization": "account-authorization"}), nil
		case "https://css.example/.account/client-credentials":
			return testJSONResponse(req, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "https://css.example/.well-known/openid-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "https://css.example/token":
			return testJSONResponse(req, map[string]any{"access_token": "account-token"}), nil
		case "https://as.example/uma/register":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]string{"client_id": "rs-client", "client_secret": "rs-secret"}), nil
		case "https://as.example/uma/token":
			return testStatusJSONResponse(req, http.StatusCreated, map[string]any{"access_token": "pat-token", "token_type": "Bearer", "expires_in": 3600}), nil
		case "https://as.example/uma/resource-owner/assets?include=description,scopes,policy_uri,policies":
			if req.Header.Get("Authorization") != "Bearer account-token" {
				t.Fatalf("asset discovery authorization = %q", req.Header.Get("Authorization"))
			}
			return testJSONResponse(req, map[string]any{
				"assets": []map[string]any{{
					"_id": resourceID,
					"description": map[string]any{
						"resource_scopes": []string{scopeRead, scopeCreate, scopeDelete},
					},
				}},
			}), nil
		case "https://as.example/uma/policies":
			switch req.Method {
			case http.MethodGet:
				if req.Header.Get("Accept") != "text/turtle" {
					t.Fatalf("policies accept = %q", req.Header.Get("Accept"))
				}
				return testTurtleResponse(req, `@prefix odrl: <http://www.w3.org/ns/odrl/2/> .

<https://as.example/uma/policies/public/existing> a odrl:Set ;
  odrl:permission <https://as.example/uma/policies/public/existing#rule> .

<https://as.example/uma/policies/public/existing#rule> a odrl:Permission ;
  odrl:target <https://aggregator.example/aggregators/agg-1/services> ;
  odrl:action odrl:write ;
  odrl:assigner <https://pod.example/alice#me> .
`), nil
			case http.MethodPost:
				body, err := io.ReadAll(req.Body)
				if err != nil {
					t.Fatal(err)
				}
				text := string(body)
				if !strings.Contains(text, " a <http://www.w3.org/ns/odrl/2/Agreement> ") ||
					!strings.Contains(text, "odrl:action <http://www.w3.org/ns/odrl/2/create>") ||
					!strings.Contains(text, "odrl:assignee <https://aggregator.example/profile/agg#me>") {
					t.Fatalf("unexpected agreement policy body:\n%s", text)
				}
				createdAgreement = true
				return &http.Response{StatusCode: http.StatusCreated, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
			default:
				t.Fatalf("policies method = %s", req.Method)
			}
		case "https://as.example/uma/policies/" + url.PathEscape("https://as.example/uma/policies/public/existing"):
			if req.Method != http.MethodPatch {
				t.Fatalf("public policy method = %s, want PATCH", req.Method)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "odrl:action <http://www.w3.org/ns/odrl/2/read>") ||
				strings.Contains(string(body), "odrl:assignee") {
				t.Fatalf("unexpected public read patch:\n%s", string(body))
			}
			patchedPublicRead = true
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		case "https://as.example/uma/policies/" + url.PathEscape("https://as.example/uma/policies/agreement/"+url.PathEscape(resourceID)):
			if req.Method != http.MethodPatch {
				t.Fatalf("agreement policy method = %s, want PATCH", req.Method)
			}
			body, err := io.ReadAll(req.Body)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), "odrl:action <http://www.w3.org/ns/odrl/2/delete>") ||
				!strings.Contains(string(body), "odrl:assignee <https://aggregator.example/profile/agg#me>") {
				t.Fatalf("unexpected aggregator delete patch:\n%s", string(body))
			}
			patchedAggregatorDelete = true
			return &http.Response{StatusCode: http.StatusNoContent, Body: io.NopCloser(strings.NewReader("")), Request: req}, nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
		return nil, nil
	})}

	server := NewServer(cfg)
	if server.authorizationServerError != nil {
		t.Fatalf("authorization server initialization error: %v", server.authorizationServerError)
	}
	if !patchedPublicRead {
		t.Fatalf("public read policy was not patched")
	}
	if !createdAgreement {
		t.Fatalf("owner agreement policy was not created")
	}
	if !patchedAggregatorDelete {
		t.Fatalf("aggregator delete policy was not patched")
	}
}

type testRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn testRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func testJSONResponse(req *http.Request, value any) *http.Response {
	return testStatusJSONResponse(req, http.StatusOK, value)
}

func testStatusJSONResponse(req *http.Request, status int, value any) *http.Response {
	body, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(body))),
		Request:    req,
	}
}

func testTurtleResponse(req *http.Request, body string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     http.Header{"Content-Type": []string{"text/turtle"}},
		Body:       io.NopCloser(strings.NewReader(body)),
		Request:    req,
	}
}
