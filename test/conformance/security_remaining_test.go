package conformance_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"aggregator-provision/internal/httpapi"
)

func TestAGGRSEC006(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	if cfg.AASIssuer == "" {
		t.Fatalf("AAS issuer must be configured")
	}
}

func TestAGGRSEC007(t *testing.T) {
	server, desc := protectedOutput(t)
	challenge := request(server, http.MethodGet, mustPath(desc.OutputURL), "", nil)
	if challenge.Code != http.StatusUnauthorized || !strings.Contains(challenge.Header().Get("WWW-Authenticate"), `ticket="`) {
		t.Fatalf("missing RPT challenge = %d %q", challenge.Code, challenge.Header().Get("WWW-Authenticate"))
	}
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid RPT status = %d, want 200", rec.Code)
	}
}

func TestAGGRSEC008(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "expired-rpt")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expired RPT status = %d, want 401", rec.Code)
	}
}

func TestAGGRSEC009(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "insufficient-scope-rpt")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("insufficient-scope RPT status = %d, want 401", rec.Code)
	}
}

func TestAGGRSEC010(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("valid RPT introspection-equivalent access status = %d, want 200", rec.Code)
	}
}

func TestAGGRSEC011(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "expired-rpt")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("inactive RPT status = %d, want 401", rec.Code)
	}
}

func TestAGGRSEC012(t *testing.T) {
	server, _ := protectedUpstreamService(t, "valid-upstream-rpt")
	accesses := server.UpstreamAccesses()
	if len(accesses) != 1 || accesses[0].AuthorizationServer != "https://uas.example" || accesses[0].Ticket == "" {
		t.Fatalf("upstream need_info-equivalent evidence = %#v", accesses)
	}
}

func TestAGGRSEC013(t *testing.T) {
	_, desc := protectedOutput(t)
	if len(desc.DerivedFrom) != 0 {
		t.Fatalf("derivation evidence = %#v, want none without upstream authorization server evidence", desc.DerivedFrom)
	}
}

func TestAGGRSEC014(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := request(server, http.MethodGet, mustPath(desc.OutputURL), "", nil)
	if rec.Code != http.StatusUnauthorized || !strings.Contains(rec.Header().Get("WWW-Authenticate"), "UMA ") {
		t.Fatalf("derived resource need_info-equivalent challenge = %d %q", rec.Code, rec.Header().Get("WWW-Authenticate"))
	}
}

func TestAGGRSEC015(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "valid-output-rpt")
	if rec.Code != http.StatusOK {
		t.Fatalf("derived-resource RPT status = %d, want 200", rec.Code)
	}
}

func TestAGGRSEC016(t *testing.T) {
	server, _ := protectedOutput(t)
	updates := server.DerivedFromUpdates()
	if len(updates) != 1 || len(updates[0].DerivedFrom) != 0 {
		t.Fatalf("management-access-token-equivalent derivation evidence = %#v", updates)
	}
}

func TestAGGRSEC017(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	rec := request(server, http.MethodGet, mustPath(agg.ServiceCollectionEndpoint), "", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("service collection read status = %d, want 200 for local adapter", rec.Code)
	}
}

func TestAGGRSEC018(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	rec := createServiceRaw(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	if rec.Code != http.StatusCreated {
		t.Fatalf("service creation status = %d, want 201 for local adapter", rec.Code)
	}
}

func TestAGGRSEC019(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodPatch, mustPath(desc.ID), "application/json", []byte(`{}`), "invalid-update-rpt")
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("unsupported service update status = %d, want 405", rec.Code)
	}
}

func TestAGGRSEC020(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := request(server, http.MethodDelete, mustPath(desc.ID), "", nil)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("service deletion status = %d, want 204 for local adapter", rec.Code)
	}
}

func TestAGGRSEC021(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "ticket-not-rpt")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid UMA ticket-as-token status = %d, want 401", rec.Code)
	}
}

func TestAGGRSEC022(t *testing.T) {
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.FailDerivedFromUpdate = true
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	desc := createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
	if desc.Status != "failed" {
		t.Fatalf("invalid transformation-description claim status = %q, want failed", desc.Status)
	}
}

func TestAGGRSEC023(t *testing.T) {
	_, rec := protectedUpstreamServiceRaw(t, "invalid-upstream-rpt")
	if rec.Code != http.StatusCreated {
		t.Fatalf("invalid upstream access token claim status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
}

func TestAGGRSEC024(t *testing.T) {
	server, desc := protectedOutput(t)
	rec := requestWithBearer(server, http.MethodGet, mustPath(desc.OutputURL), "", nil, "invalid-management-access-token")
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("invalid management access token status = %d, want 401", rec.Code)
	}
}

func TestAGGRSEC025(t *testing.T) {
	assertInvalidManagementRequest(t, `{"management_flow":"provision","aggregator":"https://unrelated.example/resource"}`)
}

func TestMilestone10CSSAccountTokenUsedForProtectedSource(t *testing.T) {
	sourceBody := []byte(`<https://example.test/protected> <https://example.test/p> "protected" .`)
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "my-email@example.com"
	cfg.AccountPassword = "my-password"
	cfg.AccountWebID = "http://localhost:3000/my-pod/card#me"
	cfg.AccountHTTPClient = &http.Client{Transport: fakeCSSAccountTransport{t: t}}
	cfg.SourceHTTPClient = &http.Client{Transport: protectedSourceTransportWithToken{
		body:  sourceBody,
		token: "generated-uma-access-token",
	}}

	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	if agg.Subject != cfg.AccountWebID {
		t.Fatalf("provisioned subject = %q, want configured WebID %q", agg.Subject, cfg.AccountWebID)
	}
	desc := createService(t, server, agg.ServiceCollectionEndpoint, serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", "https://source.example/source.nt"))
	if desc.Status != "ready" {
		t.Fatalf("service status = %q, want ready", desc.Status)
	}

	accesses := server.UpstreamAccesses()
	if len(accesses) != 1 {
		t.Fatalf("upstream access exchanges = %d, want 1", len(accesses))
	}
	if accesses[0].Token != "generated-uma-access-token" {
		t.Fatalf("upstream token = %q, want generated UMA access token", accesses[0].Token)
	}
}

func TestAGGRSEC028(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	assertCORSPreflight(t, server, "/", http.MethodGet)
	assertCORSActual(t, server, http.MethodGet, "/")
	assertCORSPreflight(t, server, "/client.jsonld", http.MethodGet)
	assertCORSActual(t, server, http.MethodGet, "/client.jsonld")
}

func TestAGGRSEC029(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	for _, endpoint := range []string{"/transformations", mustPath(agg.TransformationCatalog)} {
		assertCORSPreflight(t, server, endpoint, http.MethodGet)
		assertCORSActual(t, server, http.MethodGet, endpoint)
	}
}

func TestAGGRSEC030(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		assertCORSPreflight(t, server, "/registration", method)
	}
}

func TestAGGRSEC031(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	path := mustPath(agg.ID)
	assertCORSPreflight(t, server, path, http.MethodGet)
	assertCORSActual(t, server, http.MethodGet, path)
}

func TestAGGRSEC032(t *testing.T) {
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	path := mustPath(agg.ServiceCollectionEndpoint)
	for _, method := range []string{http.MethodHead, http.MethodGet, http.MethodPost} {
		assertCORSPreflight(t, server, path, method)
	}
	assertCORSActual(t, server, http.MethodHead, path)
	assertCORSActual(t, server, http.MethodGet, path)
}

func TestAGGRSEC033(t *testing.T) {
	server, desc := protectedOutput(t)
	for _, path := range []string{mustPath(desc.ID), mustPath(desc.OutputURL)} {
		for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPatch, http.MethodPut, http.MethodDelete} {
			assertCORSPreflight(t, server, path, method)
		}
	}
	assertCORSActual(t, server, http.MethodGet, mustPath(desc.ID))
	assertCORSActualWithBearer(t, server, http.MethodGet, mustPath(desc.OutputURL), "valid-output-rpt")
}

func assertCORSPreflight(t *testing.T, server *httpapi.Server, path, method string) {
	t.Helper()
	rec := requestWithCORS(t, server, http.MethodOptions, path, "", nil, "", method)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("CORS preflight %s %s status = %d, want 204", method, path, rec.Code)
	}
	assertCORSHeaders(t, rec, method)
}

func assertCORSActual(t *testing.T, server *httpapi.Server, method, path string) {
	t.Helper()
	rec := requestWithCORS(t, server, method, path, "", nil, "", "")
	if rec.Code < 200 || rec.Code >= 400 {
		t.Fatalf("CORS actual %s %s status = %d, want 2xx/3xx", method, path, rec.Code)
	}
	assertCORSHeaders(t, rec, method)
}

func assertCORSActualWithBearer(t *testing.T, server *httpapi.Server, method, path, token string) {
	t.Helper()
	rec := requestWithCORS(t, server, method, path, "", nil, token, "")
	if rec.Code < 200 || rec.Code >= 400 {
		t.Fatalf("CORS actual %s %s status = %d, want 2xx/3xx", method, path, rec.Code)
	}
	assertCORSHeaders(t, rec, method)
}

func requestWithCORS(t *testing.T, server *httpapi.Server, method, path, contentType string, body []byte, bearer, preflightMethod string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, bytes.NewReader(body))
	req.Header.Set("Origin", "https://client.example")
	if preflightMethod != "" {
		req.Header.Set("Access-Control-Request-Method", preflightMethod)
		req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type, DPoP")
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	server.Routes().ServeHTTP(rec, req)
	return rec
}

func assertCORSHeaders(t *testing.T, rec *httptest.ResponseRecorder, method string) {
	t.Helper()
	if origin := rec.Header().Get("Access-Control-Allow-Origin"); origin != "https://client.example" {
		t.Fatalf("Access-Control-Allow-Origin = %q, want client origin", origin)
	}
	if !headerListContains(rec.Header().Get("Access-Control-Allow-Methods"), method) {
		t.Fatalf("Access-Control-Allow-Methods = %q, want %s", rec.Header().Get("Access-Control-Allow-Methods"), method)
	}
	for _, header := range []string{"Authorization", "Content-Type", "DPoP"} {
		if !headerListContains(rec.Header().Get("Access-Control-Allow-Headers"), header) {
			t.Fatalf("Access-Control-Allow-Headers = %q, want %s", rec.Header().Get("Access-Control-Allow-Headers"), header)
		}
	}
	if rec.Header().Get("Access-Control-Expose-Headers") == "" {
		t.Fatalf("Access-Control-Expose-Headers is required")
	}
}

func headerListContains(list, want string) bool {
	for _, item := range strings.Split(list, ",") {
		if strings.EqualFold(strings.TrimSpace(item), want) {
			return true
		}
	}
	return false
}

func protectedOutput(t *testing.T) (*httpapi.Server, httpapi.ServiceDescription) {
	t.Helper()
	server := httpapi.NewServer(httpapi.DefaultConfig("https://aggregator.example"))
	agg := provision(t, server)
	return server, createService(t, server, agg.ServiceCollectionEndpoint, validServiceRequest(t))
}

func protectedUpstreamService(t *testing.T, upstreamRPT string) (*httpapi.Server, httpapi.ServiceDescription) {
	t.Helper()
	server, rec := protectedUpstreamServiceRaw(t, upstreamRPT)
	if rec.Code != http.StatusCreated {
		t.Fatalf("protected upstream service status = %d, want 201; body: %s", rec.Code, rec.Body.String())
	}
	var desc httpapi.ServiceDescription
	if err := json.Unmarshal(rec.Body.Bytes(), &desc); err != nil {
		t.Fatalf("protected upstream service response must be JSON-LD: %v", err)
	}
	return server, desc
}

func protectedUpstreamServiceRaw(t *testing.T, upstreamRPT string) (*httpapi.Server, *httptest.ResponseRecorder) {
	t.Helper()
	sourceBody := []byte(`<https://example.test/protected> <https://example.test/p> "protected" .`)
	cfg := httpapi.DefaultConfig("https://aggregator.example")
	cfg.UpstreamRPT = upstreamRPT
	cfg.SourceHTTPClient = &http.Client{Transport: protectedSourceTransport{body: sourceBody}}
	server := httpapi.NewServer(cfg)
	agg := provision(t, server)
	rec := createServiceRawNoFail(t, server, agg.ServiceCollectionEndpoint, serviceRequestWithSource("SELECT * WHERE { ?s ?p ?o }", "https://source.example/source.nt"))
	return server, rec
}

func createServiceRawNoFail(t *testing.T, server *httpapi.Server, collectionURL string, body string) *httptest.ResponseRecorder {
	t.Helper()
	return request(server, http.MethodPost, mustPath(collectionURL), "application/json", []byte(body))
}

type protectedSourceTransportWithToken struct {
	body  []byte
	token string
}

func (t protectedSourceTransportWithToken) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get("Authorization") != "Bearer "+t.token {
		return response(req, http.StatusUnauthorized, "text/plain", `UMA as_uri="https://uas.example/uma", ticket="source-ticket"`, []byte(http.StatusText(http.StatusUnauthorized))), nil
	}
	return response(req, http.StatusOK, "application/n-triples", "", t.body), nil
}

type fakeCSSAccountTransport struct {
	t *testing.T
}

func (t fakeCSSAccountTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.t.Helper()

	switch req.URL.Path {
	case "/.account/":
		if req.Method != http.MethodGet {
			t.t.Fatalf("/.account/ method = %s, want GET", req.Method)
		}
		if req.Header.Get("Authorization") == "" {
			return jsonResponse(req, map[string]any{
				"controls": map[string]any{
					"password": map[string]string{"login": "https://css.example/.account/login"},
				},
			}), nil
		}
		if req.Header.Get("Authorization") != "CSS-Account-Token account-authorization" {
			t.t.Fatalf("/.account/ authorization = %q", req.Header.Get("Authorization"))
		}
		return jsonResponse(req, map[string]any{
			"controls": map[string]any{
				"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"},
			},
		}), nil
	case "/.account/login":
		if req.Method != http.MethodPost {
			t.t.Fatalf("/.account/login method = %s, want POST", req.Method)
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.t.Fatalf("decode login request: %v", err)
		}
		if body["email"] != "my-email@example.com" || body["password"] != "my-password" {
			t.t.Fatalf("login body = %#v", body)
		}
		return jsonResponse(req, map[string]string{"authorization": "account-authorization"}), nil
	case "/.account/client-credentials":
		if req.Method != http.MethodPost {
			t.t.Fatalf("/.account/client-credentials method = %s, want POST", req.Method)
		}
		if req.Header.Get("Authorization") != "CSS-Account-Token account-authorization" {
			t.t.Fatalf("client credentials authorization = %q", req.Header.Get("Authorization"))
		}
		var body map[string]string
		if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
			t.t.Fatalf("decode client credentials request: %v", err)
		}
		if body["name"] != "aggregator" || body["webId"] != "http://localhost:3000/my-pod/card#me" {
			t.t.Fatalf("client credentials body = %#v", body)
		}
		return jsonResponse(req, map[string]string{
			"id":       "token-id",
			"secret":   "token-secret",
			"resource": "https://css.example/.account/client-credentials/token-id",
		}), nil
	case "/.well-known/openid-configuration":
		if req.Method != http.MethodGet {
			t.t.Fatalf("/.well-known/openid-configuration method = %s, want GET", req.Method)
		}
		return jsonResponse(req, map[string]string{"token_endpoint": "https://css.example/.oidc/token"}), nil
	case "/uma/.well-known/uma2-configuration":
		if req.Method != http.MethodGet {
			t.t.Fatalf("/uma/.well-known/uma2-configuration method = %s, want GET", req.Method)
		}
		return jsonResponse(req, map[string]string{"token_endpoint": "https://css.example/.oidc/token"}), nil
	case "/.oidc/token":
		if req.Method != http.MethodPost {
			t.t.Fatalf("/.oidc/token method = %s, want POST", req.Method)
		}
		if strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.t.Fatalf("decode UMA token request: %v", err)
			}
			if body["grant_type"] != "urn:ietf:params:oauth:grant-type:uma-ticket" ||
				body["ticket"] != "source-ticket" ||
				body["scope"] != "urn:knows:uma:scopes:derivation-creation" ||
				body["claim_token"] != "generated-css-access-token" ||
				body["claim_token_format"] != "http://openid.net/specs/openid-connect-core-1_0.html#IDToken" {
				t.t.Fatalf("UMA token request body = %#v", body)
			}
			return jsonResponse(req, map[string]any{
				"access_token": "generated-uma-access-token",
				"expires_in":   3600,
			}), nil
		}
		wantAuth := "Basic " + base64.StdEncoding.EncodeToString([]byte(url.QueryEscape("token-id")+":"+url.QueryEscape("token-secret")))
		if req.Header.Get("Authorization") != wantAuth {
			t.t.Fatalf("token authorization = %q, want %q", req.Header.Get("Authorization"), wantAuth)
		}
		if err := req.ParseForm(); err != nil {
			t.t.Fatalf("parse token form: %v", err)
		}
		if req.Form.Get("grant_type") != "client_credentials" || req.Form.Get("scope") != "webid" {
			t.t.Fatalf("token form = %#v", req.Form)
		}
		return jsonResponse(req, map[string]any{
			"access_token": "generated-css-access-token",
			"expires_in":   3600,
		}), nil
	default:
		t.t.Fatalf("unexpected CSS account request %s %s", req.Method, req.URL.String())
		return nil, nil
	}
}

func jsonResponse(req *http.Request, body any) *http.Response {
	return statusJSONResponse(req, http.StatusOK, body)
}

func statusJSONResponse(req *http.Request, status int, body any) *http.Response {
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return response(req, status, "application/json", "", encoded)
}
