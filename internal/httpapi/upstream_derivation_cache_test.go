package httpapi

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
)

func TestUpstreamDerivationResourceIDCacheIsScopedByServiceAndOwner(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://aggregator.example/profile/card#me"

	var tokenRequests []map[string]any
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			tokenRequests = append(tokenRequests, body)
			response := map[string]any{"access_token": "token"}
			if len(tokenRequests) == 1 {
				response["derivation_resource_id"] = "derivation-bob-service-1"
			}
			return testStatusJSONResponse(req, http.StatusOK, response), nil
		default:
			t.Fatalf("unexpected account request %s", req.URL.String())
			return nil, nil
		}
	})}
	cfg.SourceHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodHead {
			t.Fatalf("owner discovery method = %s, want HEAD", req.Method)
		}
		switch req.URL.String() {
		case "https://pods.example/profile/card":
			return testStatusJSONResponse(req, http.StatusNotFound, map[string]string{}), nil
		case "https://pods.example/pods/bob/profile/card", "https://pods.example/pods/alice/profile/card":
			return testStatusJSONResponse(req, http.StatusOK, map[string]string{}), nil
		default:
			t.Fatalf("unexpected source request %s", req.URL.String())
			return nil, nil
		}
	})}

	server := &Server{
		cfg:                      cfg,
		upstreamTokens:           make(map[string]cachedUpstreamToken),
		upstreamOwnerIDs:         make(map[string]string),
		upstreamDerivationIDs:    make(map[string]string),
		upstreamDerivationTokens: make(map[string]upstreamTokenResponse),
		accountAccessToken:       "account-token",
	}

	_, first, err := server.obtainUpstreamRPT("service-1", "https://pods.example/pods/bob/index", "https://uas.example/uma", "ticket-1")
	if err != nil {
		t.Fatalf("first token request: %v", err)
	}
	if first.DerivationResourceID != "derivation-bob-service-1" {
		t.Fatalf("first derivation_resource_id = %q", first.DerivationResourceID)
	}
	_, second, err := server.obtainUpstreamRPT("service-1", "https://pods.example/pods/bob/private/mediaProfile", "https://uas.example/uma", "ticket-2")
	if err != nil {
		t.Fatalf("same-owner token request: %v", err)
	}
	if second.DerivationResourceID != "derivation-bob-service-1" {
		t.Fatalf("same-owner derivation_resource_id = %q, want cached Bob ID", second.DerivationResourceID)
	}
	if tokenRequests[1]["derivation_resource_id"] != "derivation-bob-service-1" {
		t.Fatalf("same-owner token request derivation_resource_id = %#v", tokenRequests[1]["derivation_resource_id"])
	}

	_, _, err = server.obtainUpstreamRPT("service-1", "https://pods.example/pods/alice/private/mediaProfile", "https://uas.example/uma", "ticket-3")
	if err != nil {
		t.Fatalf("different-owner token request: %v", err)
	}
	if _, ok := tokenRequests[2]["derivation_resource_id"]; ok {
		t.Fatalf("different-owner token request reused derivation_resource_id: %#v", tokenRequests[2])
	}

	_, _, err = server.obtainUpstreamRPT("service-2", "https://pods.example/pods/bob/private/mediaProfile", "https://uas.example/uma", "ticket-4")
	if err != nil {
		t.Fatalf("different-service token request: %v", err)
	}
	if _, ok := tokenRequests[3]["derivation_resource_id"]; ok {
		t.Fatalf("different-service token request reused derivation_resource_id: %#v", tokenRequests[3])
	}
}

func TestCachedAccessTokenDoesNotReuseDerivationResponseAcrossServices(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://aggregator.example/profile/card#me"

	sourceURL := "https://pods.example/pods/bob/private/mediaProfile"
	var tokenRequests []map[string]any
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			var body map[string]any
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			tokenRequests = append(tokenRequests, body)
			n := len(tokenRequests)
			return testStatusJSONResponse(req, http.StatusOK, map[string]any{
				"access_token":           fmt.Sprintf("token-%d", n),
				"derivation_resource_id": fmt.Sprintf("derivation-service-%d", n),
				"management_access_token": map[string]any{
					"access_token": fmt.Sprintf("management-%d", n),
					"token_type":   "Bearer",
				},
			}), nil
		default:
			t.Fatalf("unexpected account request %s", req.URL.String())
			return nil, nil
		}
	})}

	var authorizedGETs []string
	cfg.SourceHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch {
		case req.Method == http.MethodHead && req.URL.String() == "https://pods.example/profile/card":
			return testStatusJSONResponse(req, http.StatusNotFound, map[string]string{}), nil
		case req.Method == http.MethodHead && req.URL.String() == "https://pods.example/pods/bob/profile/card":
			return testStatusJSONResponse(req, http.StatusOK, map[string]string{}), nil
		case req.Method == http.MethodGet && req.URL.String() == sourceURL && req.Header.Get("Authorization") == "":
			resp := testStatusJSONResponse(req, http.StatusUnauthorized, map[string]string{})
			resp.Header.Set("WWW-Authenticate", `UMA as_uri="https://uas.example/uma", ticket="source-ticket"`)
			return resp, nil
		case req.Method == http.MethodGet && req.URL.String() == sourceURL:
			authorizedGETs = append(authorizedGETs, req.Header.Get("Authorization"))
			return testStatusJSONResponse(req, http.StatusOK, map[string]string{}), nil
		default:
			t.Fatalf("unexpected source request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	server := &Server{
		cfg:                      cfg,
		upstreamTokens:           make(map[string]cachedUpstreamToken),
		upstreamOwnerIDs:         make(map[string]string),
		upstreamDerivationIDs:    make(map[string]string),
		upstreamDerivationTokens: make(map[string]upstreamTokenResponse),
		accountAccessToken:       "account-token",
	}

	_, first, err := server.obtainUpstreamRPT("service-1", sourceURL, "https://uas.example/uma", "ticket-1")
	if err != nil {
		t.Fatalf("service-1 token request: %v", err)
	}
	if first.DerivationResourceID != "derivation-service-1" {
		t.Fatalf("service-1 derivation_resource_id = %q", first.DerivationResourceID)
	}

	fetched, err := server.fetchHTTPSource("service-2", sourceURL, upstreamAccessRequestAlways)
	if err != nil {
		t.Fatalf("service-2 fetch: %v", err)
	}
	if fetched.UpstreamDerivation.DerivationResourceID != "derivation-service-2" {
		t.Fatalf("service-2 derivation_resource_id = %q, want fresh service-2 ID", fetched.UpstreamDerivation.DerivationResourceID)
	}
	if fetched.UpstreamDerivation.ManagementAccessToken != "management-2" {
		t.Fatalf("service-2 management token = %q, want fresh management token", fetched.UpstreamDerivation.ManagementAccessToken)
	}
	if len(tokenRequests) != 2 {
		t.Fatalf("token requests = %d, want fresh request for service-2", len(tokenRequests))
	}
	if len(authorizedGETs) != 1 || authorizedGETs[0] != "Bearer token-2" {
		t.Fatalf("authorized source GETs = %#v, want only fresh service-2 token", authorizedGETs)
	}
}

func TestPollingProbeDoesNotSubmitRepeatedAccessRequests(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://aggregator.example/profile/card#me"

	sourceURL := "https://pods.example/pods/bob/private/mediaProfile"
	tokenRequests := 0
	accessRequests := 0
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			tokenRequests++
			return testStatusJSONResponse(req, http.StatusForbidden, map[string]string{
				"error":  "need_info",
				"ticket": "need-info-ticket",
			}), nil
		case "https://uas.example/uma/requests":
			accessRequests++
			return testStatusJSONResponse(req, http.StatusAccepted, map[string]string{}), nil
		default:
			t.Fatalf("unexpected account request %s", req.URL.String())
			return nil, nil
		}
	})}
	cfg.SourceHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead && req.URL.String() == sourceURL {
			resp := testStatusJSONResponse(req, http.StatusUnauthorized, map[string]string{})
			resp.Header.Set("WWW-Authenticate", `UMA as_uri="https://uas.example/uma", ticket="source-ticket"`)
			return resp, nil
		}
		t.Fatalf("unexpected source request %s %s", req.Method, req.URL.String())
		return nil, nil
	})}

	server := &Server{
		cfg:                      cfg,
		upstreamTokens:           make(map[string]cachedUpstreamToken),
		upstreamOwnerIDs:         make(map[string]string),
		upstreamDerivationIDs:    make(map[string]string),
		upstreamDerivationTokens: make(map[string]upstreamTokenResponse),
		accountAccessToken:       "account-token",
	}

	if _, _, err := server.obtainUpstreamRPT("", sourceURL, "https://uas.example/uma", "source-ticket"); err == nil {
		t.Fatalf("initial token request error = nil, want access request submission path")
	}
	if accessRequests != 1 {
		t.Fatalf("access requests after initial attempt = %d, want 1", accessRequests)
	}

	for i := 0; i < 2; i++ {
		if server.upstreamSourceAccessible(sourceURL) {
			t.Fatalf("polling probe %d reported source accessible", i+1)
		}
	}
	if accessRequests != 1 {
		t.Fatalf("access requests after polling probes = %d, want still 1", accessRequests)
	}
	if tokenRequests != 3 {
		t.Fatalf("token requests = %d, want initial attempt plus two polling probes", tokenRequests)
	}
}

func TestPollingMaterializationDoesNotSubmitRepeatedAccessRequests(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://aggregator.example/profile/card#me"
	cfg.OxigraphWorkdir = t.TempDir()
	cfg.OutputsDirectory = t.TempDir()

	sourceURL := "https://pods.example/pods/bob/private/mediaProfileIndex"
	tokenRequests := 0
	accessRequests := 0
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			tokenRequests++
			return testStatusJSONResponse(req, http.StatusForbidden, map[string]string{
				"error":  "need_info",
				"ticket": "need-info-ticket",
			}), nil
		case "https://uas.example/uma/requests":
			accessRequests++
			return testStatusJSONResponse(req, http.StatusAccepted, map[string]string{}), nil
		default:
			t.Fatalf("unexpected account request %s", req.URL.String())
			return nil, nil
		}
	})}
	cfg.SourceHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.Method == http.MethodHead && req.URL.String() == "https://pods.example/profile/card" {
			return testStatusJSONResponse(req, http.StatusNotFound, map[string]string{}), nil
		}
		if req.Method == http.MethodHead && req.URL.String() == "https://pods.example/pods/bob/profile/card" {
			return testStatusJSONResponse(req, http.StatusOK, map[string]string{}), nil
		}
		if req.Method == http.MethodGet && req.URL.String() == sourceURL {
			resp := testStatusJSONResponse(req, http.StatusUnauthorized, map[string]string{})
			resp.Header.Set("WWW-Authenticate", `UMA as_uri="https://uas.example/uma", ticket="source-ticket"`)
			return resp, nil
		}
		t.Fatalf("unexpected source request %s %s", req.Method, req.URL.String())
		return nil, nil
	})}

	server := &Server{
		cfg:                      cfg,
		upstreamTokens:           make(map[string]cachedUpstreamToken),
		upstreamOwnerIDs:         make(map[string]string),
		upstreamDerivationIDs:    make(map[string]string),
		upstreamDerivationTokens: make(map[string]upstreamTokenResponse),
		accountAccessToken:       "account-token",
	}
	req := createServiceRequest{SourceURLs: []string{sourceURL}}

	if _, err := server.materialize("service-1", req, "SELECT"); !isInsufficientUpstreamResources(err) {
		t.Fatalf("initial materialize error = %v, want insufficient upstream resources", err)
	}
	if accessRequests != 1 {
		t.Fatalf("access requests after initial materialize = %d, want 1", accessRequests)
	}
	if _, err := server.materializeWithMissingAccessRequests("service-1", req, "SELECT"); !isInsufficientUpstreamResources(err) {
		t.Fatalf("polling materialize error = %v, want insufficient upstream resources", err)
	}
	if accessRequests != 1 {
		t.Fatalf("access requests after polling materialize = %d, want still 1", accessRequests)
	}
	if tokenRequests != 2 {
		t.Fatalf("token requests = %d, want initial and polling token attempts", tokenRequests)
	}
}

func TestMissingAccessRequestPolicySubmitsForNewlyDiscoveredResources(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://aggregator.example/profile/card#me"

	indexURL := "https://pods.example/pods/bob/private/mediaProfileIndex"
	profileURL := "https://pods.example/pods/bob/private/mediaProfile"
	var accessRequestTickets []string
	cfg.AccountHTTPClient = &http.Client{Transport: testRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return testJSONResponse(req, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode token request: %v", err)
			}
			return testStatusJSONResponse(req, http.StatusForbidden, map[string]string{
				"error":  "need_info",
				"ticket": "need-info-" + body["ticket"],
			}), nil
		case "https://uas.example/uma/requests":
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode access request: %v", err)
			}
			accessRequestTickets = append(accessRequestTickets, body["ticket"])
			return testStatusJSONResponse(req, http.StatusAccepted, map[string]string{}), nil
		default:
			t.Fatalf("unexpected account request %s", req.URL.String())
			return nil, nil
		}
	})}

	server := &Server{
		cfg:                      cfg,
		upstreamTokens:           make(map[string]cachedUpstreamToken),
		upstreamOwnerIDs:         make(map[string]string),
		upstreamDerivationIDs:    make(map[string]string),
		upstreamDerivationTokens: make(map[string]upstreamTokenResponse),
		accountAccessToken:       "account-token",
	}

	if _, _, err := server.obtainUpstreamRPT("", indexURL, "https://uas.example/uma", "index-ticket"); err == nil {
		t.Fatalf("initial index token request error = nil, want access request submission path")
	}
	if _, _, err := server.obtainUpstreamRPTWithAccessRequestPolicy("", indexURL, "https://uas.example/uma", "index-ticket-2", upstreamAccessRequestIfMissing); err == nil {
		t.Fatalf("polling index token request error = nil, want no access token yet")
	}
	if _, _, err := server.obtainUpstreamRPTWithAccessRequestPolicy("", profileURL, "https://uas.example/uma", "profile-ticket", upstreamAccessRequestIfMissing); err == nil {
		t.Fatalf("polling profile token request error = nil, want access request submission path")
	}

	want := []string{"need-info-index-ticket", "need-info-profile-ticket"}
	if len(accessRequestTickets) != len(want) {
		t.Fatalf("access request tickets = %#v, want %#v", accessRequestTickets, want)
	}
	for i := range want {
		if accessRequestTickets[i] != want[i] {
			t.Fatalf("access request tickets = %#v, want %#v", accessRequestTickets, want)
		}
	}
}
