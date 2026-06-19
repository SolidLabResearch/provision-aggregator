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

	fetched, err := server.fetchHTTPSource("service-2", sourceURL)
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
