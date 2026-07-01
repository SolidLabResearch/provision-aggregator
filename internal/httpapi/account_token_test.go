package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestUMAAccessTokenRequestIncludesDerivationResourceID(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountHTTPClient = &http.Client{Transport: accountTokenRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			if req.Header.Get("Content-Type") != "application/json" {
				t.Fatalf("content-type = %q, want application/json", req.Header.Get("Content-Type"))
			}
			var body map[string]string
			if err := json.NewDecoder(req.Body).Decode(&body); err != nil {
				t.Fatalf("decode UMA token body: %v", err)
			}
			if body["derivation_resource_id"] != "derivation-resource-previous" {
				t.Fatalf("derivation_resource_id = %q, want previous ID", body["derivation_resource_id"])
			}
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{
				"access_token":           "new-upstream-token",
				"token_type":             "Bearer",
				"derivation_resource_id": "derivation-resource-previous",
			}), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	token, nextTicket, err := cfg.requestUMAAccessToken("https://uas.example/uma", "ticket", "claim-token", "derivation-resource-previous")
	if err != nil {
		t.Fatalf("requestUMAAccessToken: %v", err)
	}
	if nextTicket != nil {
		t.Fatalf("next ticket = %q, want nil when token is issued", *nextTicket)
	}
	if token.AccessToken != "new-upstream-token" {
		t.Fatalf("access token = %q, want new-upstream-token", token.AccessToken)
	}
}

func TestUMAAccessTokenNeedInfoReturnsTicket(t *testing.T) {
	cfg := DefaultConfig("https://aggregator.example")
	tokenRequests := 0
	cfg.AccountHTTPClient = &http.Client{Transport: accountTokenRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://uas.example/uma/.well-known/uma2-configuration":
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{"token_endpoint": "https://uas.example/uma/token"}), nil
		case "https://uas.example/uma/token":
			tokenRequests++
			return accountTokenJSONResponse(req, http.StatusForbidden, map[string]any{
				"error":  "need_info",
				"ticket": "need-info-ticket",
				"required_claims": map[string]any{
					"claim_token_format": [][]string{{}},
				},
			}), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	_, nextTicket, err := cfg.requestUMAAccessToken("https://uas.example/uma", "resource-server-ticket", "claim-token", "")
	if err == nil {
		t.Fatalf("requestUMAAccessToken error = nil, want need_info failure")
	}
	if nextTicket == nil {
		t.Fatalf("next ticket = nil, want AS-issued ticket")
	}
	if *nextTicket != "need-info-ticket" {
		t.Fatalf("next ticket = %q, want AS-issued ticket", *nextTicket)
	}
	if tokenRequests != 1 {
		t.Fatalf("token requests = %d, want no form retry after need_info", tokenRequests)
	}
}

func TestAggregatorTokenExpiryComesFromIDToken(t *testing.T) {
	expectedExpiry := time.Now().Add(37 * time.Minute).UTC().Truncate(time.Second)
	cfg := DefaultConfig("https://aggregator.example")
	cfg.AccountServerURL = "https://css.example"
	cfg.AccountEmail = "alice@example.com"
	cfg.AccountPassword = "password"
	cfg.AccountWebID = "https://pod.example/alice#me"
	cfg.AccountHTTPClient = &http.Client{Transport: accountTokenRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		switch req.URL.String() {
		case "https://css.example/.account/":
			if req.Header.Get("Authorization") == "" {
				return accountTokenJSONResponse(req, http.StatusOK, map[string]any{
					"controls": map[string]any{"password": map[string]string{"login": "https://css.example/.account/login"}},
				}), nil
			}
			return accountTokenJSONResponse(req, http.StatusOK, map[string]any{
				"controls": map[string]any{"account": map[string]string{"clientCredentials": "https://css.example/.account/client-credentials"}},
			}), nil
		case "https://css.example/.account/login":
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{"authorization": "account-authorization"}), nil
		case "https://css.example/.account/client-credentials":
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{"id": "css-client", "secret": "css-secret"}), nil
		case "https://css.example/.well-known/openid-configuration":
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{"token_endpoint": "https://css.example/token"}), nil
		case "https://css.example/token":
			return accountTokenJSONResponse(req, http.StatusOK, map[string]string{"access_token": testIDToken(expectedExpiry)}), nil
		default:
			t.Fatalf("unexpected request %s %s", req.Method, req.URL.String())
			return nil, nil
		}
	})}

	server := NewServer(cfg)
	if server.accountTokenError != nil {
		t.Fatalf("account token error: %v", server.accountTokenError)
	}
	agg, err := server.createAggregator("owner-token")
	if err != nil {
		t.Fatalf("createAggregator: %v", err)
	}
	if !agg.TokenExpiry.Equal(expectedExpiry) {
		t.Fatalf("TokenExpiry = %s, want %s (from ID token exp)", agg.TokenExpiry, expectedExpiry)
	}
}

// testIDToken builds a minimal unsigned JWT whose payload only carries the
// `exp` claim, used to verify the Aggregator Instance token expiry is derived
// from the ID token.
func testIDToken(exp time.Time) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payloadJSON, err := json.Marshal(map[string]any{"exp": exp.Unix()})
	if err != nil {
		panic(err)
	}
	payload := base64.RawURLEncoding.EncodeToString(payloadJSON)
	return header + "." + payload + ".signature"
}

type accountTokenRoundTripFunc func(*http.Request) (*http.Response, error)

func (f accountTokenRoundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
}

func accountTokenJSONResponse(req *http.Request, status int, body any) *http.Response {
	encoded, err := json.Marshal(body)
	if err != nil {
		panic(err)
	}
	return &http.Response{
		StatusCode: status,
		Status:     http.StatusText(status),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
		Body:       io.NopCloser(strings.NewReader(string(encoded))),
		Request:    req,
	}
}
