package httpapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
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

	token, err := cfg.requestUMAAccessToken("https://uas.example/uma", "ticket", "claim-token", "derivation-resource-previous")
	if err != nil {
		t.Fatalf("requestUMAAccessToken: %v", err)
	}
	if token.AccessToken != "new-upstream-token" {
		t.Fatalf("access token = %q, want new-upstream-token", token.AccessToken)
	}
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
