package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// idTokenExpiry decodes the `exp` claim from a JWT ID token (for example the
// client-credentials token obtained for the Aggregator Instance) and returns it
// as a UTC time. The second return value is false when the token is not a JWT or
// does not carry a usable `exp` claim, in which case callers should fall back to
// a default expiry.
func idTokenExpiry(token string) (time.Time, bool) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return time.Time{}, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return time.Time{}, false
	}
	var claims struct {
		Exp int64 `json:"exp"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Exp == 0 {
		return time.Time{}, false
	}
	return time.Unix(claims.Exp, 0).UTC(), true
}

type accountIndex struct {
	Controls accountControls `json:"controls"`
}

type accountControls struct {
	Password struct {
		Login string `json:"login"`
	} `json:"password"`
	Account struct {
		ClientCredentials string `json:"clientCredentials"`
	} `json:"account"`
}

type accountLoginResponse struct {
	Authorization string `json:"authorization"`
}

type clientCredentialsResponse struct {
	ID       string `json:"id"`
	Secret   string `json:"secret"`
	Resource string `json:"resource"`
}

type oidcConfiguration struct {
	Issuer                       string `json:"issuer"`
	TokenEndpoint                string `json:"token_endpoint"`
	PermissionEndpoint           string `json:"permission_endpoint"`
	IntrospectionEndpoint        string `json:"introspection_endpoint"`
	ResourceRegistrationEndpoint string `json:"resource_registration_endpoint"`
	RegistrationEndpoint         string `json:"registration_endpoint"`
}

type accessTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

type upstreamManagementAccessToken struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
}

type upstreamTokenResponse struct {
	AccessToken           string                         `json:"access_token"`
	TokenType             string                         `json:"token_type"`
	DerivationResourceID  string                         `json:"derivation_resource_id,omitempty"`
	ManagementAccessToken *upstreamManagementAccessToken `json:"management_access_token,omitempty"`
}

type umaTokenRequest struct {
	GrantType            string `json:"grant_type"`
	Ticket               string `json:"ticket"`
	Scope                string `json:"scope"`
	ClaimToken           string `json:"claim_token,omitempty"`
	ClaimTokenFormat     string `json:"claim_token_format,omitempty"`
	DerivationResourceID string `json:"derivation_resource_id,omitempty"`
}

func (c Config) requestAccountAccessToken() (string, error) {
	if !c.hasAccountCredentials() {
		return "", fmt.Errorf("account credentials are not configured")
	}

	accountIndexURL := joinURL(c.AccountServerURL, "/.account/")
	initialIndex, err := c.fetchAccountIndex(accountIndexURL, "")
	if err != nil {
		return "", err
	}
	loginURL, err := resolveURL(accountIndexURL, initialIndex.Controls.Password.Login)
	if err != nil {
		return "", err
	}
	authorization, err := c.loginAccount(loginURL)
	if err != nil {
		return "", err
	}

	authIndex, err := c.fetchAccountIndex(accountIndexURL, "CSS-Account-Token "+authorization)
	if err != nil {
		return "", err
	}
	clientCredentialsURL, err := resolveURL(accountIndexURL, authIndex.Controls.Account.ClientCredentials)
	if err != nil {
		return "", err
	}
	credentials, err := c.createClientCredentials(clientCredentialsURL, authorization)
	if err != nil {
		return "", err
	}

	tokenEndpoint, err := c.discoverTokenEndpoint()
	if err != nil {
		return "", err
	}
	return c.exchangeClientCredentials(tokenEndpoint, credentials)
}

func (c Config) fetchAccountIndex(indexURL, authorization string) (accountIndex, error) {
	req, err := http.NewRequest(http.MethodGet, indexURL, nil)
	if err != nil {
		return accountIndex{}, err
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	var index accountIndex
	if err := c.doJSON(req, http.StatusOK, &index); err != nil {
		return accountIndex{}, err
	}
	return index, nil
}

func (c Config) loginAccount(loginURL string) (string, error) {
	body, err := json.Marshal(map[string]string{
		"email":    c.AccountEmail,
		"password": c.AccountPassword,
	})
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, loginURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	var response accountLoginResponse
	if err := c.doJSON(req, http.StatusOK, &response); err != nil {
		return "", err
	}
	if response.Authorization == "" {
		return "", fmt.Errorf("account login response did not include authorization")
	}
	return response.Authorization, nil
}

func (c Config) createClientCredentials(clientCredentialsURL, authorization string) (clientCredentialsResponse, error) {
	body, err := json.Marshal(map[string]string{
		"name":  "aggregator",
		"webId": c.AccountWebID,
	})
	if err != nil {
		return clientCredentialsResponse{}, err
	}
	req, err := http.NewRequest(http.MethodPost, clientCredentialsURL, bytes.NewReader(body))
	if err != nil {
		return clientCredentialsResponse{}, err
	}
	req.Header.Set("Authorization", "CSS-Account-Token "+authorization)
	req.Header.Set("Content-Type", "application/json")
	var response clientCredentialsResponse
	if err := c.doJSON(req, http.StatusOK, &response); err != nil {
		return clientCredentialsResponse{}, err
	}
	if response.ID == "" || response.Secret == "" {
		return clientCredentialsResponse{}, fmt.Errorf("client credentials response did not include id and secret")
	}
	return response, nil
}

func (c Config) discoverTokenEndpoint() (string, error) {
	discoveryURL := joinURL(c.AccountServerURL, "/.well-known/openid-configuration")
	req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	var config oidcConfiguration
	if err := c.doJSON(req, http.StatusOK, &config); err != nil {
		return "", err
	}
	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("OIDC discovery response did not include token_endpoint")
	}
	return config.TokenEndpoint, nil
}

func (c Config) exchangeClientCredentials(tokenEndpoint string, credentials clientCredentialsResponse) (string, error) {
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", "webid")
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	authString := url.QueryEscape(credentials.ID) + ":" + url.QueryEscape(credentials.Secret)
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(authString)))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	var response accessTokenResponse
	if err := c.doJSON(req, http.StatusOK, &response); err != nil {
		return "", err
	}
	if response.AccessToken == "" {
		return "", fmt.Errorf("token response did not include access_token")
	}
	return response.AccessToken, nil
}

func (c Config) requestUMAAccessToken(asURI, ticket, claimToken, derivationResourceID string) (upstreamTokenResponse, *string, error) {
	tokenEndpoint, err := c.discoverAuthorizationServerTokenEndpoint(asURI)
	if err != nil {
		return upstreamTokenResponse{}, nil, err
	}
	token, nextTicket, jsonErr := c.requestUMAAccessTokenJSON(tokenEndpoint, ticket, claimToken, derivationResourceID)
	if jsonErr == nil {
		return token, nil, nil
	}
	if nextTicket != nil {
		return upstreamTokenResponse{}, nextTicket, jsonErr
	}
	token, nextTicket, formErr := c.requestUMAAccessTokenForm(tokenEndpoint, ticket, claimToken, derivationResourceID)
	if formErr == nil {
		return token, nil, nil
	}
	if nextTicket != nil {
		return upstreamTokenResponse{}, nextTicket, formErr
	}
	return upstreamTokenResponse{}, nil, fmt.Errorf("UMA token request failed using JSON (%v) and form encoding (%v)", jsonErr, formErr)
}

func (c Config) requestUMAAccessTokenJSON(tokenEndpoint, ticket, claimToken, derivationResourceID string) (upstreamTokenResponse, *string, error) {
	body, err := json.Marshal(umaTokenRequest{
		GrantType:            "urn:ietf:params:oauth:grant-type:uma-ticket",
		Ticket:               ticket,
		Scope:                "urn:knows:uma:scopes:derivation-creation",
		ClaimToken:           claimToken,
		ClaimTokenFormat:     "http://openid.net/specs/openid-connect-core-1_0.html#IDToken",
		DerivationResourceID: derivationResourceID,
	})
	if err != nil {
		return upstreamTokenResponse{}, nil, err
	}
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, bytes.NewReader(body))
	if err != nil {
		return upstreamTokenResponse{}, nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	status, responseBody, err := c.doBodyWithStatus(req)
	if err != nil {
		return upstreamTokenResponse{}, nil, err
	}
	if status != http.StatusOK {
		if ticket := needInfoTicket(responseBody); ticket != "" {
			return upstreamTokenResponse{}, &ticket, unexpectedStatusError(req, status, responseBody)
		}
		return upstreamTokenResponse{}, nil, unexpectedStatusError(req, status, responseBody)
	}
	var response upstreamTokenResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return upstreamTokenResponse{}, nil, fmt.Errorf("decode %s response: %w", req.URL.String(), err)
	}
	if response.AccessToken == "" {
		return upstreamTokenResponse{}, nil, fmt.Errorf("UMA token response did not include access_token")
	}
	return response, nil, nil
}

func (c Config) requestUMAAccessTokenForm(tokenEndpoint, ticket, claimToken, derivationResourceID string) (upstreamTokenResponse, *string, error) {
	form := url.Values{}
	form.Set("grant_type", "urn:ietf:params:oauth:grant-type:uma-ticket")
	form.Set("ticket", ticket)
	form.Set("scope", "urn:knows:uma:scopes:derivation-creation")
	if claimToken != "" {
		form.Set("claim_token", claimToken)
		form.Set("claim_token_format", "http://openid.net/specs/openid-connect-core-1_0.html#IDToken")
	}
	if derivationResourceID != "" {
		form.Set("derivation_resource_id", derivationResourceID)
	}
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return upstreamTokenResponse{}, nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, responseBody, err := c.doBodyWithStatus(req)
	if err != nil {
		return upstreamTokenResponse{}, nil, err
	}
	if status != http.StatusOK {
		if ticket := needInfoTicket(responseBody); ticket != "" {
			return upstreamTokenResponse{}, &ticket, unexpectedStatusError(req, status, responseBody)
		}
		return upstreamTokenResponse{}, nil, unexpectedStatusError(req, status, responseBody)
	}
	var response upstreamTokenResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return upstreamTokenResponse{}, nil, fmt.Errorf("decode %s response: %w", req.URL.String(), err)
	}
	if response.AccessToken == "" {
		return upstreamTokenResponse{}, nil, fmt.Errorf("UMA token response did not include access_token")
	}
	return response, nil, nil
}

func needInfoTicket(body []byte) string {
	var response struct {
		Error  string `json:"error"`
		Ticket string `json:"ticket"`
	}
	if err := json.Unmarshal(body, &response); err != nil {
		return ""
	}
	if response.Error != "need_info" || response.Ticket == "" {
		return ""
	}
	return response.Ticket
}

func (c Config) discoverAuthorizationServerTokenEndpoint(asURI string) (string, error) {
	if c.matchesConfiguredAuthorizationServer(asURI) && c.AuthorizationServerTokenEndpoint != "" {
		return c.AuthorizationServerTokenEndpoint, nil
	}
	var lastErr error
	for _, discoveryURL := range authorizationServerMetadataURLs(asURI) {
		tokenEndpoint, err := c.fetchAuthorizationServerTokenEndpoint(asURI, discoveryURL)
		if err == nil {
			return tokenEndpoint, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", fmt.Errorf("authorization server metadata URLs could not be built for %s", asURI)
}

func (c Config) fetchAuthorizationServerTokenEndpoint(asURI, discoveryURL string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}
	var config oidcConfiguration
	if err := c.doJSON(req, http.StatusOK, &config); err != nil {
		return "", err
	}
	config = c.applyAuthorizationServerEndpointOverrides(asURI, config)
	if config.TokenEndpoint == "" {
		return "", fmt.Errorf("authorization server discovery response did not include token_endpoint")
	}
	return config.TokenEndpoint, nil
}

func authorizationServerMetadataURLs(asURI string) []string {
	if strings.Contains(asURI, "/.well-known/") {
		return []string{asURI}
	}
	return []string{
		joinURL(asURI, "/.well-known/uma2-configuration"),
		joinURL(asURI, "/.well-known/openid-configuration"),
	}
}

func (c Config) doJSON(req *http.Request, wantStatus int, target any) error {
	body, err := c.doBody(req, wantStatus)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(body, target); err != nil {
		return fmt.Errorf("decode %s response: %w", req.URL.String(), err)
	}
	return nil
}

func (c Config) doBody(req *http.Request, wantStatus int) ([]byte, error) {
	status, body, err := c.doBodyWithStatus(req)
	if err != nil {
		return nil, err
	}
	if status != wantStatus {
		return nil, unexpectedStatusError(req, status, body)
	}
	return body, nil
}

func (c Config) doBodyWithStatus(req *http.Request) (int, []byte, error) {
	client := c.AccountHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, nil, err
	}
	return resp.StatusCode, body, nil
}

func unexpectedStatusError(req *http.Request, status int, body []byte) error {
	return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(body)))
}

func joinURL(baseURL, path string) string {
	return strings.TrimRight(baseURL, "/") + "/" + strings.TrimLeft(path, "/")
}

func resolveURL(baseURL, ref string) (string, error) {
	if ref == "" {
		return "", fmt.Errorf("missing control URL")
	}
	parsedRef, err := url.Parse(ref)
	if err != nil {
		return "", err
	}
	if parsedRef.IsAbs() {
		return parsedRef.String(), nil
	}
	parsedBase, err := url.Parse(baseURL)
	if err != nil {
		return "", err
	}
	return parsedBase.ResolveReference(parsedRef).String(), nil
}
