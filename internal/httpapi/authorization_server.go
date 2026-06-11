package httpapi

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const protectionAPIScope = "uma_protection"

const (
	scopeRead   = "urn:example:css:modes:read"
	scopeAppend = "urn:example:css:modes:append"
	scopeCreate = "urn:example:css:modes:create"
	scopeDelete = "urn:example:css:modes:delete"
	scopeWrite  = "urn:example:css:modes:write"
)

type authorizationServerClient struct {
	ClientID     string
	ClientSecret string
}

type protectionToken struct {
	Authorization string
	ExpiresAt     time.Time
}

type authorizationServerClientResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type authorizationServerRegisteredClient struct {
	ID  string `json:"id"`
	URI string `json:"uri"`
}

type protectionTokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   int    `json:"expires_in"`
}

type permissionDescription struct {
	ResourceID     string   `json:"resource_id"`
	ResourceScopes []string `json:"resource_scopes"`
}

type permissionTicketResponse struct {
	Ticket string `json:"ticket"`
}

type resourceRegistrationResponse struct {
	ID string `json:"_id"`
}

type introspectionResponse struct {
	Active      bool                    `json:"active"`
	Permissions []permissionDescription `json:"permissions"`
}

type resourceDescriptionDocument struct {
	Name             string              `json:"name"`
	ResourceScopes   []string            `json:"resource_scopes"`
	Type             string              `json:"type,omitempty"`
	Description      string              `json:"description,omitempty"`
	DerivedFrom      []Derivation        `json:"derived_from,omitempty"`
	ResourceDefaults map[string][]string `json:"resource_defaults,omitempty"`
}

type derivationResourceDescriptionDocument struct {
	Type           string   `json:"type"`
	Name           string   `json:"name"`
	Description    string   `json:"description,omitempty"`
	IconURI        string   `json:"icon_uri,omitempty"`
	ResourceScopes []string `json:"resource_scopes"`
}

func (s *Server) shouldUseLiveAuthorizationServer() bool {
	return s.cfg.hasAccountCredentials() && s.cfg.AuthorizationServerURL != ""
}

func (s *Server) authorizationServerMetadataAndPAT() (oidcConfiguration, string, error) {
	if s.accountTokenError != nil {
		return oidcConfiguration{}, "", s.accountTokenError
	}
	if s.authorizationServerError != nil {
		return oidcConfiguration{}, "", s.authorizationServerError
	}
	metadata, err := s.cfg.discoverAuthorizationServerMetadata(s.cfg.authorizationServerURL())
	if err != nil {
		return oidcConfiguration{}, "", err
	}
	pat, err := s.protectionAPIAuthorization(metadata)
	if err != nil {
		return oidcConfiguration{}, "", err
	}
	return metadata, pat, nil
}

func (s *Server) registerConfiguredAuthorizationResource(resourceID string, scopes []string, kind string) error {
	if !s.shouldUseLiveAuthorizationServer() {
		return nil
	}
	metadata, pat, err := s.authorizationServerMetadataAndPAT()
	if err != nil {
		return err
	}
	authorizationResourceID, err := s.registerLiveAuthorizationResource(metadata, pat, resourceID, scopes, kind)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.authorizationResourceIDs[resourceID] = authorizationResourceID
	s.mu.Unlock()
	if err := s.syncConfiguredAuthorizationPolicies(); err != nil {
		return err
	}
	return nil
}

func (s *Server) updateConfiguredAuthorizationResource(resourceID string, scopes []string, kind string, derivedFrom []Derivation) error {
	if !s.shouldUseLiveAuthorizationServer() {
		return nil
	}
	s.mu.Lock()
	authorizationResourceID := s.authorizationResourceIDs[resourceID]
	s.mu.Unlock()
	if authorizationResourceID == "" {
		return fmt.Errorf("authorization resource %s is not registered", resourceID)
	}
	metadata, pat, err := s.authorizationServerMetadataAndPAT()
	if err != nil {
		return err
	}
	return s.putLiveAuthorizationResource(metadata, pat, authorizationResourceID, resourceID, scopes, kind, derivedFrom)
}

func (s *Server) deleteConfiguredAuthorizationResource(resourceID string) error {
	if !s.shouldUseLiveAuthorizationServer() {
		return nil
	}
	s.mu.Lock()
	authorizationResourceID := s.authorizationResourceIDs[resourceID]
	s.mu.Unlock()
	if authorizationResourceID == "" {
		return nil
	}
	metadata, pat, err := s.authorizationServerMetadataAndPAT()
	if err != nil {
		return err
	}
	if err := s.deleteLiveAuthorizationResource(metadata, pat, authorizationResourceID); err != nil {
		return err
	}
	s.mu.Lock()
	delete(s.authorizationResourceIDs, resourceID)
	s.mu.Unlock()
	return nil
}

func (s *Server) deleteAuthorizationServerClientRegistration() error {
	if !s.shouldUseLiveAuthorizationServer() {
		return nil
	}
	s.mu.Lock()
	client := s.authorizationServerClient
	s.mu.Unlock()
	if client.ClientID == "" {
		return nil
	}
	metadata, err := s.cfg.discoverAuthorizationServerMetadata(s.cfg.authorizationServerURL())
	if err != nil {
		return err
	}
	if metadata.RegistrationEndpoint == "" {
		return fmt.Errorf("authorization server metadata did not include registration_endpoint")
	}
	webID := s.cfg.provisionSubject()
	if webID == "" {
		return fmt.Errorf("cannot delete authorization server client without a WebID")
	}
	req, err := http.NewRequest(http.MethodDelete, authorizationServerClientRegistrationURL(metadata.RegistrationEndpoint, client.ClientID), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "WebID "+url.QueryEscape(webID))
	req.Header.Set("Accept", "application/json")
	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}
	if status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	s.mu.Lock()
	s.authorizationServerClient = authorizationServerClient{}
	s.protectionToken = protectionToken{}
	s.mu.Unlock()
	return nil
}

func (s *Server) requestLivePermission(resourceID string, scopes []string) (string, error) {
	log.Printf("httpapi: requesting live permission for %s with scopes %v", resourceID, scopes)
	metadata, pat, err := s.authorizationServerMetadataAndPAT()
	if err != nil {
		log.Printf("httpapi: live permission setup failed for %s: %v", resourceID, err)
		return "", err
	}
	authorizationResourceID := s.authorizationResourceID(resourceID)
	return s.createLivePermissionTicket(metadata.PermissionEndpoint, pat, []permissionDescription{{
		ResourceID:     authorizationResourceID,
		ResourceScopes: append([]string(nil), scopes...),
	}})
}

func (s *Server) protectionAPIAuthorization(metadata oidcConfiguration) (string, error) {
	s.mu.Lock()
	cached := s.protectionToken
	if cached.Authorization != "" && cached.ExpiresAt.After(time.Now().Add(5*time.Second)) {
		s.mu.Unlock()
		log.Printf("httpapi: reusing cached protection token expiring at %s", cached.ExpiresAt.Format(time.RFC3339))
		return cached.Authorization, nil
	}
	client := s.authorizationServerClient
	s.mu.Unlock()

	if client.ClientID == "" || client.ClientSecret == "" {
		var err error
		log.Printf("httpapi: registering authorization-server client for protection API access")
		client, err = s.registerAuthorizationServerClient(metadata)
		if err != nil {
			log.Printf("httpapi: authorization-server client registration failed: %v", err)
			return "", err
		}
		s.mu.Lock()
		s.authorizationServerClient = client
		s.mu.Unlock()
	}

	log.Printf("httpapi: requesting protection token from %s", metadata.TokenEndpoint)
	pat, err := s.requestProtectionToken(metadata.TokenEndpoint, client)
	if err != nil {
		log.Printf("httpapi: protection token request failed: %v", err)
		return "", err
	}
	s.mu.Lock()
	s.protectionToken = pat
	s.mu.Unlock()
	return pat.Authorization, nil
}

func (s *Server) registerAuthorizationServerClient(metadata oidcConfiguration) (authorizationServerClient, error) {
	if metadata.RegistrationEndpoint == "" {
		log.Printf("httpapi: cannot register authorization-server client: metadata missing registration_endpoint")
		return authorizationServerClient{}, fmt.Errorf("authorization server metadata did not include registration_endpoint")
	}
	webID := s.cfg.provisionSubject()
	if webID == "" {
		log.Printf("httpapi: cannot register authorization-server client: missing WebID")
		return authorizationServerClient{}, fmt.Errorf("cannot register authorization server client without a WebID")
	}
	log.Printf("httpapi: registering authorization-server client at %s for %s", metadata.RegistrationEndpoint, webID)
	body, err := json.Marshal(map[string]string{
		"client_uri": s.cfg.BaseURL,
	})
	if err != nil {
		return authorizationServerClient{}, err
	}
	req, err := http.NewRequest(http.MethodPost, metadata.RegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return authorizationServerClient{}, err
	}
	req.Header.Set("Authorization", "WebID "+url.QueryEscape(webID))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	response, err := s.doAuthorizationServerClientRegistration(req)
	if err != nil {
		log.Printf("httpapi: authorization-server client registration request failed: %v", err)
		return authorizationServerClient{}, err
	}
	if response.ClientID == "" || response.ClientSecret == "" {
		log.Printf("httpapi: authorization-server client registration response missing credentials")
		return authorizationServerClient{}, fmt.Errorf("authorization server client registration did not return client_id and client_secret")
	}
	return authorizationServerClient{
		ClientID:     response.ClientID,
		ClientSecret: response.ClientSecret,
	}, nil
}

func (s *Server) doAuthorizationServerClientRegistration(req *http.Request) (authorizationServerClientResponse, error) {
	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return authorizationServerClientResponse{}, err
	}
	if status == http.StatusConflict {
		if err := s.deleteExistingAuthorizationServerClientRegistration(req); err != nil {
			return authorizationServerClientResponse{}, err
		}
		retry := req.Clone(req.Context())
		body, err := json.Marshal(map[string]string{
			"client_uri": s.cfg.BaseURL,
		})
		if err != nil {
			return authorizationServerClientResponse{}, err
		}
		retry.Body = io.NopCloser(bytes.NewReader(body))
		status, responseBody, err = s.doAuthorizationServer(retry)
		if err != nil {
			return authorizationServerClientResponse{}, err
		}
	}
	if status != http.StatusCreated {
		return authorizationServerClientResponse{}, fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	var response authorizationServerClientResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return authorizationServerClientResponse{}, fmt.Errorf("decode %s response: %w", req.URL.String(), err)
	}
	return response, nil
}

func (s *Server) deleteExistingAuthorizationServerClientRegistration(original *http.Request) error {
	req, err := http.NewRequest(http.MethodGet, original.URL.String(), nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", original.Header.Get("Authorization"))
	req.Header.Set("Accept", "application/json")

	var clients []authorizationServerRegisteredClient
	if err := s.doAuthorizationServerJSON(req, http.StatusOK, &clients); err != nil {
		return err
	}
	for _, client := range clients {
		if client.URI == s.cfg.BaseURL && client.ID != "" {
			deleteReq, err := http.NewRequest(http.MethodDelete, authorizationServerClientRegistrationURL(original.URL.String(), client.ID), nil)
			if err != nil {
				return err
			}
			deleteReq.Header.Set("Authorization", original.Header.Get("Authorization"))
			deleteReq.Header.Set("Accept", "application/json")
			status, responseBody, err := s.doAuthorizationServer(deleteReq)
			if err != nil {
				return err
			}
			if status != http.StatusNoContent && status != http.StatusNotFound {
				return fmt.Errorf("%s %s returned %d: %s", deleteReq.Method, deleteReq.URL.String(), status, strings.TrimSpace(string(responseBody)))
			}
			return nil
		}
	}
	return fmt.Errorf("authorization server reported existing client registration for %s, but it was not returned by GET %s", s.cfg.BaseURL, original.URL.String())
}

func authorizationServerClientRegistrationURL(registrationEndpoint, clientID string) string {
	return strings.TrimRight(registrationEndpoint, "/") + "/" + url.PathEscape(clientID)
}

func (s *Server) requestProtectionToken(tokenEndpoint string, client authorizationServerClient) (protectionToken, error) {
	if tokenEndpoint == "" {
		log.Printf("httpapi: cannot request protection token: metadata missing token_endpoint")
		return protectionToken{}, fmt.Errorf("authorization server metadata did not include token_endpoint")
	}
	log.Printf("httpapi: POST protection token request to %s using client %s", tokenEndpoint, client.ClientID)
	form := url.Values{}
	form.Set("grant_type", "client_credentials")
	form.Set("scope", protectionAPIScope)
	req, err := http.NewRequest(http.MethodPost, tokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return protectionToken{}, err
	}
	req.Header.Set("Authorization", basicAuthorization(client.ClientID, client.ClientSecret))
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	var response protectionTokenResponse
	if err := s.doAuthorizationServerJSONEither(req, []int{http.StatusOK, http.StatusCreated}, &response); err != nil {
		return protectionToken{}, err
	}
	if response.AccessToken == "" || response.TokenType == "" {
		log.Printf("httpapi: protection token response missing access_token or token_type")
		return protectionToken{}, fmt.Errorf("PAT response did not include access_token and token_type")
	}
	expiresAt := time.Now().Add(time.Hour)
	if response.ExpiresIn > 0 {
		expiresAt = time.Now().Add(time.Duration(response.ExpiresIn) * time.Second)
	}
	return protectionToken{
		Authorization: response.TokenType + " " + response.AccessToken,
		ExpiresAt:     expiresAt,
	}, nil
}

func (s *Server) registerLiveAuthorizationResource(metadata oidcConfiguration, pat, resourceID string, scopes []string, kind string) (string, error) {
	if metadata.ResourceRegistrationEndpoint == "" {
		return "", fmt.Errorf("authorization server metadata did not include resource_registration_endpoint")
	}
	body, err := json.Marshal(resourceDescriptionDocument{
		Name:           resourceID,
		ResourceScopes: append([]string(nil), scopes...),
		Type:           resourceTypeForKind(kind),
		Description:    resourceDescriptionForKind(kind),
	})
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest(http.MethodPost, metadata.ResourceRegistrationEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	setProtectionAPIHeaders(req, pat)
	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return "", err
	}
	if status == http.StatusCreated {
		var response resourceRegistrationResponse
		if err := json.Unmarshal(responseBody, &response); err != nil {
			return "", fmt.Errorf("decode %s response: %w", req.URL.String(), err)
		}
		if response.ID == "" {
			return "", fmt.Errorf("resource registration response did not include _id")
		}
		return response.ID, nil
	}
	if status != http.StatusConflict {
		return "", fmt.Errorf("resource registration POST %s returned %d: %s", metadata.ResourceRegistrationEndpoint, status, strings.TrimSpace(string(responseBody)))
	}

	authorizationResourceID := s.authorizationResourceID(resourceID)
	updateURL := strings.TrimRight(metadata.ResourceRegistrationEndpoint, "/") + "/" + url.PathEscape(authorizationResourceID)
	updateReq, err := http.NewRequest(http.MethodPut, updateURL, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	setProtectionAPIHeaders(updateReq, pat)
	status, responseBody, err = s.doAuthorizationServer(updateReq)
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("resource registration PUT %s returned %d: %s", updateURL, status, strings.TrimSpace(string(responseBody)))
	}
	return authorizationResourceID, nil
}

func (s *Server) putLiveAuthorizationResource(metadata oidcConfiguration, pat, authorizationResourceID, resourceID string, scopes []string, kind string, derivedFrom []Derivation) error {
	if metadata.ResourceRegistrationEndpoint == "" {
		return fmt.Errorf("authorization server metadata did not include resource_registration_endpoint")
	}
	body, err := json.Marshal(resourceDescriptionDocument{
		Name:           resourceID,
		ResourceScopes: append([]string(nil), scopes...),
		Type:           resourceTypeForKind(kind),
		Description:    resourceDescriptionForKind(kind),
		DerivedFrom:    cloneDerivations(derivedFrom),
	})
	if err != nil {
		return err
	}
	updateURL := strings.TrimRight(metadata.ResourceRegistrationEndpoint, "/") + "/" + url.PathEscape(authorizationResourceID)
	req, err := http.NewRequest(http.MethodPut, updateURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	setProtectionAPIHeaders(req, pat)

	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}

	if status != http.StatusOK {
		return fmt.Errorf("resource registration PUT %s returned %d: %s", updateURL, status, strings.TrimSpace(string(responseBody)))
	}

	return nil
}

func (s *Server) deleteLiveAuthorizationResource(metadata oidcConfiguration, pat, authorizationResourceID string) error {
	if metadata.ResourceRegistrationEndpoint == "" {
		return fmt.Errorf("authorization server metadata did not include resource_registration_endpoint")
	}
	deleteURL := strings.TrimRight(metadata.ResourceRegistrationEndpoint, "/") + "/" + url.PathEscape(authorizationResourceID)
	req, err := http.NewRequest(http.MethodDelete, deleteURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", pat)
	req.Header.Set("Accept", "application/json")
	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("resource registration DELETE %s returned %d: %s", deleteURL, status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (s *Server) createLivePermissionTicket(permissionEndpoint, pat string, permissions []permissionDescription) (string, error) {
	if permissionEndpoint == "" {
		return "", fmt.Errorf("authorization server metadata did not include permission_endpoint")
	}
	body, err := json.Marshal(permissions)
	if err != nil {
		return "", err
	}
	req, err := http.NewRequest(http.MethodPost, permissionEndpoint, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	setProtectionAPIHeaders(req, pat)

	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return "", err
	}
	if status == http.StatusOK {
		return "", nil
	}
	if status != http.StatusCreated {
		return "", fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	var response permissionTicketResponse
	if err := json.Unmarshal(responseBody, &response); err != nil {
		return "", fmt.Errorf("decode %s response: %w", req.URL.String(), err)
	}
	if response.Ticket == "" {
		return "", fmt.Errorf("permission ticket response did not include ticket")
	}
	return response.Ticket, nil
}

func (s *Server) liveRPTIsValid(token, resourceID string, requiredScopes []string) (bool, error) {
	metadata, pat, err := s.authorizationServerMetadataAndPAT()
	if err != nil {
		return false, err
	}
	if metadata.IntrospectionEndpoint == "" {
		return false, fmt.Errorf("authorization server metadata did not include introspection_endpoint")
	}

	form := url.Values{}
	form.Set("token", token)
	req, err := http.NewRequest(http.MethodPost, metadata.IntrospectionEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", pat)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	status, body, err := s.doAuthorizationServer(req)
	if err != nil {
		return false, err
	}
	if status != http.StatusOK {
		return false, nil
	}
	var response introspectionResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return false, fmt.Errorf("decode %s response: %w", req.URL.String(), err)
	}
	if !response.Active {
		return false, nil
	}
	authorizationResourceID := s.authorizationResourceID(resourceID)
	for _, permission := range response.Permissions {
		if permission.ResourceID == authorizationResourceID && containsAllStrings(permission.ResourceScopes, requiredScopes) {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) authorizationResourceID(resourceID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if authorizationResourceID := s.authorizationResourceIDs[resourceID]; authorizationResourceID != "" {
		return authorizationResourceID
	}
	return resourceID
}

func (c Config) discoverAuthorizationServerMetadata(asURI string) (oidcConfiguration, error) {
	if metadata := c.configuredAuthorizationServerMetadata(asURI); metadata.hasCoreAuthorizationServerEndpoints() {
		return metadata, nil
	}
	var lastErr error
	for _, discoveryURL := range authorizationServerMetadataURLs(asURI) {
		req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
		if err != nil {
			return oidcConfiguration{}, err
		}
		req.Header.Set("Accept", "application/json")
		var metadata oidcConfiguration
		if err := c.doJSON(req, http.StatusOK, &metadata); err != nil {
			lastErr = err
			continue
		}
		metadata = c.applyAuthorizationServerEndpointOverrides(asURI, metadata)
		if metadata.TokenEndpoint == "" {
			lastErr = fmt.Errorf("authorization server discovery response did not include token_endpoint")
			continue
		}
		return metadata, nil
	}
	if metadata := c.configuredAuthorizationServerMetadata(asURI); metadata.TokenEndpoint != "" {
		return metadata, nil
	}
	if lastErr != nil {
		return oidcConfiguration{}, lastErr
	}
	return oidcConfiguration{}, fmt.Errorf("authorization server metadata URLs could not be built for %s", asURI)
}

func (c Config) configuredAuthorizationServerMetadata(asURI string) oidcConfiguration {
	if !c.matchesConfiguredAuthorizationServer(asURI) {
		return oidcConfiguration{}
	}
	return oidcConfiguration{
		Issuer:                       c.authorizationServerURL(),
		TokenEndpoint:                c.AuthorizationServerTokenEndpoint,
		PermissionEndpoint:           c.AuthorizationServerPermissionEndpoint,
		IntrospectionEndpoint:        c.AuthorizationServerIntrospectionEndpoint,
		ResourceRegistrationEndpoint: c.AuthorizationServerResourceRegistrationEndpoint,
		RegistrationEndpoint:         c.AuthorizationServerRegistrationEndpoint,
	}
}

func (c Config) applyAuthorizationServerEndpointOverrides(asURI string, metadata oidcConfiguration) oidcConfiguration {
	overrides := c.configuredAuthorizationServerMetadata(asURI)
	if overrides.Issuer != "" {
		metadata.Issuer = overrides.Issuer
	}
	if overrides.TokenEndpoint != "" {
		metadata.TokenEndpoint = overrides.TokenEndpoint
	}
	if overrides.PermissionEndpoint != "" {
		metadata.PermissionEndpoint = overrides.PermissionEndpoint
	}
	if overrides.IntrospectionEndpoint != "" {
		metadata.IntrospectionEndpoint = overrides.IntrospectionEndpoint
	}
	if overrides.ResourceRegistrationEndpoint != "" {
		metadata.ResourceRegistrationEndpoint = overrides.ResourceRegistrationEndpoint
	}
	if overrides.RegistrationEndpoint != "" {
		metadata.RegistrationEndpoint = overrides.RegistrationEndpoint
	}
	return metadata
}

func (c Config) matchesConfiguredAuthorizationServer(asURI string) bool {
	configured := c.authorizationServerURL()
	if configured == "" || asURI == "" {
		return false
	}
	return strings.TrimRight(configured, "/") == strings.TrimRight(asURI, "/")
}

func (m oidcConfiguration) hasCoreAuthorizationServerEndpoints() bool {
	return m.TokenEndpoint != "" &&
		m.PermissionEndpoint != "" &&
		m.IntrospectionEndpoint != "" &&
		m.ResourceRegistrationEndpoint != "" &&
		m.RegistrationEndpoint != ""
}

func (s *Server) doAuthorizationServerJSON(req *http.Request, wantStatus int, target any) error {
	return s.doAuthorizationServerJSONEither(req, []int{wantStatus}, target)
}

func (s *Server) doAuthorizationServerJSONEither(req *http.Request, wantStatuses []int, target any) error {
	status, body, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}
	for _, wantStatus := range wantStatuses {
		if status == wantStatus {
			if err := json.Unmarshal(body, target); err != nil {
				return fmt.Errorf("decode %s response: %w", req.URL.String(), err)
			}
			return nil
		}
	}
	log.Printf("httpapi: unexpected AS status for %s %s: %d", req.Method, req.URL.String(), status)
	return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(body)))
}

func (s *Server) doAuthorizationServer(req *http.Request) (int, []byte, error) {
	client := s.cfg.AccountHTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	log.Printf("httpapi: sending AS request %s %s", req.Method, req.URL.String())
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("httpapi: AS request error for %s %s: %v", req.Method, req.URL.String(), err)
		return 0, nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("httpapi: reading AS response failed for %s %s: %v", req.Method, req.URL.String(), err)
		return 0, nil, err
	}
	log.Printf("httpapi: AS response %s %s -> %d", req.Method, req.URL.String(), resp.StatusCode)
	return resp.StatusCode, body, nil
}

func setProtectionAPIHeaders(req *http.Request, pat string) {
	req.Header.Set("Authorization", pat)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
}

func basicAuthorization(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

func resourceTypeForKind(kind string) string {
	switch kind {
	case "service_output":
		return "http://www.w3.org/ns/dcat#Distribution"
	case "service_description":
		return "https://w3id.org/aggregator#Service"
	case "service_collection":
		return "https://w3id.org/aggregator#ServiceCollection"
	default:
		return "https://w3id.org/aggregator#Resource"
	}
}

func resourceDescriptionForKind(kind string) string {
	switch kind {
	case "service_output":
		return "Aggregator service output resource."
	case "service_description":
		return "Aggregator service description resource."
	case "service_collection":
		return "Aggregator service collection resource."
	default:
		return "Aggregator resource."
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsAllStrings(values []string, targets []string) bool {
	for _, target := range targets {
		if !containsString(values, target) {
			return false
		}
	}
	return true
}

func scopeForLocalMode(mode string) string {
	switch mode {
	case "append":
		return scopeAppend
	case "create":
		return scopeCreate
	case "delete":
		return scopeDelete
	case "write", "modify":
		return scopeWrite
	case "read":
		return scopeRead
	default:
		if strings.HasPrefix(mode, "urn:example:css:modes:") {
			return mode
		}
		return mode
	}
}

func knowsScopeForLocalMode(mode string) string {
	switch mode {
	case "append":
		return "urn:knows:uma:scopes:append"
	case "create":
		return "urn:knows:uma:scopes:create"
	case "delete":
		return "urn:knows:uma:scopes:delete"
	case "write", "modify":
		return "urn:knows:uma:scopes:write"
	case "read":
		return "urn:knows:uma:scopes:read"
	default:
		if strings.HasPrefix(mode, "urn:knows:uma:scopes:") {
			return mode
		}
		return mode
	}
}
