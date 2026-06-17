package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

func NewMux(cfg Config) http.Handler {
	return NewServer(cfg).Routes()
}

// serverInstanceSeq gives each Server its own working directories so that
// concurrent server instances (and their background availability pollers) never
// share the same oxigraph workspace or output paths.
var serverInstanceSeq atomic.Uint64

type Server struct {
	cfg                       Config
	mu                        sync.Mutex
	nextID                    int
	nextServiceID             int
	nextTicketID              int
	aggregators               map[string]aggregatorInstance
	services                  map[string]map[string]serviceInstance
	serviceRevisions          map[string]int
	outputAssets              map[string]outputAsset
	upstreamTokens            map[string]cachedUpstreamToken
	permissions               []PermissionRequestEvidence
	upstreamAccesses          []UpstreamAccessEvidence
	upstreamAccessRequests    []UpstreamAccessRequestEvidence
	resourceRegistrations     []ResourceRegistrationEvidence
	policySyncs               []PolicySyncEvidence
	authorizationResourceIDs  map[string]string
	derivedUpdates            []DerivedFromUpdateEvidence
	cleanups                  []ServiceCleanupEvidence
	accountAccessToken        string
	accountTokenError         error
	authorizationServerError  error
	authorizationServerClient authorizationServerClient
	protectionToken           protectionToken
	now                       func() time.Time
	pollingServices           map[string]bool
	materializeLocks          map[string]*sync.Mutex
}

func NewServer(cfg Config) *Server {
	instance := "instance-" + strconv.FormatUint(serverInstanceSeq.Add(1), 10)
	if cfg.OxigraphWorkdir != "" {
		cfg.OxigraphWorkdir = filepath.Join(cfg.OxigraphWorkdir, instance)
	}
	if cfg.OutputsDirectory != "" {
		cfg.OutputsDirectory = filepath.Join(cfg.OutputsDirectory, instance)
	}
	server := &Server{
		cfg:                      cfg,
		nextID:                   1,
		nextServiceID:            1,
		nextTicketID:             1,
		aggregators:              make(map[string]aggregatorInstance),
		services:                 make(map[string]map[string]serviceInstance),
		serviceRevisions:         make(map[string]int),
		outputAssets:             make(map[string]outputAsset),
		upstreamTokens:           make(map[string]cachedUpstreamToken),
		authorizationResourceIDs: make(map[string]string),
		pollingServices:          make(map[string]bool),
		materializeLocks:         make(map[string]*sync.Mutex),
		now:                      time.Now,
	}
	server.initializeAccountToken()
	server.initializeAuthorizationServer()
	return server
}

func (s *Server) initializeAccountToken() {
	if !s.cfg.hasAccountCredentials() {
		return
	}
	token, err := s.cfg.requestAccountAccessToken()
	if err != nil {
		s.accountTokenError = err
		return
	}
	s.accountAccessToken = token
}

func (s *Server) initializeAuthorizationServer() {
	if !s.shouldUseLiveAuthorizationServer() || s.accountTokenError != nil {
		log.Printf("httpapi: skipping live authorization-server initialization (live=%t accountTokenError=%v)", s.shouldUseLiveAuthorizationServer(), s.accountTokenError)
		return
	}
	log.Printf("httpapi: initializing live authorization-server integration for %s", s.cfg.authorizationServerURL())
	metadata, err := s.cfg.discoverAuthorizationServerMetadata(s.cfg.authorizationServerURL())
	if err != nil {
		s.authorizationServerError = err
		log.Printf("httpapi: authorization-server metadata discovery failed: %v", err)
		return
	}
	if _, err := s.protectionAPIAuthorization(metadata); err != nil {
		s.authorizationServerError = err
		log.Printf("httpapi: protection API authorization failed: %v", err)
		return
	}
	if err := s.syncConfiguredAuthorizationPolicies(); err != nil {
		s.authorizationServerError = err
		log.Printf("httpapi: authorization policy synchronization failed: %v", err)
		return
	}
	log.Printf("httpapi: live authorization-server initialization completed successfully")
}

type outputAsset struct {
	ResourceID            string
	Scopes                []string
	OutputPath            string
	ServiceURL            string
	DerivedFrom           []Derivation
	UpstreamDerivation    upstreamDerivationEvidence
	UpstreamDerivations   []upstreamDerivationEvidence
	PreviousTokensExpired bool
}

type PermissionRequestEvidence struct {
	ResourceID           string   `json:"resource_id"`
	ResourceScopes       []string `json:"resource_scopes"`
	Ticket               string   `json:"ticket"`
	AuthorizationServer  string   `json:"authorization_server,omitempty"`
	LiveAuthorizationAsk bool     `json:"live_authorization_ask,omitempty"`
}

type UpstreamAccessEvidence struct {
	SourceURL           string `json:"source_url"`
	AuthorizationServer string `json:"authorization_server"`
	Ticket              string `json:"ticket"`
	Token               string `json:"token"`
}

type UpstreamAccessRequestEvidence struct {
	ResourceURL         string `json:"resource_url"`
	AuthorizationServer string `json:"authorization_server"`
	RequestingParty     string `json:"requesting_party"`
	Action              string `json:"action"`
	RequestURL          string `json:"request_url"`
}

type ResourceRegistrationEvidence struct {
	ResourceURL         string   `json:"resource_url"`
	AuthorizationServer string   `json:"authorization_server"`
	OwnerToken          string   `json:"owner_token,omitempty"`
	Scopes              []string `json:"scopes"`
	Kind                string   `json:"kind"`
}

type DerivedFromUpdateEvidence struct {
	AASResourceID         string       `json:"aas_resource_id"`
	DerivedFrom           []Derivation `json:"derived_from"`
	PreviousTokensExpired bool         `json:"previous_tokens_expired"`
}

type ServiceCleanupEvidence struct {
	ServiceID                    string       `json:"service_id"`
	AASResourceID                string       `json:"aas_resource_id"`
	RemovedDerivedFrom           []Derivation `json:"removed_derived_from,omitempty"`
	DeletedDerivationResourceIDs []string     `json:"deleted_derivation_resource_ids,omitempty"`
	RemovedAASAsset              bool         `json:"removed_aas_asset"`
	MaterializedOutputDeletePath string       `json:"materialized_output_delete_path,omitempty"`
}

type upstreamDerivationEvidence struct {
	Issuer                    string
	DerivationResourceID      string
	ManagementAccessToken     string
	ManagementAccessTokenType string
}

type cachedUpstreamToken struct {
	AccessToken          string
	AuthorizationServer  string
	Ticket               string
	DerivationResourceID string
	Response             upstreamTokenResponse
}

func (e upstreamDerivationEvidence) hasData() bool {
	return e.Issuer != "" || e.DerivationResourceID != "" || e.ManagementAccessToken != ""
}

func upstreamDerivationEvidenceFrom(issuer string, token upstreamTokenResponse) upstreamDerivationEvidence {
	evidence := upstreamDerivationEvidence{
		Issuer:               issuer,
		DerivationResourceID: token.DerivationResourceID,
	}
	if token.ManagementAccessToken != nil {
		evidence.ManagementAccessToken = token.ManagementAccessToken.AccessToken
		evidence.ManagementAccessTokenType = token.ManagementAccessToken.TokenType
	}
	return evidence
}

func cloneUpstreamDerivations(derivations []upstreamDerivationEvidence) []upstreamDerivationEvidence {
	if len(derivations) == 0 {
		return nil
	}
	cloned := make([]upstreamDerivationEvidence, len(derivations))
	copy(cloned, derivations)
	return cloned
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		if !negotiateJSON(w, r) {
			return
		}
		writeJSON(w, http.StatusOK, BuildServerDescription(s.cfg))
	})
	mux.HandleFunc(s.cfg.ClientIdentifierPath, getOnly(func(w http.ResponseWriter, r *http.Request) {
		if !negotiateJSONLD(w, r) {
			return
		}
		writeJSONLD(w, http.StatusOK, BuildClientIdentifierDocument(s.cfg))
	}))
	mux.HandleFunc(s.cfg.TransformationCatalogPath, getOnly(func(w http.ResponseWriter, r *http.Request) {
		if !negotiateJSONLD(w, r) {
			return
		}
		writeJSONLD(w, http.StatusOK, BuildTransformationCatalog(s.cfg))
	}))
	mux.HandleFunc(s.cfg.ManagementEndpointPath, s.handleRegistration)
	mux.HandleFunc("/aggregators/", s.handleAggregator)
	return withCORS(s.withRoutePrefix(mux))
}

func (s *Server) withRoutePrefix(next http.Handler) http.Handler {
	prefix := s.cfg.routePrefix()
	if prefix == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == prefix {
			next.ServeHTTP(w, cloneRequestWithPath(r, "/"))
			return
		}
		if strings.HasPrefix(r.URL.Path, prefix+"/") {
			next.ServeHTTP(w, cloneRequestWithPath(r, strings.TrimPrefix(r.URL.Path, prefix)))
			return
		}
		next.ServeHTTP(w, r)
	})
}

func cloneRequestWithPath(r *http.Request, path string) *http.Request {
	cloned := new(http.Request)
	*cloned = *r
	urlCopy := *r.URL
	urlCopy.Path = path
	urlCopy.RawPath = ""
	cloned.URL = &urlCopy
	return cloned
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeCORSHeaders(w, r)
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeCORSHeaders(w http.ResponseWriter, r *http.Request) {
	origin := r.Header.Get("Origin")
	if origin == "" {
		origin = "*"
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Access-Control-Allow-Methods", "HEAD, GET, POST, PUT, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, DPoP, WWW-Authenticate, Link, Accept, Accept-Post")
	w.Header().Set("Access-Control-Expose-Headers", "Authorization, WWW-Authenticate, Link, Location, ETag, Accept-Post")
	if origin != "*" {
		w.Header().Set("Vary", "Origin")
	}
}

func getOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

type registrationRequest struct {
	ManagementFlow string `json:"management_flow"`
	Aggregator     string `json:"aggregator"`
	Code           string `json:"code"`
	RedirectURI    string `json:"redirect_uri"`
	State          string `json:"state"`
}

func (s *Server) handleRegistration(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListAggregators(w, r)
	case http.MethodPost:
		s.handleProvision(w, r)
	default:
		w.Header().Set("Allow", "GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleListAggregators(w http.ResponseWriter, r *http.Request) {
	if !negotiateJSON(w, r) {
		return
	}
	ownerToken := bearerToken(r.Header.Get("Authorization"))
	if !s.acceptProvisionToken(ownerToken) {
		w.Header().Set("WWW-Authenticate", `Bearer scope="read"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	s.writeAggregatorList(w, ownerToken)
}

func (s *Server) handleProvision(w http.ResponseWriter, r *http.Request) {
	if !negotiateJSON(w, r) {
		return
	}
	ownerToken := bearerToken(r.Header.Get("Authorization"))
	if !s.acceptProvisionToken(ownerToken) {
		w.Header().Set("WWW-Authenticate", `Bearer scope="create"`)
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	if contentType := r.Header.Get("Content-Type"); contentType != "" && !strings.HasPrefix(contentType, "application/json") {
		http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
		return
	}

	var req registrationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
		return
	}
	if req.ManagementFlow != "provision" {
		http.Error(w, "unsupported management_flow", http.StatusBadRequest)
		return
	}
	if req.Aggregator != "" || req.Code != "" || req.RedirectURI != "" || req.State != "" {
		http.Error(w, "invalid management request", http.StatusBadRequest)
		return
	}

	agg, err := s.createAggregator(ownerToken)
	if err != nil {
		http.Error(w, "authorization server registration failed: "+err.Error(), http.StatusBadGateway)
		return
	}

	aggregatorURL := s.cfg.absolute("/aggregators/" + agg.ID)
	resp := ManagementResponse{
		Aggregator: aggregatorURL,
		Subject:    agg.Subject,
	}
	if !isWebID(agg.Subject) {
		resp.IDP = s.cfg.provisionIDP()
	}
	w.Header().Set("Location", aggregatorURL)
	writeJSON(w, http.StatusCreated, resp)
}

func isWebID(subject string) bool {
	parsed, err := url.Parse(subject)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}

func (s *Server) acceptProvisionToken(token string) bool {
	return token != "" && token != "invalid-management-token"
}

func (s *Server) writeAggregatorList(w http.ResponseWriter, ownerToken string) {
	// Only list aggregators owned by the user behind the supplied token. The
	// owner is identified by an exact owner-token match or, for JWT access
	// tokens, by the token's subject claim.
	subject := subjectFromBearer(ownerToken, "")

	s.mu.Lock()
	aggregators := make([]aggregatorInstance, 0, len(s.aggregators))
	for _, agg := range s.aggregators {
		if agg.OwnerToken == ownerToken || (subject != "" && agg.Subject == subject) {
			aggregators = append(aggregators, agg)
		}
	}
	s.mu.Unlock()

	descriptions := make([]AggregatorDescription, 0, len(aggregators))
	for _, agg := range aggregators {
		descriptions = append(descriptions, BuildAggregatorDescription(s.cfg, agg))
	}
	writeJSON(w, http.StatusOK, descriptions)
}

func (s *Server) handleAggregator(w http.ResponseWriter, r *http.Request) {
	path := strings.Trim(strings.TrimPrefix(r.URL.Path, "/aggregators/"), "/")
	segments := strings.Split(path, "/")
	if path == "" || segments[0] == "" {
		http.NotFound(w, r)
		return
	}
	aggID := segments[0]

	s.mu.Lock()
	agg, ok := s.aggregators[aggID]
	s.mu.Unlock()
	if !ok {
		http.NotFound(w, r)
		return
	}

	if len(segments) == 1 {
		switch r.Method {
		case http.MethodGet:
			if !negotiateJSON(w, r) {
				return
			}
			writeJSON(w, http.StatusOK, BuildAggregatorDescription(s.cfg, agg))
		case http.MethodDelete:
			if bearerToken(r.Header.Get("Authorization")) != agg.OwnerToken {
				w.Header().Set("WWW-Authenticate", `Bearer scope="delete"`)
				http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
				return
			}
			s.deleteAggregator(aggID)
			w.WriteHeader(http.StatusNoContent)
		default:
			w.Header().Set("Allow", "GET, DELETE")
			http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		}
		return
	}

	if len(segments) == 2 && segments[1] == "transformations" {
		getOnly(func(w http.ResponseWriter, r *http.Request) {
			if !negotiateJSONLD(w, r) {
				return
			}
			writeJSONLD(w, http.StatusOK, BuildInstanceTransformationCatalog(s.cfg, aggID, s.serviceList(aggID)))
		})(w, r)
		return
	}

	if segments[1] != "services" {
		http.NotFound(w, r)
		return
	}

	if len(segments) == 2 {
		s.handleServiceCollection(w, r, aggID)
		return
	}
	if len(segments) == 3 {
		s.handleServiceEndpoint(w, r, aggID, segments[2])
		return
	}
	if len(segments) == 4 && segments[3] == "output" {
		s.handleServiceOutput(w, r, aggID, segments[2])
		return
	}
	http.NotFound(w, r)
}

func (s *Server) createAggregator(ownerToken string) (aggregatorInstance, error) {
	s.mu.Lock()

	id := "agg-" + strconv.Itoa(s.nextID)
	s.nextID++
	now := s.now().UTC()

	tokenExpiry := now.Add(time.Hour)
	if expiry, ok := idTokenExpiry(s.accountAccessToken); ok {
		tokenExpiry = expiry
	}
	agg := aggregatorInstance{
		ID:          id,
		Subject:     subjectFromBearer(ownerToken, s.cfg.provisionSubject()),
		OwnerToken:  ownerToken,
		CreatedAt:   now,
		TokenExpiry: tokenExpiry,
	}
	log.Printf("Created aggregator %s for subject %s", agg.ID, agg.Subject)
	s.aggregators[id] = agg
	s.services[id] = make(map[string]serviceInstance)
	s.registerAggregatorResourcesLocked(agg)
	s.mu.Unlock()

	if err := s.registerAggregatorResourcesAtAuthorizationServer(agg); err != nil {
		log.Printf("httpapi: authorization server registration failed for aggregator %s: %v", agg.ID, err)
		return aggregatorInstance{}, err
	}
	return agg, nil
}

func (s *Server) deleteAggregator(aggID string) {
	log.Printf("httpapi: deleting aggregator %s and its services", aggID)
	resources := []string{
		s.cfg.absolute("/aggregators/" + aggID),
		s.cfg.absolute("/aggregators/" + aggID + "/transformations"),
		s.cfg.absolute("/aggregators/" + aggID + "/services"),
	}
	for _, resourceID := range resources {
		_ = s.deleteConfiguredAuthorizationResource(resourceID)
	}
	s.mu.Lock()
	delete(s.aggregators, aggID)
	delete(s.services, aggID)
	delete(s.serviceRevisions, aggID)
	s.mu.Unlock()
}

type createServiceRequest struct {
	Transformation string   `json:"transformation"`
	SourceURLs     []string `json:"source_urls"`
}

func (s *Server) handleServiceCollection(w http.ResponseWriter, r *http.Request, aggID string) {
	switch r.Method {
	case http.MethodHead:
		if !negotiateJSONLD(w, r) {
			return
		}
		s.writeServiceCollectionHeaders(w, aggID)
	case http.MethodGet:
		if !negotiateJSONLD(w, r) {
			return
		}
		s.writeServiceCollectionHeaders(w, aggID)
		writeJSONLD(w, http.StatusOK, BuildServiceCollection(s.cfg, aggID, s.serviceList(aggID)))
	case http.MethodPost:
		s.handleCreateService(w, r, aggID)
	default:
		w.Header().Set("Allow", "HEAD, GET, POST")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleCreateService(w http.ResponseWriter, r *http.Request, aggID string) {
	if !negotiateJSONLD(w, r) {
		return
	}
	serviceCollectionURL := s.cfg.absolute("/aggregators/" + aggID + "/services")
	authorized, err := s.requireLiveUMAPermission(w, r, serviceCollectionURL, []string{scopeCreate})
	if err != nil {
		http.Error(w, "permission ticket request failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if !authorized {
		return
	}

	req, err := s.parseCreateServiceRequest(r)
	if err != nil {
		if errors.Is(err, errUnsupportedServiceContentType) {
			http.Error(w, http.StatusText(http.StatusUnsupportedMediaType), http.StatusUnsupportedMediaType)
			return
		}
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	req.Transformation = defaultString(req.Transformation, supportedTransformationURL(s.cfg))
	query := s.cfg.mediaProfileQuery()
	queryType, err := validateQuery(query)
	if req.Transformation != supportedTransformationURL(s.cfg) || err != nil || len(req.SourceURLs) == 0 {
		http.Error(w, "invalid service request", http.StatusBadRequest)
		return
	}

	serviceID := s.reserveServiceID()
	log.Printf("httpapi: creating service %s for aggregator %s (%d source(s), query type %s)", serviceID, aggID, len(req.SourceURLs), queryType)
	output, err := s.materialize(serviceID, req, queryType)
	if err != nil {
		if serviceCanBeCreatedWithoutInitialMaterialization(err) {
			log.Printf("httpapi: service %s created without initial materialization, %d source(s) still inaccessible; starting availability polling", serviceID, len(inaccessibleSourceURLs(err)))
			output = materializedOutput{MediaType: outputMediaTypeForQueryType(queryType)}
			if err := s.registerServiceResource(aggID, serviceID); err != nil {
				log.Printf("httpapi: authorization server registration failed for service %s: %v", serviceID, err)
				http.Error(w, "authorization server registration failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			asset, err := s.registerOutputAsset(aggID, serviceID, output)
			if err != nil {
				log.Printf("httpapi: output asset registration failed for service %s: %v", serviceID, err)
				http.Error(w, "authorization server registration failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			svc := s.createService(aggID, serviceID, req, queryType, output, asset, "ready", "", nil)
			s.startSourceAvailabilityPolling(aggID, serviceID, req, queryType, inaccessibleSourceURLs(err))
			desc := BuildServiceDescription(s.cfg, svc)
			w.Header().Set("Location", desc.ID)
			writeJSONLD(w, http.StatusCreated, desc)
			return
		}
		status := http.StatusBadRequest
		if strings.Contains(err.Error(), "oxigraph") {
			status = http.StatusInternalServerError
		}
		log.Printf("httpapi: materialization failed for service %s: %v", serviceID, err)
		http.Error(w, "materialization failed: "+err.Error(), status)
		return
	}

	if err := s.registerServiceResource(aggID, serviceID); err != nil {
		log.Printf("httpapi: authorization server registration failed for service %s: %v", serviceID, err)
		http.Error(w, "authorization server registration failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	asset, err := s.registerOutputAsset(aggID, serviceID, output)
	if err != nil {
		log.Printf("httpapi: output asset registration failed for service %s: %v", serviceID, err)
		http.Error(w, "authorization server registration failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	derivedFrom, err := s.updateOutputAssetDerivedFrom(asset.ResourceID, serviceID, output)
	status := "ready"
	errorMessage := ""
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
		log.Printf("httpapi: service %s materialized but derivedFrom update failed: %v", serviceID, err)
	}

	svc := s.createService(aggID, serviceID, req, queryType, output, asset, status, errorMessage, derivedFrom)
	log.Printf("httpapi: service %s for aggregator %s created with status %q", serviceID, aggID, status)
	desc := BuildServiceDescription(s.cfg, svc)
	w.Header().Set("Location", desc.ID)
	writeJSONLD(w, http.StatusCreated, desc)
}

func (s *Server) parseCreateServiceRequest(r *http.Request) (createServiceRequest, error) {
	contentType := strings.ToLower(strings.TrimSpace(strings.Split(r.Header.Get("Content-Type"), ";")[0]))
	if contentType == "application/ld+json" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return createServiceRequest{}, err
		}
		return parseCreateServiceRequestJSONLD(s.cfg, body)
	}
	if contentType == "" || contentType == "application/json" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return createServiceRequest{}, err
		}
		// A JSON-LD deployment may arrive with a generic application/json content
		// type; detect and route it to the JSON-LD parser so its nested applied
		// function data is not dropped by the flat {transformation, source_urls} decode.
		if looksLikeJSONLD(body) {
			return parseCreateServiceRequestJSONLD(s.cfg, body)
		}
		var req createServiceRequest
		if err := json.Unmarshal(body, &req); err != nil {
			return createServiceRequest{}, err
		}
		return req, nil
	}
	if contentType == "text/turtle" || contentType == "application/x-turtle" {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return createServiceRequest{}, err
		}
		return parseCreateServiceRequestTurtle(s.cfg, string(body))
	}
	return createServiceRequest{}, errUnsupportedServiceContentType
}

func (s *Server) handleServiceEndpoint(w http.ResponseWriter, r *http.Request, aggID, serviceID string) {
	switch r.Method {
	case http.MethodGet:
		s.handleServiceDescription(w, r, aggID, serviceID)
	case http.MethodDelete:
		s.handleDeleteService(w, r, aggID, serviceID)
	default:
		w.Header().Set("Allow", "GET, DELETE")
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleServiceDescription(w http.ResponseWriter, r *http.Request, aggID, serviceID string) {
	svc, ok := s.service(aggID, serviceID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if !negotiateJSONLD(w, r) {
		return
	}
	writeJSONLD(w, http.StatusOK, BuildServiceDescription(s.cfg, svc))
}

func (s *Server) handleDeleteService(w http.ResponseWriter, r *http.Request, aggID, serviceID string) {
	svc, ok := s.service(aggID, serviceID)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if err := s.deleteService(aggID, svc); err != nil {
		log.Printf("httpapi: service cleanup failed for service %s (aggregator %s): %v", serviceID, aggID, err)
		http.Error(w, "service cleanup failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	log.Printf("httpapi: deleted service %s for aggregator %s", serviceID, aggID)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleServiceOutput(w http.ResponseWriter, r *http.Request, aggID, serviceID string) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	svc, ok := s.service(aggID, serviceID)
	if !ok {
		http.NotFound(w, r)
		return
	}

	// Content negotiation: the service has exactly one representation on disk
	// (Turtle for CONSTRUCT, SPARQL-JSON for SELECT). If the client's Accept
	// header excludes that type, reject up front with 406 instead of doing
	// (re)materialization work and returning a surprising body.
	producedMediaType := svc.OutputMediaType
	if producedMediaType == "" {
		producedMediaType = outputMediaTypeForQueryType(svc.QueryType)
	}
	if !acceptsMediaType(r.Header.Get("Accept"), producedMediaType) {
		http.Error(w, fmt.Sprintf("service output is only available as %s", producedMediaType), http.StatusNotAcceptable)
		return
	}

	token := bearerToken(r.Header.Get("Authorization"))
	validRPT, err := s.outputRPTIsValid(token, svc.AASResourceID)
	if err != nil {
		http.Error(w, "RPT validation failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	ticket := ""
	if !validRPT {
		ticket, err = s.requestOutputPermission(svc.AASResourceID)
		if err != nil {
			http.Error(w, "permission ticket request failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		if ticket == "" {
			validRPT = true
		}
	}
	if !validRPT {
		w.Header().Set("WWW-Authenticate", fmt.Sprintf(`UMA as_uri="%s", ticket="%s"`, s.cfg.authorizationServerURL(), ticket))
		http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
		return
	}
	needsMaterialization, err := s.serviceNeedsMaterialization(svc)
	if err != nil {
		http.Error(w, "source validation failed: "+err.Error(), http.StatusBadGateway)
		return
	}
	if needsMaterialization {
		req := createServiceRequest{
			Transformation: svc.Transformation,
			SourceURLs:     append([]string(nil), svc.SourceURLs...),
		}
		output, err := s.materialize(serviceID, req, svc.QueryType)
		if err != nil {
			if isInsufficientUpstreamResources(err) {
				s.markServiceFailed(aggID, serviceID, insufficientUpstreamResourcesMessage)
				s.startSourceAvailabilityPolling(aggID, serviceID, req, svc.QueryType, inaccessibleSourceURLs(err))
				http.Error(w, insufficientUpstreamResourcesMessage, http.StatusFailedDependency)
				return
			}
			status := http.StatusBadRequest
			if strings.Contains(err.Error(), "oxigraph") {
				status = http.StatusInternalServerError
			}
			http.Error(w, "rematerialization failed: "+err.Error(), status)
			return
		}

		updatedSvc, exists, err := s.applyMaterializedOutput(aggID, serviceID, output)
		if exists {
			svc = updatedSvc
		}

		if err == nil {
			validRPT, err = s.outputRPTIsValid(token, svc.AASResourceID)
			if err != nil {
				http.Error(w, "RPT validation failed: "+err.Error(), http.StatusBadGateway)
				return
			}
			if !validRPT {
				ticket, err = s.requestOutputPermission(svc.AASResourceID)
				if err != nil {
					http.Error(w, "permission ticket request failed: "+err.Error(), http.StatusBadGateway)
					return
				}
				if ticket != "" {
					w.Header().Set("WWW-Authenticate", fmt.Sprintf(`UMA as_uri="%s", ticket="%s"`, s.cfg.authorizationServerURL(), ticket))
					http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
					return
				}
			}
		}
	}
	w.Header().Set("Link", "<"+serviceURL(s.cfg, aggID, serviceID)+">; rel=\"aggr:fromService\"")
	s.serveMaterializedOutput(w, r, svc)
}

// serveMaterializedOutput streams the materialized output file verbatim with its
// own RDF/SPARQL media type (e.g. text/turtle, application/sparql-results+json).
// We deliberately avoid http.ServeFile and any JSON encoding so a Turtle document
// is returned as raw text/turtle bytes rather than a content-sniffed or
// JSON.stringify'd body. Setting Content-Type explicitly before writing also
// suppresses net/http's content sniffing.
func (s *Server) serveMaterializedOutput(w http.ResponseWriter, r *http.Request, svc serviceInstance) {
	mediaType := svc.OutputMediaType
	if mediaType == "" {
		mediaType = outputMediaTypeForQueryType(svc.QueryType)
	}
	w.Header().Set("Content-Type", mediaType)

	if svc.OutputPath == "" {
		w.WriteHeader(http.StatusOK)
		return
	}
	body, err := os.ReadFile(svc.OutputPath)
	if err != nil {
		if os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}
		http.Error(w, "reading materialized output failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

// acceptsMediaType reports whether an Accept header value permits the given
// concrete media type. An empty/absent Accept header means the client accepts
// anything (RFC 9110 §12.5.1). It honors `*/*` and `type/*` wildcards and q=0
// exclusions, picking the most specific matching media range (with q as a
// tiebreaker) since the endpoint only ever has a single representation to offer.
func acceptsMediaType(accept, mediaType string) bool {
	accept = strings.TrimSpace(accept)
	if accept == "" {
		return true
	}
	wantType, wantSub, ok := splitMediaRange(mediaType)
	if !ok {
		return true
	}
	bestSpecificity := -1
	bestQ := 0.0
	matched := false
	for _, part := range strings.Split(accept, ",") {
		fields := strings.Split(part, ";")
		rType, rSub, ok := splitMediaRange(fields[0])
		if !ok {
			continue
		}
		if rType != "*" && rType != wantType {
			continue
		}
		if rSub != "*" && rSub != wantSub {
			continue
		}
		specificity := 0
		if rType != "*" {
			specificity++
		}
		if rSub != "*" {
			specificity++
		}
		q := 1.0
		for _, param := range fields[1:] {
			param = strings.TrimSpace(param)
			if strings.HasPrefix(strings.ToLower(param), "q=") {
				if parsed, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64); err == nil {
					q = parsed
				}
			}
		}
		if specificity > bestSpecificity || (specificity == bestSpecificity && q > bestQ) {
			bestSpecificity = specificity
			bestQ = q
		}
		matched = true
	}
	if !matched {
		return false
	}
	return bestQ > 0
}

// splitMediaRange splits a media type or media range into its type and subtype,
// discarding any parameters (e.g. charset). It returns ok=false for malformed
// values so callers can treat them leniently.
func splitMediaRange(value string) (string, string, bool) {
	value = strings.ToLower(strings.TrimSpace(value))
	if idx := strings.IndexByte(value, ';'); idx >= 0 {
		value = strings.TrimSpace(value[:idx])
	}
	slash := strings.IndexByte(value, '/')
	if slash <= 0 || slash == len(value)-1 {
		return "", "", false
	}
	return value[:slash], value[slash+1:], true
}

// negotiate enforces content negotiation for endpoints with a fixed response
// representation. compatible lists the concrete media types the response can
// satisfy; the first entry is the type that will actually be sent. If the
// client's Accept header permits none of them, negotiate writes a 406 and
// returns false. An empty/absent Accept header always passes.
func negotiate(w http.ResponseWriter, r *http.Request, compatible ...string) bool {
	accept := r.Header.Get("Accept")
	for _, mediaType := range compatible {
		if acceptsMediaType(accept, mediaType) {
			return true
		}
	}
	http.Error(w, fmt.Sprintf("representation is only available as %s", strings.Join(compatible, ", ")), http.StatusNotAcceptable)
	return false
}

// negotiateJSON / negotiateJSONLD gate the JSON and JSON-LD endpoints. JSON-LD
// is valid JSON, so each treats the other as an acceptable alias to stay
// interoperable with clients that send only `application/json`.
func negotiateJSON(w http.ResponseWriter, r *http.Request) bool {
	return negotiate(w, r, "application/json", "application/ld+json")
}

func negotiateJSONLD(w http.ResponseWriter, r *http.Request) bool {
	return negotiate(w, r, "application/ld+json", "application/json")
}

func (s *Server) writeServiceCollectionHeaders(w http.ResponseWriter, aggID string) {
	w.Header().Set("ETag", s.serviceCollectionETag(aggID))
	w.Header().Set("Accept-Post", "application/json, application/ld+json, text/turtle")
}

func (s *Server) serviceList(aggID string) []serviceInstance {
	s.mu.Lock()
	defer s.mu.Unlock()

	services := make([]serviceInstance, 0, len(s.services[aggID]))
	for _, svc := range s.services[aggID] {
		services = append(services, svc)
	}
	return services
}

func (s *Server) service(aggID, serviceID string) (serviceInstance, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc, ok := s.services[aggID][serviceID]
	return svc, ok
}

func (s *Server) markServiceFailed(aggID, serviceID, message string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if existing, exists := s.services[aggID][serviceID]; exists {
		existing.Status = "failed"
		existing.ErrorMessage = message
		existing.OutputPath = ""
		s.services[aggID][serviceID] = existing
		s.serviceRevisions[aggID]++
	}
}

// serviceMaterializeLock returns a per-service mutex so that synchronous
// (re)materialization and background availability polling never operate on the
// same oxigraph workspace concurrently.
func (s *Server) serviceMaterializeLock(serviceID string) *sync.Mutex {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.materializeLocks == nil {
		s.materializeLocks = make(map[string]*sync.Mutex)
	}
	lock, ok := s.materializeLocks[serviceID]
	if !ok {
		lock = &sync.Mutex{}
		s.materializeLocks[serviceID] = lock
	}
	return lock
}

// applyMaterializedOutput commits a freshly materialized output to the stored
// service instance, updating its derivation evidence and readiness status.
func (s *Server) applyMaterializedOutput(aggID, serviceID string, output materializedOutput) (serviceInstance, bool, error) {
	svc, ok := s.service(aggID, serviceID)
	if !ok {
		return serviceInstance{}, false, nil
	}

	derivedFrom, err := s.updateOutputAssetDerivedFrom(svc.AASResourceID, serviceID, output)
	status := "ready"
	errorMessage := ""
	if err != nil {
		status = "failed"
		errorMessage = err.Error()
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	existing, exists := s.services[aggID][serviceID]
	if !exists {
		return serviceInstance{}, false, err
	}
	existing.SourceMetadata = cloneSourceMetadata(output.Sources)
	existing.OutputMediaType = output.MediaType
	existing.OutputPath = output.Path
	existing.DerivedFrom = cloneDerivations(derivedFrom)
	existing.UpstreamDerivation = output.UpstreamDerivation
	existing.UpstreamDerivations = cloneUpstreamDerivations(output.UpstreamDerivations)
	existing.Status = status
	existing.ErrorMessage = errorMessage
	s.services[aggID][serviceID] = existing
	s.serviceRevisions[aggID]++
	return existing, true, err
}

// startSourceAvailabilityPolling launches (at most one per service) a
// background loop that re-attempts materialization once a previously
// inaccessible upstream resource (index or profile source) becomes reachable.
// This is triggered whenever an access request has been submitted: rather than
// re-fetching and re-loading every source on each tick, the loop probes only
// the resources the aggregator does not yet have access to and re-materializes
// the moment one of them is granted.
func (s *Server) startSourceAvailabilityPolling(aggID, serviceID string, req createServiceRequest, queryType string, pending []string) {
	s.mu.Lock()
	if s.pollingServices == nil {
		s.pollingServices = make(map[string]bool)
	}
	if s.pollingServices[serviceID] {
		s.mu.Unlock()
		return
	}
	s.pollingServices[serviceID] = true
	s.mu.Unlock()

	interval := s.cfg.sourceAvailabilityPollInterval()
	reqCopy := createServiceRequest{
		Transformation: req.Transformation,
		SourceURLs:     append([]string(nil), req.SourceURLs...),
	}
	pendingSources := append([]string(nil), pending...)

	go func() {
		defer func() {
			s.mu.Lock()
			delete(s.pollingServices, serviceID)
			s.mu.Unlock()
		}()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for range ticker.C {
			if _, ok := s.service(aggID, serviceID); !ok {
				return
			}
			// Only re-attempt materialization once a previously inaccessible
			// upstream resource has become reachable. This avoids re-fetching
			// and re-loading sources the aggregator already has access to on
			// every poll tick. When the inaccessible set is unknown we fall
			// back to probing through a full materialization attempt.
			if len(pendingSources) > 0 && !s.anyUpstreamSourceAccessible(pendingSources) {
				continue
			}
			output, err := s.materialize(serviceID, reqCopy, queryType)
			if err != nil {
				if isInsufficientUpstreamResources(err) {
					// Some resources are still inaccessible; narrow the polling
					// set to just those and keep waiting.
					pendingSources = inaccessibleSourceURLs(err)
					continue
				}
				log.Printf("httpapi: stopping availability polling for service %s: %v", serviceID, err)
				return
			}
			if _, _, err := s.applyMaterializedOutput(aggID, serviceID, output); err != nil {
				log.Printf("httpapi: availability polling materialized service %s but commit failed: %v", serviceID, err)
				return
			}
			log.Printf("httpapi: availability polling completed materialization for service %s", serviceID)
			return
		}
	}()
}

// anyUpstreamSourceAccessible reports whether at least one of the given upstream
// resources can now be accessed by the aggregator.
func (s *Server) anyUpstreamSourceAccessible(urls []string) bool {
	for _, rawURL := range urls {
		if s.upstreamSourceAccessible(rawURL) {
			return true
		}
	}
	return false
}

// upstreamSourceAccessible performs a lightweight access probe for a single
// upstream resource, negotiating UMA authorization if required. It does not
// download or load the resource, so it is cheap enough to run on every poll
// tick for the resources the aggregator still lacks access to.
func (s *Server) upstreamSourceAccessible(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		// Local sources are always reachable.
		return true
	}
	resp, err := s.requestHTTPSource(http.MethodHead, rawURL, "")
	if err != nil {
		return false
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return true
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return false
	}
	asURI, ticket, ok := parseUMAChallenge(resp.Challenge)
	if !ok {
		return false
	}
	if token := s.cachedUpstreamToken(rawURL, asURI); token != "" {
		resp, err = s.requestHTTPSource(http.MethodHead, rawURL, token)
		if err == nil && resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			return true
		}
	}
	upstreamToken, _, err := s.obtainUpstreamRPT(rawURL, asURI, ticket)
	if err != nil {
		return false
	}
	resp, err = s.requestHTTPSource(http.MethodHead, rawURL, upstreamToken)
	if err != nil {
		return false
	}
	return resp.StatusCode >= 200 && resp.StatusCode <= 299
}

func (s *Server) deleteService(aggID string, svc serviceInstance) error {
	if svc.OutputPath != "" {
		if err := os.Remove(svc.OutputPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	s.cleanupServiceAssets(svc)

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.services[aggID][svc.ID]; !ok {
		return nil
	}
	delete(s.services[aggID], svc.ID)
	s.serviceRevisions[aggID]++
	return nil
}

func (s *Server) reserveServiceID() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	serviceID := "service-" + strconv.Itoa(s.nextServiceID)
	s.nextServiceID++
	return serviceID
}

func (s *Server) createService(aggID string, serviceID string, req createServiceRequest, queryType string, output materializedOutput, asset outputAsset, status, errorMessage string, derivedFrom []Derivation) serviceInstance {
	s.mu.Lock()
	defer s.mu.Unlock()

	svc := serviceInstance{
		ID:                  serviceID,
		AggregatorID:        aggID,
		Transformation:      req.Transformation,
		Query:               s.cfg.mediaProfileQuery(),
		QueryType:           queryType,
		SourceURLs:          append([]string(nil), req.SourceURLs...),
		SourceMetadata:      cloneSourceMetadata(output.Sources),
		Status:              status,
		OutputMediaType:     output.MediaType,
		OutputPath:          output.Path,
		AASIssuer:           s.cfg.authorizationServerURL(),
		AASResourceID:       asset.ResourceID,
		DerivedFrom:         cloneDerivations(derivedFrom),
		UpstreamDerivation:  output.UpstreamDerivation,
		UpstreamDerivations: cloneUpstreamDerivations(output.UpstreamDerivations),
		ErrorMessage:        errorMessage,
		CreatedAt:           s.now().UTC(),
	}
	s.services[aggID][serviceID] = svc
	s.serviceRevisions[aggID]++
	return svc
}

func (s *Server) serviceCollectionETag(aggID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return `"` + aggID + "-" + strconv.Itoa(s.serviceRevisions[aggID]) + `"`
}

func supportedTransformationURL(cfg Config) string {
	return cfg.absolute(cfg.TransformationCatalogPath) + "#" + cfg.transformationFragment()
}

func transformationSourceParameterURL(cfg Config) string {
	return cfg.absolute(cfg.TransformationCatalogPath) + "#" + cfg.transformationSourceFragment()
}

func transformationOutputURL(cfg Config) string {
	return cfg.absolute(cfg.TransformationCatalogPath) + "#" + cfg.transformationOutputFragment()
}

func (s *Server) registerAggregatorResourcesLocked(agg aggregatorInstance) {
	base := s.cfg.absolute("/aggregators/" + agg.ID)
	s.registerResourceLocked(base, []string{"read", "delete"}, "aggregator_description", agg.OwnerToken)
	s.registerResourceLocked(base+"/transformations", []string{"read"}, "instance_transformation_catalog", agg.OwnerToken)
	s.registerResourceLocked(base+"/services", []string{"read", "create"}, "service_collection", agg.OwnerToken)
}

func (s *Server) registerAggregatorResourcesAtAuthorizationServer(agg aggregatorInstance) error {
	base := s.cfg.absolute("/aggregators/" + agg.ID)
	for _, resource := range []struct {
		url    string
		scopes []string
		kind   string
	}{
		{url: base, scopes: []string{scopeRead, scopeDelete}, kind: "aggregator_description"},
		{url: base + "/transformations", scopes: []string{scopeRead}, kind: "instance_transformation_catalog"},
		{url: base + "/services", scopes: []string{scopeRead, scopeCreate}, kind: "service_collection"},
	} {
		if err := s.registerConfiguredAuthorizationResource(resource.url, resource.scopes, resource.kind); err != nil {
			return err
		}
	}
	return nil
}

func (s *Server) registerResourceLocked(resourceURL string, scopes []string, kind, ownerToken string) {
	s.resourceRegistrations = append(s.resourceRegistrations, ResourceRegistrationEvidence{
		ResourceURL:         resourceURL,
		AuthorizationServer: s.cfg.authorizationServerURL(),
		OwnerToken:          ownerToken,
		Scopes:              append([]string(nil), scopes...),
		Kind:                kind,
	})
}

func (s *Server) registerOutputAsset(aggID, serviceID string, output materializedOutput) (outputAsset, error) {
	outputURL := serviceURL(s.cfg, aggID, serviceID) + "/output"
	asset := outputAsset{
		ResourceID:          outputURL,
		Scopes:              []string{s.cfg.OutputReadScope},
		OutputPath:          output.Path,
		ServiceURL:          serviceURL(s.cfg, aggID, serviceID),
		UpstreamDerivation:  output.UpstreamDerivation,
		UpstreamDerivations: cloneUpstreamDerivations(output.UpstreamDerivations),
	}

	s.mu.Lock()
	s.outputAssets[asset.ResourceID] = asset
	ownerToken := s.aggregators[aggID].OwnerToken
	s.registerResourceLocked(serviceURL(s.cfg, aggID, serviceID)+"/output", []string{s.cfg.OutputReadScope}, "service_output", ownerToken)
	s.mu.Unlock()
	if err := s.registerConfiguredAuthorizationResource(serviceURL(s.cfg, aggID, serviceID)+"/output", []string{scopeForLocalMode(s.cfg.OutputReadScope)}, "service_output"); err != nil {
		return outputAsset{}, err
	}
	return asset, nil
}

func (s *Server) registerServiceResource(aggID, serviceID string) error {
	s.mu.Lock()

	ownerToken := s.aggregators[aggID].OwnerToken
	s.registerResourceLocked(serviceURL(s.cfg, aggID, serviceID), []string{"read", "delete"}, "service_description", ownerToken)
	s.mu.Unlock()

	if err := s.registerConfiguredAuthorizationResource(serviceURL(s.cfg, aggID, serviceID), []string{scopeRead, scopeDelete}, "service_description"); err != nil {
		return err
	}
	return nil
}

func (s *Server) updateOutputAssetDerivedFrom(resourceID, serviceID string, output materializedOutput) ([]Derivation, error) {
	if s.cfg.FailDerivedFromUpdate {
		return nil, fmt.Errorf("AAS derived_from update failed")
	}
	scopes := []string{knowsScopeForLocalMode(s.cfg.OutputReadScope)}
	derivedFrom := make([]Derivation, 0, len(output.UpstreamDerivations))
	for i, upstreamDerivation := range output.UpstreamDerivations {
		if !upstreamDerivation.hasData() {
			continue
		}
		derivation := Derivation{
			Issuer:               upstreamDerivation.Issuer,
			DerivationResourceID: upstreamDerivation.DerivationResourceID,
		}
		if derivation.DerivationResourceID == "" {
			derivation.DerivationResourceID = fmt.Sprintf("%s-%s-%d", s.cfg.DerivationResourceIDPrefix, serviceID, i+1)
		}
		managementAccessToken := s.accountAccessToken
		managementAccessTokenType := "Bearer"
		if upstreamDerivation.ManagementAccessToken != "" {
			managementAccessToken = upstreamDerivation.ManagementAccessToken
		}
		if upstreamDerivation.ManagementAccessTokenType != "" {
			managementAccessTokenType = upstreamDerivation.ManagementAccessTokenType
		}
		if derivation.Issuer != "" {
			if err := s.updateUASDerivationResource(derivation.DerivationResourceID, derivation.Issuer, resourceID, serviceID, scopes, managementAccessToken, managementAccessTokenType); err != nil {
				return derivedFrom, err
			}
		}
		if derivation.hasData() {
			derivedFrom = append(derivedFrom, derivation)
		}
	}
	if err := s.updateConfiguredAuthorizationResource(resourceID, []string{scopeForLocalMode(s.cfg.OutputReadScope)}, "service_output", derivedFrom); err != nil {
		return derivedFrom, err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	asset := s.outputAssets[resourceID]
	asset.DerivedFrom = cloneDerivations(derivedFrom)
	asset.UpstreamDerivation = output.UpstreamDerivation
	asset.UpstreamDerivations = cloneUpstreamDerivations(output.UpstreamDerivations)
	asset.PreviousTokensExpired = true
	s.outputAssets[resourceID] = asset
	s.derivedUpdates = append(s.derivedUpdates, DerivedFromUpdateEvidence{
		AASResourceID:         resourceID,
		DerivedFrom:           cloneDerivations(asset.DerivedFrom),
		PreviousTokensExpired: asset.PreviousTokensExpired,
	})
	return derivedFrom, nil
}

func (s *Server) cleanupServiceAssets(svc serviceInstance) {
	_ = s.deleteConfiguredAuthorizationResource(serviceURL(s.cfg, svc.AggregatorID, svc.ID))
	_ = s.deleteConfiguredAuthorizationResource(svc.AASResourceID)

	s.mu.Lock()
	defer s.mu.Unlock()

	asset, hadAsset := s.outputAssets[svc.AASResourceID]
	if hadAsset {
		delete(s.outputAssets, svc.AASResourceID)
	}

	removed := cloneDerivations(asset.DerivedFrom)
	if len(removed) == 0 {
		removed = cloneDerivations(svc.DerivedFrom)
	}
	upstreamDerivation := asset.UpstreamDerivation
	if !upstreamDerivation.hasData() {
		upstreamDerivation = svcUpstreamDerivation(svc)
	}
	deletedDerivationIDs := make([]string, 0, len(removed))
	for _, derivation := range removed {
		if derivation.DerivationResourceID != "" {
			_ = s.deleteUASDerivationResource(derivation.DerivationResourceID, upstreamDerivationForID(derivation.DerivationResourceID, asset.UpstreamDerivations, svc.UpstreamDerivations, upstreamDerivation))
			deletedDerivationIDs = append(deletedDerivationIDs, derivation.DerivationResourceID)
		}
	}

	s.cleanups = append(s.cleanups, ServiceCleanupEvidence{
		ServiceID:                    svc.ID,
		AASResourceID:                svc.AASResourceID,
		RemovedDerivedFrom:           removed,
		DeletedDerivationResourceIDs: deletedDerivationIDs,
		RemovedAASAsset:              hadAsset,
		MaterializedOutputDeletePath: svc.OutputPath,
	})
}

func (s *Server) updateUASDerivationResource(derivationResourceID, derivationIssuer string, resourceID, serviceID string, scopes []string, managementAccessToken, managementAccessTokenType string) error {
	if !s.shouldUseLiveAuthorizationServer() && s.cfg.UASDerivationResourcesEndpoint == "" {
		return nil
	}

	metadata, err := s.cfg.discoverAuthorizationServerMetadata(derivationIssuer)
	if err != nil {
		return err
	}

	endpoint := strings.TrimRight(metadata.ResourceRegistrationEndpoint, "/")
	if endpoint == "" {
		errMsg := fmt.Errorf("authorization server metadata did not include resource_registration_endpoint")
		return errMsg
	}

	if managementAccessToken == "" {
		if s.accountTokenError != nil {
			return s.accountTokenError
		}
		if s.accountAccessToken == "" {
			errMsg := fmt.Errorf("account access token is not available for resource %s", resourceID)
			return errMsg
		}
		managementAccessToken = s.accountAccessToken
		if managementAccessTokenType == "" {
			managementAccessTokenType = "Bearer"
		}
	}

	body, err := json.Marshal(derivationResourceDescriptionDocument{
		Name:           s.cfg.upstreamDerivationResourceName(),
		ResourceScopes: append([]string(nil), scopes...),
	})
	if err != nil {
		return err
	}

	req, err := http.NewRequest(http.MethodPut, endpoint+"/"+url.PathEscape(derivationResourceID), bytes.NewReader(body))
	if err != nil {
		return err
	}

	if managementAccessTokenType == "" {
		managementAccessTokenType = "Bearer"
	}

	authHeader := fmt.Sprintf("%s %s", managementAccessTokenType, managementAccessToken)
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")

	status, responseBody, err := s.doAuthorizationServer(req)

	if err != nil {
		return err
	}

	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
		errMsg := fmt.Errorf("UAS derivation resource PUT %s returned %d: %s", req.URL.String(), status, strings.TrimSpace(string(responseBody)))
		return errMsg
	}

	return nil
}

func (s *Server) deleteUASDerivationResource(derivationResourceID string, upstreamDerivation upstreamDerivationEvidence) error {
	if !s.shouldUseLiveAuthorizationServer() && s.cfg.UASDerivationResourcesEndpoint == "" {
		return nil
	}
	metadata, err := s.uasAuthorizationServerMetadata(upstreamDerivation.Issuer)
	if err != nil {
		return err
	}
	endpoint := strings.TrimRight(metadata.ResourceRegistrationEndpoint, "/")
	if endpoint == "" {
		return fmt.Errorf("authorization server metadata did not include resource_registration_endpoint")
	}
	managementAccessToken := upstreamDerivation.ManagementAccessToken
	managementAccessTokenType := upstreamDerivation.ManagementAccessTokenType
	if managementAccessToken == "" {
		if s.accountTokenError != nil {
			return s.accountTokenError
		}
		if s.accountAccessToken == "" {
			return fmt.Errorf("account access token is not available")
		}
		managementAccessToken = s.accountAccessToken
		if managementAccessTokenType == "" {
			managementAccessTokenType = "Bearer"
		}
	}
	req, err := http.NewRequest(http.MethodDelete, endpoint+"/"+url.PathEscape(derivationResourceID), nil)
	if err != nil {
		return err
	}
	if managementAccessTokenType == "" {
		managementAccessTokenType = "Bearer"
	}
	req.Header.Set("Authorization", managementAccessTokenType+" "+managementAccessToken)
	req.Header.Set("Accept", "application/json")
	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("UAS derivation resource DELETE %s returned %d: %s", req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (s *Server) uasAuthorizationServerMetadata(issuer string) (oidcConfiguration, error) {
	if issuer != "" {
		if metadata, err := s.cfg.discoverAuthorizationServerMetadata(issuer); err == nil {
			return metadata, nil
		} else if s.cfg.UASDerivationResourcesEndpoint == "" {
			return oidcConfiguration{}, err
		}
	}
	if s.cfg.UASDerivationResourcesEndpoint != "" {
		return oidcConfiguration{
			ResourceRegistrationEndpoint: strings.TrimRight(s.cfg.UASDerivationResourcesEndpoint, "/"),
		}, nil
	}
	return oidcConfiguration{}, fmt.Errorf("authorization server metadata could not be discovered for UAS")
}

func svcUpstreamDerivation(svc serviceInstance) upstreamDerivationEvidence {
	return svc.UpstreamDerivation
}

func upstreamDerivationForID(derivationResourceID string, assetDerivations, serviceDerivations []upstreamDerivationEvidence, fallback upstreamDerivationEvidence) upstreamDerivationEvidence {
	for _, derivation := range assetDerivations {
		if derivation.DerivationResourceID == derivationResourceID {
			return derivation
		}
	}
	for _, derivation := range serviceDerivations {
		if derivation.DerivationResourceID == derivationResourceID {
			return derivation
		}
	}
	return fallback
}

func (s *Server) Shutdown() error {
	s.mu.Lock()
	resources := make([]string, 0, len(s.authorizationResourceIDs))
	for resourceID := range s.authorizationResourceIDs {
		resources = append(resources, resourceID)
	}
	s.mu.Unlock()

	var errs []string
	for _, resourceID := range resources {
		if err := s.deleteConfiguredAuthorizationResource(resourceID); err != nil {
			errs = append(errs, err.Error())
		}
	}
	if err := s.deleteAuthorizationServerClientRegistration(); err != nil {
		errs = append(errs, err.Error())
	}
	if len(errs) > 0 {
		return fmt.Errorf("authorization server cleanup failed: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (s *Server) outputRPTIsValid(token, resourceID string) (bool, error) {
	if token == "" || resourceID == "" {
		return false, nil
	}
	s.mu.Lock()
	_, assetExists := s.outputAssets[resourceID]
	s.mu.Unlock()
	if !assetExists {
		return false, nil
	}
	if s.shouldUseLiveAuthorizationServer() {
		return s.liveRPTIsValid(token, resourceID, []string{scopeForLocalMode(s.cfg.OutputReadScope)})
	}
	for _, valid := range s.cfg.ValidOutputRPTs {
		if token == valid {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) requestOutputPermission(resourceID string) (string, error) {
	if s.shouldUseLiveAuthorizationServer() {
		ticket, err := s.requestLivePermission(resourceID, []string{scopeForLocalMode(s.cfg.OutputReadScope)})
		if err != nil {
			return "", err
		}
		if ticket != "" {
			s.recordPermissionRequest(resourceID, []string{s.cfg.OutputReadScope}, ticket, true)
		}
		return ticket, nil
	}

	ticket := s.localPermissionTicket()
	s.recordPermissionRequest(resourceID, []string{s.cfg.OutputReadScope}, ticket, false)
	return ticket, nil
}

func (s *Server) localPermissionTicket() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	ticket := "ticket-" + strconv.Itoa(s.nextTicketID)
	s.nextTicketID++
	return ticket
}

func (s *Server) requireLiveUMAPermission(w http.ResponseWriter, r *http.Request, resourceID string, scopes []string) (bool, error) {
	if !s.shouldUseLiveAuthorizationServer() {
		return true, nil
	}
	token := bearerToken(r.Header.Get("Authorization"))
	if token != "" {
		valid, err := s.liveRPTIsValid(token, resourceID, scopes)
		if err != nil {
			return false, err
		}
		if valid {
			return true, nil
		}
	}
	ticket, err := s.requestLivePermission(resourceID, scopes)
	if err != nil {
		return false, err
	}
	if ticket == "" {
		return true, nil
	}
	s.recordPermissionRequest(resourceID, scopes, ticket, true)
	w.Header().Set("WWW-Authenticate", fmt.Sprintf(`UMA as_uri="%s", ticket="%s"`, s.cfg.authorizationServerURL(), ticket))
	http.Error(w, http.StatusText(http.StatusUnauthorized), http.StatusUnauthorized)
	return false, nil
}

func (s *Server) recordPermissionRequest(resourceID string, scopes []string, ticket string, live bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.permissions = append(s.permissions, PermissionRequestEvidence{
		ResourceID:           resourceID,
		ResourceScopes:       append([]string(nil), scopes...),
		Ticket:               ticket,
		AuthorizationServer:  s.cfg.authorizationServerURL(),
		LiveAuthorizationAsk: live,
	})
}

func (s *Server) PermissionRequests() []PermissionRequestEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	requests := make([]PermissionRequestEvidence, 0, len(s.permissions))
	for _, permission := range s.permissions {
		requests = append(requests, PermissionRequestEvidence{
			ResourceID:           permission.ResourceID,
			ResourceScopes:       append([]string(nil), permission.ResourceScopes...),
			Ticket:               permission.Ticket,
			AuthorizationServer:  permission.AuthorizationServer,
			LiveAuthorizationAsk: permission.LiveAuthorizationAsk,
		})
	}
	return requests
}

func (s *Server) UpstreamAccesses() []UpstreamAccessEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	accesses := make([]UpstreamAccessEvidence, len(s.upstreamAccesses))
	copy(accesses, s.upstreamAccesses)
	return accesses
}

func (s *Server) UpstreamAccessRequests() []UpstreamAccessRequestEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	requests := make([]UpstreamAccessRequestEvidence, len(s.upstreamAccessRequests))
	copy(requests, s.upstreamAccessRequests)
	return requests
}

func (s *Server) ResourceRegistrations() []ResourceRegistrationEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	registrations := make([]ResourceRegistrationEvidence, 0, len(s.resourceRegistrations))
	for _, registration := range s.resourceRegistrations {
		registrations = append(registrations, ResourceRegistrationEvidence{
			ResourceURL:         registration.ResourceURL,
			AuthorizationServer: registration.AuthorizationServer,
			OwnerToken:          registration.OwnerToken,
			Scopes:              append([]string(nil), registration.Scopes...),
			Kind:                registration.Kind,
		})
	}
	return registrations
}

func (s *Server) DerivedFromUpdates() []DerivedFromUpdateEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	updates := make([]DerivedFromUpdateEvidence, 0, len(s.derivedUpdates))
	for _, update := range s.derivedUpdates {
		updates = append(updates, DerivedFromUpdateEvidence{
			AASResourceID:         update.AASResourceID,
			DerivedFrom:           cloneDerivations(update.DerivedFrom),
			PreviousTokensExpired: update.PreviousTokensExpired,
		})
	}
	return updates
}

func (s *Server) ServiceCleanups() []ServiceCleanupEvidence {
	s.mu.Lock()
	defer s.mu.Unlock()

	cleanups := make([]ServiceCleanupEvidence, 0, len(s.cleanups))
	for _, cleanup := range s.cleanups {
		cleanups = append(cleanups, ServiceCleanupEvidence{
			ServiceID:                    cleanup.ServiceID,
			AASResourceID:                cleanup.AASResourceID,
			RemovedDerivedFrom:           cloneDerivations(cleanup.RemovedDerivedFrom),
			DeletedDerivationResourceIDs: append([]string(nil), cleanup.DeletedDerivationResourceIDs...),
			RemovedAASAsset:              cleanup.RemovedAASAsset,
			MaterializedOutputDeletePath: cleanup.MaterializedOutputDeletePath,
		})
	}
	return cleanups
}

func bearerToken(header string) string {
	prefix := "Bearer "
	if !strings.HasPrefix(header, prefix) {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(header, prefix))
}

func subjectFromBearer(token, fallback string) string {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return fallback
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return fallback
	}
	var claims struct {
		Subject string `json:"sub"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil || claims.Subject == "" {
		return fallback
	}
	return claims.Subject
}

func validateQuery(query string) (string, error) {
	normalized := strings.ToUpper(strings.TrimSpace(query))
	if normalized == "" {
		return "", fmt.Errorf("query is required")
	}
	if strings.Contains(normalized, " SERVICE ") || strings.Contains(normalized, "{SERVICE ") || strings.Contains(normalized, "\nSERVICE ") {
		return "", fmt.Errorf("remote SERVICE is not supported")
	}
	switch {
	case strings.HasPrefix(normalized, "CONSTRUCT"):
		return "CONSTRUCT", nil
	case strings.HasPrefix(normalized, "SELECT"):
		return "SELECT", nil
	case strings.HasPrefix(normalized, "ASK"):
		return "", fmt.Errorf("ASK is not supported")
	case strings.HasPrefix(normalized, "DESCRIBE"):
		return "", fmt.Errorf("DESCRIBE is not supported")
	case strings.HasPrefix(normalized, "INSERT"), strings.HasPrefix(normalized, "DELETE"), strings.HasPrefix(normalized, "LOAD"), strings.HasPrefix(normalized, "CLEAR"), strings.HasPrefix(normalized, "CREATE"), strings.HasPrefix(normalized, "DROP"), strings.HasPrefix(normalized, "COPY"), strings.HasPrefix(normalized, "MOVE"), strings.HasPrefix(normalized, "ADD"):
		return "", fmt.Errorf("SPARQL Update is not supported")
	default:
		return "", fmt.Errorf("only CONSTRUCT and SELECT are supported")
	}
}

type materializedOutput struct {
	MediaType           string
	Path                string
	Sources             []SourceMetadata
	UpstreamDerivation  upstreamDerivationEvidence
	UpstreamDerivations []upstreamDerivationEvidence
}

type stagedSource struct {
	Path               string
	Format             string
	Metadata           SourceMetadata
	UpstreamDerivation upstreamDerivationEvidence
}

type sourceHTTPResult struct {
	Body                []byte
	ContentType         string
	ETag                string
	Protected           bool
	AuthorizationServer string
	Ticket              string
	UpstreamDerivation  upstreamDerivationEvidence
}

type sparqlResultsJSON struct {
	Results struct {
		Bindings []map[string]sparqlBinding `json:"bindings"`
	} `json:"results"`
}

type sparqlBinding struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type inaccessibleSourceError struct {
	err error
}

const insufficientUpstreamResourcesMessage = "not enough upstream resources can be accessed"

type insufficientUpstreamResourcesError struct {
	Accessible   int
	Total        int
	Inaccessible []string
}

func (e insufficientUpstreamResourcesError) Error() string {
	return insufficientUpstreamResourcesMessage
}

func isInsufficientUpstreamResources(err error) bool {
	var insufficient insufficientUpstreamResourcesError
	return errors.As(err, &insufficient)
}

// inaccessibleSourceURLs extracts the upstream resource URLs that could not be
// accessed during materialization. Availability polling uses this set to probe
// only the resources the aggregator still lacks access to, instead of
// re-fetching every source on each tick.
func inaccessibleSourceURLs(err error) []string {
	var insufficient insufficientUpstreamResourcesError
	if errors.As(err, &insufficient) {
		return append([]string(nil), insufficient.Inaccessible...)
	}
	return nil
}

func isInaccessibleSourceError(err error) bool {
	var inaccessible inaccessibleSourceError
	return errors.As(err, &inaccessible)
}

func serviceCanBeCreatedWithoutInitialMaterialization(err error) bool {
	var inaccessible inaccessibleSourceError
	return isInsufficientUpstreamResources(err) || errors.As(err, &inaccessible)
}

func (e inaccessibleSourceError) Error() string {
	return e.err.Error()
}

func (e inaccessibleSourceError) Unwrap() error {
	return e.err
}

func (s *Server) materialize(serviceID string, req createServiceRequest, queryType string) (materializedOutput, error) {
	workspace := filepath.Join(s.cfg.OxigraphWorkdir, serviceID)
	storeDir := filepath.Join(workspace, "store")
	stagingDir := filepath.Join(workspace, "sources")
	outputDir := filepath.Join(s.cfg.OutputsDirectory, serviceID)

	if err := os.RemoveAll(workspace); err != nil {
		return materializedOutput{}, err
	}
	if err := os.RemoveAll(outputDir); err != nil {
		return materializedOutput{}, err
	}
	if err := os.MkdirAll(stagingDir, 0o755); err != nil {
		return materializedOutput{}, err
	}
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return materializedOutput{}, err
	}

	var sources []SourceMetadata
	var upstreamDerivations []upstreamDerivationEvidence
	var lastSourceErr error
	var lastIndexAccessErr error
	var inaccessibleIndexSources []string
	var indexSourceURLs []string
	accessibleIndexSources := 0
	for i, sourceURL := range req.SourceURLs {
		source, err := s.stageSource(stagingDir, i, sourceURL)
		if err != nil {
			log.Printf("httpapi: failed to stage index source %s: %v", sourceURL, err)
			lastSourceErr = err
			if isInaccessibleSourceError(err) {
				lastIndexAccessErr = err
				inaccessibleIndexSources = append(inaccessibleIndexSources, sourceURL)
			}
			continue
		}
		sources = append(sources, source.Metadata)
		if source.UpstreamDerivation.hasData() {
			upstreamDerivations = appendUniqueUpstreamDerivation(upstreamDerivations, source.UpstreamDerivation)
		}
		if err := loadStagedSource(s.cfg.OxigraphBinary, storeDir, source); err != nil {
			log.Printf("httpapi: failed to load index source %s into oxigraph: %v", sourceURL, err)
			lastSourceErr = err
			continue
		}
		accessibleIndexSources++
		indexSourceURLs = append(indexSourceURLs, sourceURL)
	}

	// When the index itself cannot be reached because of an access decision we
	// have no way to discover the profile sources it references, so treat it the
	// same as not having enough accessible upstream resources (HTTP 424) and let
	// the caller poll until the access request is accepted. Other failures (e.g.
	// malformed/non-RDF index, oxigraph errors) keep their original handling.
	if len(req.SourceURLs) > 0 && accessibleIndexSources == 0 && lastIndexAccessErr != nil {
		return materializedOutput{}, insufficientUpstreamResourcesError{
			Accessible:   accessibleIndexSources,
			Total:        len(req.SourceURLs),
			Inaccessible: inaccessibleIndexSources,
		}
	}

	profileURLs, err := s.queryMediaProfileIndex(storeDir, outputDir, indexSourceURLs)
	if err != nil {
		if lastSourceErr != nil {
			return materializedOutput{}, lastSourceErr
		}
		return materializedOutput{}, err
	}

	accessibleProfileSources := 0
	var inaccessibleProfileSources []string
	if len(profileURLs) > 0 {
		if err := os.RemoveAll(storeDir); err != nil {
			return materializedOutput{}, err
		}

		for i, sourceURL := range profileURLs {
			source, err := s.stageSource(stagingDir, len(req.SourceURLs)+i, sourceURL)
			if err != nil {
				log.Printf("httpapi: failed to stage media profile source %s: %v", sourceURL, err)
				lastSourceErr = err
				if isInaccessibleSourceError(err) {
					inaccessibleProfileSources = append(inaccessibleProfileSources, sourceURL)
				}
				continue
			}
			sources = append(sources, source.Metadata)
			if source.UpstreamDerivation.hasData() {
				upstreamDerivations = appendUniqueUpstreamDerivation(upstreamDerivations, source.UpstreamDerivation)
			}
			if err := loadStagedSource(s.cfg.OxigraphBinary, storeDir, source); err != nil {
				log.Printf("httpapi: failed to load media profile source %s into oxigraph: %v", sourceURL, err)
				lastSourceErr = err
				continue
			}
			accessibleProfileSources++
		}
	}

	if !s.hasEnoughAccessibleProfileSources(accessibleProfileSources, len(profileURLs)) {
		return materializedOutput{}, insufficientUpstreamResourcesError{
			Accessible:   accessibleProfileSources,
			Total:        len(profileURLs),
			Inaccessible: inaccessibleProfileSources,
		}
	}

	var mediaType string
	var outputName string
	var resultFormat string
	switch queryType {
	case "CONSTRUCT":
		mediaType = "text/turtle"
		outputName = "output.ttl"
		resultFormat = "ttl"
	case "SELECT":
		mediaType = "application/sparql-results+json"
		outputName = "output.srj"
		resultFormat = "json"
	default:
		return materializedOutput{}, fmt.Errorf("unsupported query type %s", queryType)
	}

	if len(sources) == 0 {
		if lastSourceErr != nil {
			return materializedOutput{}, lastSourceErr
		}
		outputPath := filepath.Join(outputDir, "empty."+resultFormat)
		if err := os.WriteFile(outputPath, []byte(""), 0o644); err != nil {
			return materializedOutput{}, err
		}
		log.Printf("httpapi: materialized service %s with no accessible sources; produced empty output", serviceID)
		return materializedOutputFromSources(mediaType, outputPath, sources, upstreamDerivations), nil
	}

	outputPath := filepath.Join(outputDir, outputName)
	if err := runOxigraph(
		s.cfg.OxigraphBinary,
		"query",
		"--location", storeDir,
		"--query", s.cfg.mediaProfileQuery(),
		"--results-file", outputPath,
		"--results-format", resultFormat,
	); err != nil {
		return materializedOutput{}, err
	}
	log.Printf("httpapi: materialized service %s (%d source(s) loaded, %d/%d profile source(s) accessible)", serviceID, len(sources), accessibleProfileSources, len(profileURLs))
	return materializedOutputFromSources(mediaType, outputPath, sources, upstreamDerivations), nil
}

func (s *Server) hasEnoughAccessibleProfileSources(accessible, total int) bool {
	if total == 0 {
		return true
	}
	return accessible >= s.cfg.minimumAccessibleSources() && float64(accessible)/float64(total) >= s.cfg.minimumAccessibleSourceRatio()
}

func outputMediaTypeForQueryType(queryType string) string {
	switch queryType {
	case "CONSTRUCT":
		return "text/turtle"
	case "SELECT":
		return "application/sparql-results+json"
	default:
		return ""
	}
}

func loadStagedSource(binary, storeDir string, source stagedSource) error {
	args := []string{"load", "--location", storeDir, "--file", source.Path}
	if source.Format != "" {
		args = append(args, "--format", source.Format)
	}
	return runOxigraph(binary, args...)
}

func materializedOutputFromSources(mediaType, outputPath string, sources []SourceMetadata, upstreamDerivations []upstreamDerivationEvidence) materializedOutput {
	output := materializedOutput{
		MediaType:           mediaType,
		Path:                outputPath,
		Sources:             sources,
		UpstreamDerivations: upstreamDerivations,
	}
	if len(upstreamDerivations) > 0 {
		output.UpstreamDerivation = upstreamDerivations[0]
	}
	return output
}

// sourceIndexPlaceholder is replaced in the media profile index query with the
// IRI of the requested index source, so discovery can be scoped to that exact
// subject instead of every subject sharing the same document.
const sourceIndexPlaceholder = "$sourceIndex$"

func (s *Server) queryMediaProfileIndex(storeDir, outputDir string, indexSourceURLs []string) ([]string, error) {
	query := s.cfg.mediaProfileIndexQuery()

	// When the configured index query references the source placeholder, the
	// caller wants discovery scoped to the exact requested IRI (e.g.
	// .../index#familyIndex) rather than every subject that happens to live in
	// the same document. Run the query once per index source, substituting the
	// placeholder with that source's IRI, and union the discovered URLs.
	if strings.Contains(query, sourceIndexPlaceholder) {
		seen := map[string]bool{}
		var urls []string
		for i, sourceURL := range indexSourceURLs {
			scoped := strings.ReplaceAll(query, sourceIndexPlaceholder, "<"+sourceURL+">")
			discovered, err := s.runMediaProfileIndexQuery(storeDir, outputDir, scoped, i)
			if err != nil {
				return nil, err
			}
			for _, u := range discovered {
				if !seen[u] {
					seen[u] = true
					urls = append(urls, u)
				}
			}
		}
		return urls, nil
	}

	return s.runMediaProfileIndexQuery(storeDir, outputDir, query, 0)
}

func (s *Server) runMediaProfileIndexQuery(storeDir, outputDir, query string, index int) ([]string, error) {
	resultsPath := filepath.Join(outputDir, fmt.Sprintf("media-profile-index-%d.srj", index))
	if err := runOxigraph(
		s.cfg.OxigraphBinary,
		"query",
		"--location", storeDir,
		"--query", query,
		"--results-file", resultsPath,
		"--results-format", "json",
	); err != nil {
		return nil, err
	}
	body, err := os.ReadFile(resultsPath)
	if err != nil {
		return nil, err
	}
	var results sparqlResultsJSON
	if err := json.Unmarshal(body, &results); err != nil {
		return nil, fmt.Errorf("decode media profile index query results: %w", err)
	}
	seen := map[string]bool{}
	var urls []string
	for _, row := range results.Results.Bindings {
		for _, binding := range row {
			if binding.Value == "" || binding.Type != "uri" || seen[binding.Value] {
				continue
			}
			seen[binding.Value] = true
			urls = append(urls, binding.Value)
		}
	}
	return urls, nil
}

func appendUniqueUpstreamDerivation(derivations []upstreamDerivationEvidence, derivation upstreamDerivationEvidence) []upstreamDerivationEvidence {
	for _, existing := range derivations {
		if existing.Issuer == derivation.Issuer && existing.DerivationResourceID == derivation.DerivationResourceID {
			return derivations
		}
	}
	return append(derivations, derivation)
}

func (s *Server) stageSource(stagingDir string, index int, rawURL string) (stagedSource, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return stagedSource{}, err
	}
	switch parsed.Scheme {
	case "http", "https":
		fetched, err := s.fetchHTTPSource(rawURL)
		if err != nil {
			return stagedSource{}, err
		}
		format := rdfFormatFromContentType(fetched.ContentType)
		if format == "" {
			format = rdfFormatFromPath(parsed.Path)
		}
		if format == "" {
			return stagedSource{}, fmt.Errorf("source %s is not an RDF document", rawURL)
		}
		path := filepath.Join(stagingDir, fmt.Sprintf("source-%d.%s", index, format))
		if err := os.WriteFile(path, fetched.Body, 0o644); err != nil {
			return stagedSource{}, err
		}
		return stagedSource{Path: path, Format: format, Metadata: SourceMetadata{
			URL:                 rawURL,
			MediaType:           rdfMediaType(format, fetched.ContentType),
			SHA256:              sha256Hex(fetched.Body),
			ETag:                fetched.ETag,
			Protected:           fetched.Protected,
			AuthorizationServer: fetched.AuthorizationServer,
			PermissionTicket:    fetched.Ticket,
		}, UpstreamDerivation: fetched.UpstreamDerivation}, nil
	case "file":
		return stageLocalSource(parsed.Path, rawURL)
	case "":
		return stageLocalSource(rawURL, rawURL)
	default:
		return stagedSource{}, fmt.Errorf("unsupported source URL scheme %q", parsed.Scheme)
	}
}

func (s *Server) fetchHTTPSource(rawURL string) (sourceHTTPResult, error) {
	resp, err := s.requestHTTPSource(http.MethodGet, rawURL, "")
	if err != nil {
		return sourceHTTPResult{}, err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return sourceHTTPResult{Body: resp.Body, ContentType: resp.ContentType, ETag: resp.ETag}, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return sourceHTTPResult{}, fmt.Errorf("source %s returned %d", rawURL, resp.StatusCode)
	}
	asURI, ticket, ok := parseUMAChallenge(resp.Challenge)
	if !ok {
		return sourceHTTPResult{}, inaccessibleSourceError{err: fmt.Errorf("source %s returned 401 without UMA challenge", rawURL)}
	}
	upstreamToken := s.cachedUpstreamToken(rawURL, asURI)
	var upstreamResponse upstreamTokenResponse
	if upstreamToken != "" {
		resp, err = s.requestHTTPSource(http.MethodGet, rawURL, upstreamToken)
		if err != nil {
			return sourceHTTPResult{}, err
		}
		if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
			return sourceHTTPResult{
				Body:                resp.Body,
				ContentType:         resp.ContentType,
				ETag:                resp.ETag,
				Protected:           true,
				AuthorizationServer: asURI,
				Ticket:              ticket,
				UpstreamDerivation:  upstreamDerivationEvidenceFrom(asURI, s.cachedUpstreamTokenResponse(rawURL, asURI)),
			}, nil
		}
	}
	upstreamToken, upstreamResponse, err = s.obtainUpstreamRPT(rawURL, asURI, ticket)
	if err != nil {
		return sourceHTTPResult{}, inaccessibleSourceError{err: err}
	}
	resp, err = s.requestHTTPSource(http.MethodGet, rawURL, upstreamToken)
	if err != nil {
		return sourceHTTPResult{}, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return sourceHTTPResult{}, inaccessibleSourceError{err: fmt.Errorf("source %s returned %d after UMA authorization", rawURL, resp.StatusCode)}
	}
	return sourceHTTPResult{
		Body:                resp.Body,
		ContentType:         resp.ContentType,
		ETag:                resp.ETag,
		Protected:           true,
		AuthorizationServer: asURI,
		Ticket:              ticket,
		UpstreamDerivation:  upstreamDerivationEvidenceFrom(asURI, upstreamResponse),
	}, nil
}

func (s *Server) serviceNeedsMaterialization(svc serviceInstance) (bool, error) {
	if svc.Status == "failed" && svc.ErrorMessage == insufficientUpstreamResourcesMessage {
		return true, nil
	}
	if svc.OutputPath == "" {
		return true, nil
	}
	if _, err := os.Stat(svc.OutputPath); err != nil {
		if os.IsNotExist(err) {
			return true, nil
		}
		return false, err
	}
	if len(svc.SourceMetadata) == 0 {
		return true, nil
	}
	sourceURLSeen := make(map[string]bool, len(svc.SourceMetadata))
	for _, metadata := range svc.SourceMetadata {
		sourceURLSeen[metadata.URL] = true
		if metadata.ETag == "" {
			continue
		}
		currentETag, err := s.currentHTTPSourceETag(metadata.URL, metadata)
		if err != nil {
			return false, err
		}
		if currentETag == "" || currentETag != metadata.ETag {
			return true, nil
		}
	}
	for _, sourceURL := range svc.SourceURLs {
		if !sourceURLSeen[sourceURL] {
			return true, nil
		}
	}
	return false, nil
}

func (s *Server) currentHTTPSourceETag(rawURL string, metadata SourceMetadata) (string, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return "", err
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", nil
	}
	token := ""
	if metadata.AuthorizationServer != "" {
		token = s.cachedUpstreamToken(rawURL, metadata.AuthorizationServer)
	}
	resp, err := s.requestHTTPSource(http.MethodHead, rawURL, token)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return resp.ETag, nil
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return "", nil
	}
	asURI, ticket, ok := parseUMAChallenge(resp.Challenge)
	if !ok {
		return "", nil
	}
	upstreamToken, _, err := s.obtainUpstreamRPT(rawURL, asURI, ticket)
	if err != nil {
		return "", err
	}
	resp, err = s.requestHTTPSource(http.MethodHead, rawURL, upstreamToken)
	if err != nil {
		return "", err
	}
	if resp.StatusCode >= 200 && resp.StatusCode <= 299 {
		return resp.ETag, nil
	}
	return "", nil
}

func (s *Server) cachedUpstreamToken(sourceURL, asURI string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstreamTokens[upstreamTokenCacheKey(sourceURL, asURI)].AccessToken
}

func (s *Server) cachedUpstreamTokenResponse(sourceURL, asURI string) upstreamTokenResponse {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstreamTokens[upstreamTokenCacheKey(sourceURL, asURI)].Response
}

func (s *Server) cachedUpstreamDerivationResourceID(sourceURL, asURI string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.upstreamTokens[upstreamTokenCacheKey(sourceURL, asURI)].DerivationResourceID
}

func (s *Server) storeUpstreamToken(sourceURL, asURI, ticket string, response upstreamTokenResponse) {
	derivationResourceID := response.DerivationResourceID
	if derivationResourceID == "" {
		derivationResourceID = s.cachedUpstreamDerivationResourceID(sourceURL, asURI)
	}
	s.mu.Lock()
	s.upstreamTokens[upstreamTokenCacheKey(sourceURL, asURI)] = cachedUpstreamToken{
		AccessToken:          response.AccessToken,
		AuthorizationServer:  asURI,
		Ticket:               ticket,
		DerivationResourceID: derivationResourceID,
		Response:             response,
	}
	s.mu.Unlock()
}

func upstreamTokenCacheKey(sourceURL, asURI string) string {
	return asURI + "\x00" + sourceURL
}

type sourceHTTPResponse struct {
	Body        []byte
	ContentType string
	ETag        string
	Challenge   string
	StatusCode  int
}

func (s *Server) requestHTTPSource(method, rawURL, token string) (sourceHTTPResponse, error) {
	log.Printf("httpapi: requesting upstream source %s %s (token-present=%t)", method, rawURL, token != "")
	req, err := http.NewRequest(method, rawURL, nil)
	if err != nil {
		log.Printf("httpapi: failed to build upstream source request for %s: %v", rawURL, err)
		return sourceHTTPResponse{}, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := s.cfg.SourceHTTPClient
	if client == nil {
		client = &http.Client{Timeout: 30 * time.Second}
	}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("httpapi: upstream source request failed for %s: %v", rawURL, err)
		return sourceHTTPResponse{}, err
	}
	body, err := io.ReadAll(resp.Body)
	closeErr := resp.Body.Close()
	if err != nil {
		log.Printf("httpapi: reading upstream source response failed for %s: %v", rawURL, err)
		return sourceHTTPResponse{}, err
	}
	if closeErr != nil {
		log.Printf("httpapi: closing upstream source response failed for %s: %v", rawURL, closeErr)
		return sourceHTTPResponse{}, closeErr
	}
	log.Printf("httpapi: upstream source response %s -> %d", rawURL, resp.StatusCode)
	return sourceHTTPResponse{
		Body:        body,
		ContentType: resp.Header.Get("Content-Type"),
		ETag:        resp.Header.Get("ETag"),
		Challenge:   resp.Header.Get("WWW-Authenticate"),
		StatusCode:  resp.StatusCode,
	}, nil
}

func (s *Server) obtainUpstreamRPT(sourceURL, asURI, ticket string) (string, upstreamTokenResponse, error) {
	if s.cfg.hasAccountCredentials() {
		if s.accountTokenError != nil {
			return "", upstreamTokenResponse{}, s.accountTokenError
		}
		if s.accountAccessToken == "" {
			return "", upstreamTokenResponse{}, fmt.Errorf("account access token is not available")
		}
		derivationResourceID := s.cachedUpstreamDerivationResourceID(sourceURL, asURI)
		upstreamToken, err := s.cfg.requestUMAAccessToken(asURI, ticket, s.accountAccessToken, derivationResourceID)
		if err != nil {
			if requestErr := s.submitUpstreamAccessRequest(sourceURL, asURI, http.MethodGet); requestErr != nil {
				return "", upstreamTokenResponse{}, fmt.Errorf("UMA token request failed (%v) and access request failed (%v)", err, requestErr)
			}
			return "", upstreamTokenResponse{}, fmt.Errorf("UMA token request failed for %s; access request submitted to %s", sourceURL, joinURL(asURI, "/requests"))
		}
		s.storeUpstreamToken(sourceURL, asURI, ticket, upstreamToken)
		return s.recordUpstreamAccess(sourceURL, asURI, ticket, upstreamToken.AccessToken), upstreamToken, nil
	}
	upstreamToken := s.cfg.UpstreamRPT
	if upstreamToken == "" {
		return "", upstreamTokenResponse{}, fmt.Errorf("upstream UMA authorization failed for %s", sourceURL)
	}
	s.storeUpstreamToken(sourceURL, asURI, ticket, upstreamTokenResponse{AccessToken: upstreamToken})
	return s.recordUpstreamAccess(sourceURL, asURI, ticket, upstreamToken), upstreamTokenResponse{}, nil
}

func (s *Server) submitUpstreamAccessRequest(resourceURL, asURI, method string) error {
	requestingParty := s.cfg.provisionSubject()
	if requestingParty == "" {
		log.Printf("httpapi: cannot submit upstream access request for %s: missing requesting party WebID", resourceURL)
		return fmt.Errorf("requesting party WebID is not configured")
	}
	action := odrlActionLocalForHTTPMethod(method)
	requestURL := joinURL(asURI, "/requests")
	body := accessRequestTurtle(asURI, resourceURL, requestingParty, action)
	log.Printf("httpapi: submitting upstream access request to %s for %s (action=%s requestingParty=%s)", requestURL, resourceURL, action, requestingParty)

	req, err := http.NewRequest(http.MethodPost, requestURL, strings.NewReader(body))
	if err != nil {
		log.Printf("httpapi: failed to build upstream access request for %s: %v", resourceURL, err)
		return err
	}
	req.Header.Set("Authorization", "WebID "+url.QueryEscape(requestingParty))
	req.Header.Set("Content-Type", "text/turtle")

	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		log.Printf("httpapi: upstream access request failed for %s: %v", resourceURL, err)
		return err
	}
	if status < 200 || status > 299 {
		log.Printf("httpapi: upstream access request for %s returned %d", resourceURL, status)
		return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	log.Printf("httpapi: upstream access request recorded for %s", resourceURL)
	s.recordUpstreamAccessRequest(resourceURL, asURI, requestingParty, "odrl:"+action, requestURL)
	return nil
}

func accessRequestTurtle(asURI, resourceURL, requestingParty, action string) string {
	sum := sha256.Sum256([]byte(resourceURL + "\x00" + requestingParty + "\x00" + action))
	requestID := joinURL(asURI, "/access-requests/"+hex.EncodeToString(sum[:8]))
	return fmt.Sprintf(`@prefix sotw: <https://w3id.org/force/sotw#> .
@prefix odrl: <http://www.w3.org/ns/odrl/2/> .
@prefix ex: <http://example.org/> .

<%s> a sotw:EvaluationRequest ;
  sotw:requestedTarget <%s> ;
  sotw:requestedAction odrl:%s ;
  sotw:requestingParty <%s> ;
  ex:requestStatus ex:requested .
`, requestID, resourceURL, action, requestingParty)
}

func odrlActionLocalForHTTPMethod(method string) string {
	switch strings.ToUpper(method) {
	case http.MethodDelete:
		return "delete"
	case http.MethodPatch, http.MethodPost, http.MethodPut:
		return "write"
	default:
		return "read"
	}
}

func (s *Server) recordUpstreamAccess(sourceURL, asURI, ticket, upstreamToken string) string {
	access := UpstreamAccessEvidence{
		SourceURL:           sourceURL,
		AuthorizationServer: asURI,
		Ticket:              ticket,
		Token:               upstreamToken,
	}
	s.mu.Lock()
	s.upstreamAccesses = append(s.upstreamAccesses, access)
	s.mu.Unlock()
	return upstreamToken
}

func (s *Server) recordUpstreamAccessRequest(resourceURL, asURI, requestingParty, action, requestURL string) {
	request := UpstreamAccessRequestEvidence{
		ResourceURL:         resourceURL,
		AuthorizationServer: asURI,
		RequestingParty:     requestingParty,
		Action:              action,
		RequestURL:          requestURL,
	}
	s.mu.Lock()
	s.upstreamAccessRequests = append(s.upstreamAccessRequests, request)
	s.mu.Unlock()
}

func stageLocalSource(path, rawURL string) (stagedSource, error) {
	format := rdfFormatFromPath(path)
	if format == "" {
		return stagedSource{}, fmt.Errorf("source %s is not an RDF document", rawURL)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return stagedSource{}, err
	}
	return stagedSource{Path: path, Format: format, Metadata: SourceMetadata{
		URL:       rawURL,
		MediaType: rdfMediaType(format, ""),
		SHA256:    sha256Hex(body),
	}}, nil
}

func parseUMAChallenge(header string) (string, string, bool) {
	if !strings.HasPrefix(header, "UMA ") {
		return "", "", false
	}
	params := map[string]string{}
	for _, part := range strings.Split(strings.TrimPrefix(header, "UMA "), ",") {
		key, value, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok {
			continue
		}
		params[strings.ToLower(key)] = strings.Trim(value, `"`)
	}
	asURI := params["as_uri"]
	ticket := params["ticket"]
	return asURI, ticket, asURI != "" && ticket != ""
}

func rdfFormatFromContentType(contentType string) string {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	switch mediaType {
	case "application/n-triples":
		return "nt"
	case "text/turtle":
		return "ttl"
	case "application/n-quads":
		return "nq"
	case "application/trig":
		return "trig"
	case "application/rdf+xml":
		return "rdf"
	case "application/ld+json":
		return "jsonld"
	default:
		return ""
	}
}

func rdfFormatFromPath(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".nt":
		return "nt"
	case ".ttl":
		return "ttl"
	case ".nq":
		return "nq"
	case ".trig":
		return "trig"
	case ".rdf", ".xml":
		return "rdf"
	case ".jsonld":
		return "jsonld"
	default:
		return ""
	}
}

func rdfMediaType(format, contentType string) string {
	mediaType := strings.ToLower(strings.TrimSpace(strings.Split(contentType, ";")[0]))
	if mediaType != "" {
		return mediaType
	}
	switch format {
	case "nt":
		return "application/n-triples"
	case "ttl":
		return "text/turtle"
	case "nq":
		return "application/n-quads"
	case "trig":
		return "application/trig"
	case "rdf":
		return "application/rdf+xml"
	case "jsonld":
		return "application/ld+json"
	default:
		return ""
	}
}

func sha256Hex(body []byte) string {
	sum := sha256.Sum256(body)
	return fmt.Sprintf("%x", sum[:])
}

func runOxigraph(binary string, args ...string) error {
	output, err := exec.Command(binary, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("oxigraph %s failed: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeJSONLD(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/ld+json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
