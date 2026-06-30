package httpapi

import (
	"bytes"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const (
	odrlNS              = "http://www.w3.org/ns/odrl/2/"
	odrlPermission      = odrlNS + "permission"
	odrlTarget          = odrlNS + "target"
	odrlAction          = odrlNS + "action"
	odrlAssignee        = odrlNS + "assignee"
	odrlAssigner        = odrlNS + "assigner"
	odrlSet             = odrlNS + "Set"
	odrlAgreement       = odrlNS + "Agreement"
	odrlPermissionClass = odrlNS + "Permission"
)

type PolicySyncEvidence struct {
	ResourceID string   `json:"resource_id"`
	PolicyID   string   `json:"policy_id"`
	RuleID     string   `json:"rule_id"`
	Action     string   `json:"action"`
	Public     bool     `json:"public"`
	Assignee   string   `json:"assignee,omitempty"`
	Created    bool     `json:"created"`
	Patched    bool     `json:"patched"`
	Scopes     []string `json:"scopes,omitempty"`
}

type resourceOwnerAssetsResponse struct {
	Assets []resourceOwnerAsset `json:"assets"`
}

type resourceOwnerAsset struct {
	ID          string `json:"_id"`
	Description struct {
		Name           string   `json:"name"`
		ResourceScopes []string `json:"resource_scopes"`
	} `json:"description"`
	Scopes []string `json:"scopes"`
	Policy struct {
		PolicyURI string `json:"policy_uri"`
		Status    string `json:"status"`
	} `json:"policy"`
}

type desiredODRLRule struct {
	ResourceID string
	PolicyID   string
	PolicyType string
	RuleID     string
	Action     string
	Assigner   string
	Assignee   string
	Public     bool
	Scopes     []string
}

func (s *Server) syncConfiguredAuthorizationPolicies() error {
	if !s.shouldUseLiveAuthorizationServer() {
		return nil
	}
	if s.accountTokenError != nil {
		return s.accountTokenError
	}
	if s.accountAccessToken == "" {
		return fmt.Errorf("account access token is not available for policy synchronization")
	}
	owner := s.cfg.provisionSubject()
	if owner == "" {
		return fmt.Errorf("cannot synchronize policies without configured resource owner identity")
	}

	assets, err := s.discoverResourceOwnerAssets()
	if err != nil {
		return err
	}
	if len(assets) == 0 {
		return nil
	}
	policies, err := s.fetchAuthorizationPolicies()
	if err != nil {
		return err
	}
	for _, asset := range assets {
		if asset.ID == "" {
			continue
		}
		aggSubject := s.policySyncAggregatorSubject(asset, owner)
		for _, rule := range s.desiredODRLRules(asset, owner, aggSubject) {
			if odrlRuleExists(policies, rule) {
				continue
			}
			policyID := findODRLPolicyForResource(policies, rule.ResourceID, rule.PolicyType)
			if policyID == "" {
				if rule.PolicyID != "" {
					policyID = rule.PolicyID
				} else {
					policyID = generatedPolicyID(s.cfg.authorizationServerURL(), rule.ResourceID, rule.PolicyType)
				}
				rule.PolicyID = policyID
				if err := s.createAuthorizationPolicy(rule); err != nil {
					return err
				}
				policies = append(policies, desiredRuleTriples(rule)...)
				s.recordPolicySync(rule, true, false)
				continue
			}
			rule.PolicyID = policyID
			if rule.RuleID == "" || !strings.HasPrefix(rule.RuleID, policyID+"#") {
				rule.RuleID = generatedRuleID(policyID, rule)
			}
			if err := s.patchAuthorizationPolicy(rule); err != nil {
				return err
			}
			policies = append(policies, desiredRuleTriples(rule)...)
			s.recordPolicySync(rule, false, true)
		}
	}
	return nil
}

func (s *Server) policySyncAggregatorSubject(asset resourceOwnerAsset, fallback string) string {
	for _, resourceID := range []string{
		asset.Description.Name,
		s.resourceURLForAuthorizationResourceID(asset.ID),
		asset.ID,
	} {
		if subject := s.knownAggregatorSubjectForResource(resourceID); subject != "" {
			return subject
		}
	}
	if s.cfg.Subject != "" {
		return s.cfg.Subject
	}
	return fallback
}

func (s *Server) resourceURLForAuthorizationResourceID(authorizationResourceID string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	for resourceURL, registeredAuthorizationResourceID := range s.authorizationResourceIDs {
		if registeredAuthorizationResourceID == authorizationResourceID {
			return resourceURL
		}
	}
	return ""
}

func (s *Server) knownAggregatorSubjectForResource(resourceID string) string {
	prefix := s.cfg.absolute("/aggregators/")
	if !strings.HasPrefix(resourceID, prefix) {
		return ""
	}
	remainder := strings.TrimPrefix(resourceID, prefix)
	aggID := remainder
	if slash := strings.IndexByte(remainder, '/'); slash >= 0 {
		aggID = remainder[:slash]
	}
	if aggID == "" {
		return ""
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	return s.aggregators[aggID].Subject
}

func (s *Server) discoverResourceOwnerAssets() ([]resourceOwnerAsset, error) {
	discoveryURL := joinURL(s.cfg.authorizationServerURL(), "/resource-owner/assets") + "?include=description,scopes,policy_uri,policies"
	req, err := http.NewRequest(http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+s.accountAccessToken)

	var response resourceOwnerAssetsResponse
	if err := s.doAuthorizationServerJSON(req, http.StatusOK, &response); err != nil {
		return nil, err
	}
	return response.Assets, nil
}

func (s *Server) fetchAuthorizationPolicies() ([]turtleTriple, error) {
	req, err := http.NewRequest(http.MethodGet, joinURL(s.cfg.authorizationServerURL(), "/policies"), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "text/turtle")
	req.Header.Set("Authorization", "Bearer "+s.accountAccessToken)

	status, body, err := s.doAuthorizationServer(req)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, nil
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(body)))
	}
	return parseTurtleTriples(string(body))
}

func (s *Server) desiredODRLRules(asset resourceOwnerAsset, owner, aggSubject string) []desiredODRLRule {
	scopes := assetScopes(asset)
	rules := make([]desiredODRLRule, 0, len(scopes))
	for _, scope := range scopes {
		action := odrlActionForScope(scope)
		if action == "" {
			continue
		}
		if isReadScope(scope) {
			policyID := generatedPolicyID(s.cfg.authorizationServerURL(), asset.ID, odrlSet)
			rule := desiredODRLRule{
				ResourceID: asset.ID,
				PolicyID:   policyID,
				PolicyType: odrlSet,
				RuleID:     policyID + "#public-read",
				Action:     action,
				Assigner:   owner,
				Public:     true,
				Scopes:     []string{scope},
			}
			rules = append(rules, rule)
			continue
		}
		policyID := generatedPolicyID(s.cfg.authorizationServerURL(), asset.ID, odrlAgreement)
		rule := desiredODRLRule{
			ResourceID: asset.ID,
			PolicyID:   policyID,
			PolicyType: odrlAgreement,
			RuleID:     generatedRuleID(policyID, desiredODRLRule{Action: action, Assignee: aggSubject}),
			Action:     action,
			Assigner:   owner,
			Assignee:   aggSubject,
			Public:     false,
			Scopes:     []string{scope},
		}
		rules = append(rules, rule)
	}
	return rules
}

func (s *Server) createAuthorizationPolicy(rule desiredODRLRule) error {
	body := authorizationPolicyTurtle(rule)
	req, err := http.NewRequest(http.MethodPost, joinURL(s.cfg.authorizationServerURL(), "/policies"), strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.accountAccessToken)
	req.Header.Set("Content-Type", "text/turtle")
	req.Header.Set("Accept", "application/json, text/turtle")

	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
		return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (s *Server) patchAuthorizationPolicy(rule desiredODRLRule) error {
	body := authorizationPolicyPatch(rule)
	patchURL := joinURL(s.cfg.authorizationServerURL(), "/policies/"+url.PathEscape(rule.PolicyID))
	req, err := http.NewRequest(http.MethodPatch, patchURL, bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.accountAccessToken)
	req.Header.Set("Content-Type", "application/sparql-update")
	req.Header.Set("Accept", "application/json, text/turtle")

	status, responseBody, err := s.doAuthorizationServer(req)
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated && status != http.StatusNoContent {
		return fmt.Errorf("%s %s returned %d: %s", req.Method, req.URL.String(), status, strings.TrimSpace(string(responseBody)))
	}
	return nil
}

func (s *Server) recordPolicySync(rule desiredODRLRule, created, patched bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policySyncs = append(s.policySyncs, PolicySyncEvidence{
		ResourceID: rule.ResourceID,
		PolicyID:   rule.PolicyID,
		RuleID:     rule.RuleID,
		Action:     rule.Action,
		Public:     rule.Public,
		Assignee:   rule.Assignee,
		Created:    created,
		Patched:    patched,
		Scopes:     append([]string(nil), rule.Scopes...),
	})
}

func parseTurtleTriples(body string) ([]turtleTriple, error) {
	if strings.TrimSpace(body) == "" {
		return nil, nil
	}
	prefixes, withoutPrefixes := turtlePrefixes(body)
	tokens, err := tokenizeTurtle(withoutPrefixes)
	if err != nil {
		return nil, err
	}
	parser := &turtleParser{tokens: tokens, prefixes: prefixes}
	if err := parser.parseDocument(); err != nil {
		return nil, err
	}
	return parser.triples, nil
}

func odrlRuleExists(triples []turtleTriple, rule desiredODRLRule) bool {
	for _, triple := range triples {
		if triple.predicate != odrlPermission || !policyHasType(triples, triple.subject, rule.PolicyType) {
			continue
		}
		candidate := triple.object
		if !hasTriple(triples, candidate, odrlTarget, rule.ResourceID) ||
			!hasTriple(triples, candidate, odrlAction, rule.Action) ||
			!hasTriple(triples, candidate, odrlAssigner, rule.Assigner) {
			continue
		}
		assignee := singleObject(triples, candidate, odrlAssignee)
		if rule.Public && assignee == "" {
			return true
		}
		if !rule.Public && assignee == rule.Assignee {
			return true
		}
	}
	return false
}

func findODRLPolicyForResource(triples []turtleTriple, resourceID, policyType string) string {
	for _, triple := range triples {
		if triple.predicate != odrlPermission || !policyHasType(triples, triple.subject, policyType) {
			continue
		}
		if strings.HasPrefix(triple.subject, "_:") {
			continue
		}
		if hasTriple(triples, triple.object, odrlTarget, resourceID) {
			return triple.subject
		}
	}
	return ""
}

func policyHasType(triples []turtleTriple, policyID, policyType string) bool {
	return hasTriple(triples, policyID, rdfType, policyType)
}

func desiredRuleTriples(rule desiredODRLRule) []turtleTriple {
	triples := []turtleTriple{
		{subject: rule.PolicyID, predicate: rdfType, object: rule.PolicyType, objectKind: "iri"},
		{subject: rule.PolicyID, predicate: odrlPermission, object: rule.RuleID, objectKind: "iri"},
		{subject: rule.RuleID, predicate: rdfType, object: odrlPermissionClass, objectKind: "iri"},
		{subject: rule.RuleID, predicate: odrlTarget, object: rule.ResourceID, objectKind: "iri"},
		{subject: rule.RuleID, predicate: odrlAction, object: rule.Action, objectKind: "iri"},
		{subject: rule.RuleID, predicate: odrlAssigner, object: rule.Assigner, objectKind: "iri"},
	}
	if rule.Assignee != "" {
		triples = append(triples, turtleTriple{subject: rule.RuleID, predicate: odrlAssignee, object: rule.Assignee, objectKind: "iri"})
	}
	return triples
}

func authorizationPolicyTurtle(rule desiredODRLRule) string {
	return fmt.Sprintf(`@prefix odrl: <http://www.w3.org/ns/odrl/2/> .

<%s> a <%s> ;
  odrl:uid <%s> ;
  odrl:permission <%s> .

%s`, rule.PolicyID, rule.PolicyType, rule.PolicyID, rule.RuleID, odrlRuleTurtle(rule))
}

func authorizationPolicyPatch(rule desiredODRLRule) string {
	return fmt.Sprintf(`PREFIX odrl: <http://www.w3.org/ns/odrl/2/>

INSERT {
  <%s> odrl:permission <%s> .

%s}
WHERE {}`, rule.PolicyID, rule.RuleID, indentTurtle(odrlRuleTurtle(rule), "  "))
}

func odrlRuleTurtle(rule desiredODRLRule) string {
	var builder strings.Builder
	fmt.Fprintf(&builder, "<%s> a odrl:Permission ;\n", rule.RuleID)
	fmt.Fprintf(&builder, "  odrl:target <%s> ;\n", rule.ResourceID)
	fmt.Fprintf(&builder, "  odrl:action <%s> ;\n", rule.Action)
	if rule.Assignee != "" {
		fmt.Fprintf(&builder, "  odrl:assignee <%s> ;\n", rule.Assignee)
	}
	fmt.Fprintf(&builder, "  odrl:assigner <%s> .\n", rule.Assigner)
	return builder.String()
}

func indentTurtle(body, prefix string) string {
	lines := strings.Split(body, "\n")
	for i, line := range lines {
		if line != "" {
			lines[i] = prefix + line
		}
	}
	return strings.Join(lines, "\n")
}

func assetScopes(asset resourceOwnerAsset) []string {
	scopes := asset.Description.ResourceScopes
	if len(scopes) == 0 {
		scopes = asset.Scopes
	}
	seen := map[string]bool{}
	unique := make([]string, 0, len(scopes))
	for _, scope := range scopes {
		if scope == "" || seen[scope] {
			continue
		}
		seen[scope] = true
		unique = append(unique, scope)
	}
	return unique
}

func odrlActionForScope(scope string) string {
	if scope == "" {
		return ""
	}
	local := scope
	if index := strings.LastIndexAny(scope, ":/#"); index >= 0 && index+1 < len(scope) {
		local = scope[index+1:]
	}
	if local == "" {
		return ""
	}
	return odrlNS + local
}

func isReadScope(scope string) bool {
	return odrlActionForScope(scope) == odrlNS+"read"
}

func generatedPolicyID(asURL, resourceID, policyType string) string {
	kind := "agreement"
	if policyType == odrlSet {
		kind = "public"
	}
	return joinURL(asURL, "/policies/"+kind+"/"+url.PathEscape(resourceID))
}

func generatedRuleID(policyID string, rule desiredODRLRule) string {
	localAction := strings.TrimPrefix(rule.Action, odrlNS)
	if rule.Public {
		return policyID + "#public-" + localAction
	}
	return policyID + "#owner-" + localAction
}

func clonePolicySyncEvidence(entries []PolicySyncEvidence) []PolicySyncEvidence {
	cloned := make([]PolicySyncEvidence, len(entries))
	for i, entry := range entries {
		cloned[i] = entry
		cloned[i].Scopes = append([]string(nil), entry.Scopes...)
	}
	return cloned
}
