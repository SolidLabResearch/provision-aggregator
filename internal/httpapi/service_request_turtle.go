package httpapi

import (
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
)

const (
	rdfType               = "http://www.w3.org/1999/02/22-rdf-syntax-ns#type"
	aggrService           = "https://w3id.org/aggregator#Service"
	aggrPerforms          = "https://w3id.org/aggregator#performs"
	aggrApplies           = "https://w3id.org/aggregator#applies"
	fnoAppliedFunction    = "https://w3id.org/function/ontology#AppliedFunction"
	fnocApplies           = "https://w3id.org/function/vocabulary/composition#applies"
	fnocParameterBindings = "https://w3id.org/function/vocabulary/composition#parameterBindings"
	fnocBoundParameter    = "https://w3id.org/function/vocabulary/composition#boundParameter"
	fnocBoundToTerm       = "https://w3id.org/function/vocabulary/composition#boundToTerm"
	legacyFnocApplies     = "https://fno.io/vocabulary/composition/0.1.0/applies"
	legacyFnocBindings    = "https://fno.io/vocabulary/composition/0.1.0/parameterBindings"
	legacyFnocParameter   = "https://fno.io/vocabulary/composition/0.1.0/boundParameter"
	legacyFnocBoundTerm   = "https://fno.io/vocabulary/composition/0.1.0/boundToTerm"
	syntheticListMember   = "urn:aggregator-provision:parser:listMember"
)

var errUnsupportedServiceContentType = errors.New("unsupported service content type")

type turtleToken struct {
	kind  string
	value string
}

type turtleTriple struct {
	subject    string
	predicate  string
	object     string
	objectKind string
}

type turtleParser struct {
	tokens    []turtleToken
	prefixes  map[string]string
	index     int
	nextBlank int
	nextList  int
	triples   []turtleTriple
}

func parseCreateServiceRequestTurtle(cfg Config, body string) (createServiceRequest, error) {
	prefixes, withoutPrefixes := turtlePrefixes(body)
	tokens, err := tokenizeTurtle(withoutPrefixes)
	if err != nil {
		return createServiceRequest{}, err
	}
	parser := &turtleParser{tokens: tokens, prefixes: prefixes}
	if err := parser.parseDocument(); err != nil {
		return createServiceRequest{}, err
	}
	return serviceRequestFromTriples(cfg, parser.triples)
}

func serviceRequestFromTriples(cfg Config, triples []turtleTriple) (createServiceRequest, error) {
	services := subjectsWithObject(triples, rdfType, aggrService)
	if len(services) != 1 {
		return createServiceRequest{}, fmt.Errorf("service deployment must describe exactly one aggr:Service")
	}
	serviceSubject := services[0]
	if strings.HasPrefix(serviceSubject, "_:") {
		// Blank node service subjects are explicitly allowed.
	} else if parsed, err := url.Parse(serviceSubject); err != nil || !parsed.IsAbs() {
		return createServiceRequest{}, fmt.Errorf("service subject must be a blank node or absolute URI")
	}

	transformation := singleObject(triples, serviceSubject, aggrPerforms)
	if transformation == "" {
		return createServiceRequest{}, fmt.Errorf("service deployment must include aggr:performs")
	}
	if transformation != supportedTransformationURL(cfg) {
		return createServiceRequest{}, fmt.Errorf("service deployment references unsupported transformation")
	}

	appliedFunction := singleObject(triples, serviceSubject, aggrApplies)
	if appliedFunction == "" {
		return createServiceRequest{}, fmt.Errorf("service deployment must include aggr:applies for required parameters")
	}
	if !hasTriple(triples, appliedFunction, rdfType, fnoAppliedFunction) {
		return createServiceRequest{}, fmt.Errorf("aggr:applies must reference an fno:AppliedFunction")
	}
	if appliedTransformation := singleObjectAny(triples, appliedFunction, fnocApplies, legacyFnocApplies); appliedTransformation != transformation {
		return createServiceRequest{}, fmt.Errorf("applied function must apply same transformation as aggr:performs")
	}

	bindingsList := singleObjectAny(triples, appliedFunction, fnocParameterBindings, legacyFnocBindings)
	if bindingsList == "" {
		return createServiceRequest{}, fmt.Errorf("applied function must include parameter bindings")
	}

	bindings := listMembers(triples, bindingsList)
	var req createServiceRequest
	req.Transformation = transformation
	for _, binding := range bindings {
		parameter := singleObjectAny(triples, binding, fnocBoundParameter, legacyFnocParameter)
		value := singleObjectAny(triples, binding, fnocBoundToTerm, legacyFnocBoundTerm)
		if parameter == "" || value == "" {
			return createServiceRequest{}, fmt.Errorf("parameter binding must include boundParameter and boundToTerm")
		}
		switch parameter {
		case cfg.absolute(cfg.TransformationCatalogPath) + "#QueryParameter", cfg.absolute(cfg.TransformationCatalogPath) + "#Query":
			req.Query = value
		case transformationSourceParameterURL(cfg), cfg.absolute(cfg.TransformationCatalogPath) + "#SourceParameter", cfg.absolute(cfg.TransformationCatalogPath) + "#Sources", cfg.absolute(cfg.TransformationCatalogPath) + "#Source":
			req.SourceURLs = append(req.SourceURLs, value)
		}
	}
	if len(req.SourceURLs) == 0 {
		return createServiceRequest{}, fmt.Errorf("applied function is missing required source binding")
	}
	req.Query = cfg.mediaProfileQuery()
	return req, nil
}

func (p *turtleParser) parseDocument() error {
	for p.index < len(p.tokens) {
		if p.accept(".") {
			continue
		}
		subject, _, err := p.parseObject()
		if err != nil {
			return err
		}
		if err := p.parsePredicateObjectList(subject); err != nil {
			return err
		}
		if !p.accept(".") && p.index < len(p.tokens) {
			return fmt.Errorf("expected '.'")
		}
	}
	return nil
}

func (p *turtleParser) parsePredicateObjectList(subject string) error {
	for {
		if p.peekValue("]") || p.peekValue(".") {
			return nil
		}
		predicate, err := p.parsePredicate()
		if err != nil {
			return err
		}
		for {
			object, objectKind, err := p.parseObject()
			if err != nil {
				return err
			}
			p.triples = append(p.triples, turtleTriple{
				subject: subject, predicate: predicate, object: object, objectKind: objectKind,
			})
			if !p.accept(",") {
				break
			}
		}
		if !p.accept(";") {
			return nil
		}
		for p.accept(";") {
		}
		if p.peekValue("]") || p.peekValue(".") {
			return nil
		}
	}
}

func (p *turtleParser) parsePredicate() (string, error) {
	token, ok := p.next()
	if !ok {
		return "", fmt.Errorf("expected predicate")
	}
	if token.value == "a" {
		return rdfType, nil
	}
	return expandTurtleToken(p.prefixes, token)
}

func (p *turtleParser) parseObject() (string, string, error) {
	token, ok := p.next()
	if !ok {
		return "", "", fmt.Errorf("expected object")
	}
	switch token.value {
	case "[":
		blank := p.newBlankNode()
		if !p.accept("]") {
			if err := p.parsePredicateObjectList(blank); err != nil {
				return "", "", err
			}
			if !p.accept("]") {
				return "", "", fmt.Errorf("expected ']'")
			}
		}
		return blank, "blank", nil
	case "(":
		list := p.newListNode()
		for !p.accept(")") {
			if p.index >= len(p.tokens) {
				return "", "", fmt.Errorf("unterminated RDF list")
			}
			member, memberKind, err := p.parseObject()
			if err != nil {
				return "", "", err
			}
			p.triples = append(p.triples, turtleTriple{
				subject: list, predicate: syntheticListMember, object: member, objectKind: memberKind,
			})
		}
		return list, "list", nil
	default:
		value, err := expandTurtleToken(p.prefixes, token)
		if err != nil {
			return "", "", err
		}
		return value, token.kind, nil
	}
}

func (p *turtleParser) next() (turtleToken, bool) {
	if p.index >= len(p.tokens) {
		return turtleToken{}, false
	}
	token := p.tokens[p.index]
	p.index++
	return token, true
}

func (p *turtleParser) accept(value string) bool {
	if !p.peekValue(value) {
		return false
	}
	p.index++
	return true
}

func (p *turtleParser) peekValue(value string) bool {
	return p.index < len(p.tokens) && p.tokens[p.index].value == value
}

func (p *turtleParser) newBlankNode() string {
	p.nextBlank++
	return fmt.Sprintf("_:b%d", p.nextBlank)
}

func (p *turtleParser) newListNode() string {
	p.nextList++
	return fmt.Sprintf("_:list%d", p.nextList)
}

func subjectsWithObject(triples []turtleTriple, predicate, object string) []string {
	var subjects []string
	seen := map[string]bool{}
	for _, triple := range triples {
		if triple.predicate == predicate && triple.object == object && !seen[triple.subject] {
			subjects = append(subjects, triple.subject)
			seen[triple.subject] = true
		}
	}
	return subjects
}

func singleObject(triples []turtleTriple, subject, predicate string) string {
	for _, triple := range triples {
		if triple.subject == subject && triple.predicate == predicate {
			return triple.object
		}
	}
	return ""
}

func singleObjectAny(triples []turtleTriple, subject string, predicates ...string) string {
	for _, predicate := range predicates {
		if object := singleObject(triples, subject, predicate); object != "" {
			return object
		}
	}
	return ""
}

func hasTriple(triples []turtleTriple, subject, predicate, object string) bool {
	for _, triple := range triples {
		if triple.subject == subject && triple.predicate == predicate && triple.object == object {
			return true
		}
	}
	return false
}

func listMembers(triples []turtleTriple, list string) []string {
	var members []string
	for _, triple := range triples {
		if triple.subject == list && triple.predicate == syntheticListMember {
			members = append(members, triple.object)
		}
	}
	return members
}

func turtlePrefixes(body string) (map[string]string, string) {
	prefixes := map[string]string{
		"aggr": "https://w3id.org/aggregator#",
		"dcat": "http://www.w3.org/ns/dcat#",
		"fno":  "https://w3id.org/function/ontology#",
		"fnoc": "https://w3id.org/function/vocabulary/composition#",
		"odrl": "http://www.w3.org/ns/odrl/2/",
		"rdf":  "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
	}
	prefixRE := regexp.MustCompile(`(?im)^\s*(?:@prefix|prefix)\s+([A-Za-z][A-Za-z0-9_-]*|):\s*<([^>]+)>\s*\.\s*$`)
	for _, match := range prefixRE.FindAllStringSubmatch(body, -1) {
		prefixes[strings.TrimSuffix(match[1], ":")] = match[2]
	}
	return prefixes, prefixRE.ReplaceAllString(body, "")
}

func tokenizeTurtle(body string) ([]turtleToken, error) {
	var tokens []turtleToken
	for i := 0; i < len(body); {
		switch {
		case body[i] == '#':
			for i < len(body) && body[i] != '\n' {
				i++
			}
		case isTurtleSpace(body[i]):
			i++
		case strings.HasPrefix(body[i:], `"""`):
			end := strings.Index(body[i+3:], `"""`)
			if end < 0 {
				return nil, fmt.Errorf("unterminated triple-quoted literal")
			}
			tokens = append(tokens, turtleToken{kind: "literal", value: body[i+3 : i+3+end]})
			i = skipTurtleLiteralAnnotation(body, i+3+end+3)
		case body[i] == '"':
			value, next, err := readTurtleString(body, i)
			if err != nil {
				return nil, err
			}
			tokens = append(tokens, turtleToken{kind: "literal", value: value})
			i = skipTurtleLiteralAnnotation(body, next)
		case body[i] == '<':
			end := strings.IndexByte(body[i+1:], '>')
			if end < 0 {
				return nil, fmt.Errorf("unterminated IRI")
			}
			tokens = append(tokens, turtleToken{kind: "iri", value: body[i+1 : i+1+end]})
			i += end + 2
		case strings.ContainsRune(".;,[]()", rune(body[i])):
			tokens = append(tokens, turtleToken{kind: "punct", value: string(body[i])})
			i++
		default:
			start := i
			for i < len(body) && !isTurtleSpace(body[i]) && !strings.ContainsRune(".;,[]()", rune(body[i])) {
				i++
			}
			tokens = append(tokens, turtleToken{kind: "name", value: body[start:i]})
		}
	}
	return tokens, nil
}

func skipTurtleLiteralAnnotation(body string, start int) int {
	i := start
	if i < len(body) && body[i] == '@' {
		i++
		for i < len(body) && (isTurtleNameChar(body[i]) || body[i] == '-') {
			i++
		}
		return i
	}
	if !strings.HasPrefix(body[i:], "^^") {
		return i
	}
	i += 2
	if i < len(body) && body[i] == '<' {
		end := strings.IndexByte(body[i+1:], '>')
		if end < 0 {
			return i
		}
		return i + end + 2
	}
	for i < len(body) && !isTurtleSpace(body[i]) && !strings.ContainsRune(".;,[]()", rune(body[i])) {
		i++
	}
	return i
}

func readTurtleString(body string, start int) (string, int, error) {
	var builder strings.Builder
	for i := start + 1; i < len(body); i++ {
		if body[i] == '"' {
			return builder.String(), i + 1, nil
		}
		if body[i] == '\\' && i+1 < len(body) {
			i++
			switch body[i] {
			case 'n':
				builder.WriteByte('\n')
			case 't':
				builder.WriteByte('\t')
			case 'r':
				builder.WriteByte('\r')
			default:
				builder.WriteByte(body[i])
			}
			continue
		}
		builder.WriteByte(body[i])
	}
	return "", 0, fmt.Errorf("unterminated literal")
}

func expandTurtleToken(prefixes map[string]string, token turtleToken) (string, error) {
	if token.kind == "literal" || token.kind == "iri" {
		return token.value, nil
	}
	prefix, local, ok := strings.Cut(token.value, ":")
	if !ok {
		return token.value, nil
	}
	base, ok := prefixes[prefix]
	if !ok {
		return "", fmt.Errorf("unknown Turtle prefix %q", prefix)
	}
	return base + local, nil
}

func isTurtleSpace(value byte) bool {
	return value == ' ' || value == '\n' || value == '\r' || value == '\t'
}

func isTurtleNameChar(value byte) bool {
	return (value >= 'a' && value <= 'z') || (value >= 'A' && value <= 'Z') || (value >= '0' && value <= '9') || value == '_'
}
