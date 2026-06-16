package httpapi

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// parseCreateServiceRequestJSONLD parses a JSON-LD service deployment document
// into a createServiceRequest. It converts the document into the same flat
// triple model produced by the Turtle parser and then reuses
// serviceRequestFromTriples, so both syntaxes share one validation path and the
// same FNO applied-function vocabulary (including the legacy fno.io namespace).
func parseCreateServiceRequestJSONLD(cfg Config, body []byte) (createServiceRequest, error) {
	var doc any
	if err := json.Unmarshal(body, &doc); err != nil {
		return createServiceRequest{}, fmt.Errorf("invalid JSON-LD: %w", err)
	}

	conv := &jsonLDConverter{}
	prefixes := defaultRDFPrefixes()

	switch root := doc.(type) {
	case map[string]any:
		prefixes = mergeJSONLDContext(prefixes, root["@context"])
		if graph, ok := root["@graph"]; ok {
			for _, node := range toJSONLDSlice(graph) {
				if err := conv.convertTopLevel(node, prefixes); err != nil {
					return createServiceRequest{}, err
				}
			}
		} else if err := conv.convertTopLevel(root, prefixes); err != nil {
			return createServiceRequest{}, err
		}
	case []any:
		for _, node := range root {
			if err := conv.convertTopLevel(node, prefixes); err != nil {
				return createServiceRequest{}, err
			}
		}
	default:
		return createServiceRequest{}, fmt.Errorf("JSON-LD document must be an object or array")
	}

	return serviceRequestFromTriples(cfg, conv.triples)
}

// looksLikeJSONLD heuristically detects a JSON-LD body so that clients posting
// JSON-LD with a generic application/json content type are still understood,
// instead of being silently parsed as the flat {transformation, source_urls}
// shape (which would drop the nested data and fail validation).
func looksLikeJSONLD(body []byte) bool {
	trimmed := strings.TrimSpace(string(body))
	if trimmed == "" {
		return false
	}
	if trimmed[0] == '[' {
		return true
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal([]byte(trimmed), &probe); err != nil {
		return false
	}
	for key := range probe {
		if strings.HasPrefix(key, "@") {
			return true
		}
	}
	return false
}

type jsonLDConverter struct {
	triples   []turtleTriple
	nextBlank int
	nextList  int
}

func (c *jsonLDConverter) convertTopLevel(node any, prefixes map[string]string) error {
	obj, ok := node.(map[string]any)
	if !ok {
		return fmt.Errorf("JSON-LD node must be an object")
	}
	_, err := c.convertNode(obj, prefixes)
	return err
}

// convertNode emits the triples for a JSON-LD node object and returns the term
// (IRI or blank node) that identifies it.
func (c *jsonLDConverter) convertNode(obj map[string]any, prefixes map[string]string) (string, error) {
	prefixes = mergeJSONLDContext(prefixes, obj["@context"])

	subject := c.newBlankNode()
	if id, ok := obj["@id"].(string); ok && id != "" {
		subject = expandJSONLDIRI(prefixes, id)
	}

	for key, raw := range obj {
		switch key {
		case "@context", "@id":
			continue
		case "@type":
			for _, typeValue := range toJSONLDStringTerms(raw) {
				c.triples = append(c.triples, turtleTriple{
					subject: subject, predicate: rdfType,
					object: expandJSONLDIRI(prefixes, typeValue), objectKind: "iri",
				})
			}
		default:
			predicate := expandJSONLDIRI(prefixes, key)
			if err := c.emitValues(subject, predicate, raw, prefixes); err != nil {
				return "", err
			}
		}
	}
	return subject, nil
}

func (c *jsonLDConverter) emitValues(subject, predicate string, raw any, prefixes map[string]string) error {
	switch v := raw.(type) {
	case []any:
		for _, item := range v {
			if err := c.emitValues(subject, predicate, item, prefixes); err != nil {
				return err
			}
		}
		return nil
	case map[string]any:
		if list, ok := v["@list"]; ok {
			listNode := c.newListNode()
			c.triples = append(c.triples, turtleTriple{
				subject: subject, predicate: predicate, object: listNode, objectKind: "list",
			})
			for _, item := range toJSONLDSlice(list) {
				member, kind, err := c.termFor(item, prefixes)
				if err != nil {
					return err
				}
				c.triples = append(c.triples, turtleTriple{
					subject: listNode, predicate: syntheticListMember, object: member, objectKind: kind,
				})
			}
			return nil
		}
		if value, ok := v["@value"]; ok {
			c.triples = append(c.triples, turtleTriple{
				subject: subject, predicate: predicate, object: jsonLDValueString(value), objectKind: "literal",
			})
			return nil
		}
		child, err := c.convertNode(v, prefixes)
		if err != nil {
			return err
		}
		c.triples = append(c.triples, turtleTriple{
			subject: subject, predicate: predicate, object: child, objectKind: nodeKind(v),
		})
		return nil
	case string:
		c.triples = append(c.triples, turtleTriple{
			subject: subject, predicate: predicate, object: v, objectKind: "literal",
		})
		return nil
	case bool, float64:
		c.triples = append(c.triples, turtleTriple{
			subject: subject, predicate: predicate, object: jsonLDValueString(v), objectKind: "literal",
		})
		return nil
	case nil:
		return nil
	default:
		return fmt.Errorf("unsupported JSON-LD value for predicate %s", predicate)
	}
}

// termFor resolves a single RDF-list member to its term and kind.
func (c *jsonLDConverter) termFor(item any, prefixes map[string]string) (string, string, error) {
	switch v := item.(type) {
	case map[string]any:
		if value, ok := v["@value"]; ok {
			return jsonLDValueString(value), "literal", nil
		}
		child, err := c.convertNode(v, prefixes)
		if err != nil {
			return "", "", err
		}
		return child, nodeKind(v), nil
	case string:
		return v, "literal", nil
	case bool, float64:
		return jsonLDValueString(v), "literal", nil
	default:
		return "", "", fmt.Errorf("unsupported JSON-LD list member %T", item)
	}
}

func (c *jsonLDConverter) newBlankNode() string {
	c.nextBlank++
	return fmt.Sprintf("_:jb%d", c.nextBlank)
}

func (c *jsonLDConverter) newListNode() string {
	c.nextList++
	return fmt.Sprintf("_:jlist%d", c.nextList)
}

func nodeKind(node map[string]any) string {
	if _, ok := node["@id"].(string); ok {
		return "iri"
	}
	return "blank"
}

func defaultRDFPrefixes() map[string]string {
	return map[string]string{
		"aggr": "https://w3id.org/aggregator#",
		"dcat": "http://www.w3.org/ns/dcat#",
		"fno":  "https://w3id.org/function/ontology#",
		"fnoc": "https://w3id.org/function/vocabulary/composition#",
		"odrl": "http://www.w3.org/ns/odrl/2/",
		"rdf":  "http://www.w3.org/1999/02/22-rdf-syntax-ns#",
	}
}

// mergeJSONLDContext folds a JSON-LD @context (term -> IRI string, or
// term -> {"@id": IRI}) into a copy of the supplied prefix map. Nested context
// arrays are merged left to right. Only simple term/prefix mappings are
// supported, which is sufficient for the aggregator deployment vocabulary.
func mergeJSONLDContext(base map[string]string, ctx any) map[string]string {
	merged := make(map[string]string, len(base))
	for key, value := range base {
		merged[key] = value
	}
	switch c := ctx.(type) {
	case map[string]any:
		for term, raw := range c {
			switch value := raw.(type) {
			case string:
				merged[term] = value
			case map[string]any:
				if id, ok := value["@id"].(string); ok {
					merged[term] = id
				}
			}
		}
	case []any:
		for _, item := range c {
			merged = mergeJSONLDContext(merged, item)
		}
	}
	return merged
}

// expandJSONLDIRI resolves a JSON-LD term, compact IRI (prefix:local) or
// absolute IRI to a full IRI using the active prefix map.
func expandJSONLDIRI(prefixes map[string]string, value string) string {
	if value == "" || strings.HasPrefix(value, "_:") || strings.HasPrefix(value, "@") {
		return value
	}
	if strings.Contains(value, "://") {
		return value
	}
	if prefix, local, ok := strings.Cut(value, ":"); ok {
		if base, found := prefixes[prefix]; found {
			return base + local
		}
		return value
	}
	if mapped, found := prefixes[value]; found {
		return mapped
	}
	return value
}

func toJSONLDSlice(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case nil:
		return nil
	default:
		return []any{v}
	}
}

func toJSONLDStringTerms(value any) []string {
	var terms []string
	for _, item := range toJSONLDSlice(value) {
		switch v := item.(type) {
		case string:
			terms = append(terms, v)
		case map[string]any:
			if id, ok := v["@id"].(string); ok {
				terms = append(terms, id)
			}
		}
	}
	return terms
}

func jsonLDValueString(value any) string {
	switch v := value.(type) {
	case string:
		return v
	case bool:
		if v {
			return "true"
		}
		return "false"
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	default:
		return fmt.Sprintf("%v", v)
	}
}

