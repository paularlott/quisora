package scim

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

// This file implements the SCIM filter grammar (RFC 7644 §3.4.2.2) and the attribute path grammar (§3.10), plus the
// evaluator that matches a filter against a resource held as decoded JSON (map[string]any).

const (
	maxFilterLen   = 8192
	maxFilterDepth = 32
)

// attrPath is [URN:]name[.sub] with an optional value filter after name: emails[type eq "work"].value.
type attrPath struct {
	URN    string
	Name   string
	Sub    string
	Filter node
}

func (p attrPath) String() string {
	s := p.Name
	if p.URN != "" {
		s = p.URN + ":" + s
	}
	if p.Filter != nil {
		s += "[...]"
	}
	if p.Sub != "" {
		s += "." + p.Sub
	}
	return s
}

type node interface{}

type (
	andNode struct{ l, r node }
	orNode  struct{ l, r node }
	notNode struct{ n node }
	// cmpNode is an attribute expression. For op "pr" val is unused; val is a string, float64, bool or nil (null).
	cmpNode struct {
		path attrPath
		op   string
		val  any
	}
)

// ---------------------------------------------------------------------------------------------------------------
// Lexer

type tokKind int

const (
	tkWord tokKind = iota
	tkString
	tkLParen
	tkRParen
)

type token struct {
	kind tokKind
	s    string
}

func lex(in string) ([]token, error) {
	var out []token
	i := 0
	for i < len(in) {
		c := in[i]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			i++
		case c == '(':
			out = append(out, token{kind: tkLParen})
			i++
		case c == ')':
			out = append(out, token{kind: tkRParen})
			i++
		case c == '"':
			end, err := scanString(in, i)
			if err != nil {
				return nil, err
			}
			var s string
			if err := json.Unmarshal([]byte(in[i:end]), &s); err != nil {
				return nil, fmt.Errorf("invalid string literal")
			}
			out = append(out, token{kind: tkString, s: s})
			i = end
		default:
			j := i
			for j < len(in) {
				d := in[j]
				if d == ' ' || d == '\t' || d == '\n' || d == '\r' || d == '(' || d == ')' || d == '"' {
					break
				}
				if d == '[' {
					end, err := scanBracket(in, j)
					if err != nil {
						return nil, err
					}
					j = end
					continue
				}
				if d == ']' {
					return nil, fmt.Errorf("unexpected ]")
				}
				j++
			}
			out = append(out, token{kind: tkWord, s: in[i:j]})
			i = j
		}
	}
	return out, nil
}

// scanString returns the index just after the closing quote of the string literal starting at in[i].
func scanString(in string, i int) (int, error) {
	for j := i + 1; j < len(in); j++ {
		switch in[j] {
		case '\\':
			j++
		case '"':
			return j + 1, nil
		}
	}
	return 0, fmt.Errorf("unterminated string")
}

// scanBracket returns the index just after the ] matching the [ at in[i], skipping quoted strings.
func scanBracket(in string, i int) (int, error) {
	depth := 0
	for j := i; j < len(in); j++ {
		switch in[j] {
		case '"':
			end, err := scanString(in, j)
			if err != nil {
				return 0, err
			}
			j = end - 1
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return j + 1, nil
			}
		}
	}
	return 0, fmt.Errorf("unterminated [")
}

// ---------------------------------------------------------------------------------------------------------------
// Parser

type parser struct {
	toks  []token
	pos   int
	depth int
}

// ParseFilter parses a SCIM filter expression.
func parseFilter(in string) (node, error) { return parseFilterDepth(in, 0) }

func parseFilterDepth(in string, depth int) (node, error) {
	if len(in) > maxFilterLen {
		return nil, fmt.Errorf("filter is too long")
	}
	if depth > maxFilterDepth {
		return nil, fmt.Errorf("filter is nested too deeply")
	}
	toks, err := lex(in)
	if err != nil {
		return nil, err
	}
	if len(toks) == 0 {
		return nil, fmt.Errorf("empty filter")
	}
	p := &parser{toks: toks, depth: depth}
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos != len(p.toks) {
		return nil, fmt.Errorf("unexpected %s", p.describe(p.pos))
	}
	return n, nil
}

func (p *parser) describe(i int) string {
	if i >= len(p.toks) {
		return "end of filter"
	}
	t := p.toks[i]
	switch t.kind {
	case tkLParen:
		return "("
	case tkRParen:
		return ")"
	case tkString:
		return strconv.Quote(t.s)
	}
	return t.s
}

func (p *parser) peekWord(w string) bool {
	return p.pos < len(p.toks) && p.toks[p.pos].kind == tkWord && strings.EqualFold(p.toks[p.pos].s, w)
}

func (p *parser) parseOr() (node, error) {
	l, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for p.peekWord("or") {
		p.pos++
		r, err := p.parseAnd()
		if err != nil {
			return nil, err
		}
		l = &orNode{l, r}
	}
	return l, nil
}

func (p *parser) parseAnd() (node, error) {
	l, err := p.parseUnary()
	if err != nil {
		return nil, err
	}
	for p.peekWord("and") {
		p.pos++
		r, err := p.parseUnary()
		if err != nil {
			return nil, err
		}
		l = &andNode{l, r}
	}
	return l, nil
}

func (p *parser) group() (node, error) {
	p.depth++
	if p.depth > maxFilterDepth {
		return nil, fmt.Errorf("filter is nested too deeply")
	}
	p.pos++ // (
	n, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos >= len(p.toks) || p.toks[p.pos].kind != tkRParen {
		return nil, fmt.Errorf("missing )")
	}
	p.pos++
	p.depth--
	return n, nil
}

func (p *parser) parseUnary() (node, error) {
	if p.pos >= len(p.toks) {
		return nil, fmt.Errorf("unexpected end of filter")
	}
	t := p.toks[p.pos]
	switch {
	case t.kind == tkLParen:
		return p.group()
	case t.kind == tkWord && strings.EqualFold(t.s, "not") && p.pos+1 < len(p.toks) && p.toks[p.pos+1].kind == tkLParen:
		p.pos++
		n, err := p.group()
		if err != nil {
			return nil, err
		}
		return &notNode{n}, nil
	case t.kind != tkWord:
		return nil, fmt.Errorf("unexpected %s", p.describe(p.pos))
	}
	path, err := parsePathDepth(t.s, p.depth+1)
	if err != nil {
		return nil, err
	}
	p.pos++
	// valuePath on its own: true when some element matches.
	if p.pos >= len(p.toks) || p.toks[p.pos].kind != tkWord || isLogical(p.toks[p.pos].s) {
		if path.Filter != nil {
			return &cmpNode{path: path, op: "pr"}, nil
		}
		return nil, fmt.Errorf("missing operator after %s", t.s)
	}
	op := strings.ToLower(p.toks[p.pos].s)
	p.pos++
	switch op {
	case "pr":
		return &cmpNode{path: path, op: op}, nil
	case "eq", "ne", "co", "sw", "ew", "gt", "ge", "lt", "le":
	default:
		return nil, fmt.Errorf("unknown operator %q", op)
	}
	if p.pos >= len(p.toks) {
		return nil, fmt.Errorf("missing value after %s", op)
	}
	v := p.toks[p.pos]
	p.pos++
	switch v.kind {
	case tkString:
		return &cmpNode{path: path, op: op, val: v.s}, nil
	case tkWord:
		switch strings.ToLower(v.s) {
		case "true":
			return &cmpNode{path: path, op: op, val: true}, nil
		case "false":
			return &cmpNode{path: path, op: op, val: false}, nil
		case "null":
			return &cmpNode{path: path, op: op, val: nil}, nil
		}
		f, err := strconv.ParseFloat(v.s, 64)
		if err != nil || math.IsNaN(f) || math.IsInf(f, 0) || !validNumber(v.s) {
			return nil, fmt.Errorf("invalid value %q", v.s)
		}
		return &cmpNode{path: path, op: op, val: f}, nil
	}
	return nil, fmt.Errorf("invalid value after %s", op)
}

// validNumber accepts JSON numbers only (no hex, no leading +, no underscores).
func validNumber(s string) bool {
	var f float64
	return json.Unmarshal([]byte(s), &f) == nil
}

func isLogical(s string) bool { return strings.EqualFold(s, "and") || strings.EqualFold(s, "or") }

// knownURNs are schema URNs that can appear as a path on their own or as an attribute prefix.
var knownURNs []string

func isKnownURN(s string) bool {
	for _, u := range knownURNs {
		if strings.EqualFold(u, s) {
			return true
		}
	}
	return false
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '$':
		case i > 0 && (c >= '0' && c <= '9' || c == '-' || c == '_'):
		default:
			return false
		}
	}
	return true
}

// parsePath parses an attribute path as used in filters and PATCH operations.
func parsePath(s string) (attrPath, error) { return parsePathDepth(s, 0) }

func parsePathDepth(s string, depth int) (attrPath, error) {
	var p attrPath
	if s == "" || len(s) > maxFilterLen {
		return p, fmt.Errorf("invalid path")
	}
	if isKnownURN(s) {
		p.URN = s
		return p, nil
	}
	left, rest := s, ""
	if i := strings.IndexByte(s, '['); i >= 0 {
		end, err := scanBracket(s, i)
		if err != nil {
			return p, err
		}
		inner := s[i+1 : end-1]
		left, rest = s[:i], s[end:]
		f, err := parseFilterDepth(inner, depth+1)
		if err != nil {
			return p, fmt.Errorf("in value filter: %w", err)
		}
		p.Filter = f
		if rest != "" {
			sub, ok := strings.CutPrefix(rest, ".")
			if !ok || !validName(sub) {
				return p, fmt.Errorf("invalid path %q", s)
			}
			p.Sub = sub
		}
		if k := strings.LastIndexByte(left, ':'); k >= 0 {
			p.URN, left = left[:k], left[k+1:]
		}
		if !validName(left) {
			return p, fmt.Errorf("invalid attribute name %q", left)
		}
		p.Name = left
		return p, nil
	}
	if k := strings.LastIndexByte(left, ':'); k >= 0 {
		p.URN, left = left[:k], left[k+1:]
		if p.URN == "" {
			return p, fmt.Errorf("invalid path %q", s)
		}
	}
	name, sub, _ := strings.Cut(left, ".")
	if !validName(name) || (strings.Contains(left, ".") && !validName(sub)) {
		return p, fmt.Errorf("invalid attribute path %q", s)
	}
	p.Name, p.Sub = name, sub
	return p, nil
}

// ---------------------------------------------------------------------------------------------------------------
// Evaluation

// keyOf finds a key of m case-insensitively (attribute names are case-insensitive).
func keyOf(m map[string]any, name string) (string, bool) {
	if _, ok := m[name]; ok {
		return name, true
	}
	for k := range m {
		if strings.EqualFold(k, name) {
			return k, true
		}
	}
	return "", false
}

func getCI(m map[string]any, name string) any {
	if k, ok := keyOf(m, name); ok {
		return m[k]
	}
	return nil
}

func asSlice(v any) []any {
	switch t := v.(type) {
	case nil:
		return nil
	case []any:
		return t
	}
	return []any{v}
}

// resolve returns the values a path selects in root (after applying any value filter).
func resolve(root map[string]any, p attrPath, sch *schemaSet) []any {
	base := root
	if p.URN != "" && !strings.EqualFold(p.URN, sch.core) {
		m, _ := getCI(root, p.URN).(map[string]any)
		if m == nil {
			return nil
		}
		base = m
	}
	if p.Name == "" {
		return []any{base}
	}
	elems := asSlice(getCI(base, p.Name))
	if p.Filter != nil {
		kept := make([]any, 0, len(elems))
		for _, e := range elems {
			if em, ok := e.(map[string]any); ok && evalNode(p.Filter, em, sch) {
				kept = append(kept, e)
			}
		}
		elems = kept
	}
	if p.Sub == "" {
		return elems
	}
	out := make([]any, 0, len(elems))
	for _, e := range elems {
		em, ok := e.(map[string]any)
		if !ok {
			continue
		}
		for _, v := range asSlice(getCI(em, p.Sub)) {
			out = append(out, v)
		}
	}
	return out
}

func present(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	return true
}

func evalNode(n node, root map[string]any, sch *schemaSet) bool {
	switch t := n.(type) {
	case *andNode:
		return evalNode(t.l, root, sch) && evalNode(t.r, root, sch)
	case *orNode:
		return evalNode(t.l, root, sch) || evalNode(t.r, root, sch)
	case *notNode:
		return !evalNode(t.n, root, sch)
	case *cmpNode:
		return evalCmp(t, root, sch)
	}
	return false
}

func evalCmp(c *cmpNode, root map[string]any, sch *schemaSet) bool {
	vals := resolve(root, c.path, sch)
	if c.op == "pr" {
		for _, v := range vals {
			if present(v) {
				return true
			}
		}
		return false
	}
	info := sch.info(c.path)
	if c.val == nil {
		found := false
		for _, v := range vals {
			if present(v) {
				found = true
			}
		}
		switch c.op {
		case "eq":
			return !found
		case "ne":
			return found
		}
		return false
	}
	if c.op == "ne" {
		for _, v := range vals {
			if compareOne(v, "eq", c.val, info) {
				return false
			}
		}
		return true
	}
	for _, v := range vals {
		if compareOne(v, c.op, c.val, info) {
			return true
		}
	}
	return false
}

func toFloat(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int32:
		return float64(n), true
	case int64:
		return float64(n), true
	case json.Number:
		f, err := n.Float64()
		return f, err == nil
	}
	return 0, false
}

func parseTime(s string) (time.Time, bool) {
	t, err := time.Parse(time.RFC3339Nano, s)
	return t, err == nil
}

// compareOne compares one attribute value against the filter value with an operator other than pr/ne.
func compareOne(v any, op string, want any, info attrInfo) bool {
	if m, ok := v.(map[string]any); ok { // a complex attribute compared as a whole means its "value"
		v = getCI(m, "value")
	}
	switch w := want.(type) {
	case bool:
		b, ok := v.(bool)
		if s, isStr := v.(string); isStr && !ok {
			switch strings.ToLower(s) {
			case "true":
				b, ok = true, true
			case "false":
				b, ok = false, true
			}
		}
		return ok && op == "eq" && b == w
	case float64:
		f, ok := toFloat(v)
		if !ok {
			return false
		}
		return cmpResult(op, floatCmp(f, w))
	case string:
		s, ok := v.(string)
		if !ok {
			if b, isBool := v.(bool); isBool && op == "eq" {
				return strings.EqualFold(strconv.FormatBool(b), w)
			}
			if f, isNum := toFloat(v); isNum && op == "eq" {
				return strconv.FormatFloat(f, 'f', -1, 64) == w
			}
			return false
		}
		if info.typ == "dateTime" {
			a, ok1 := parseTime(s)
			b, ok2 := parseTime(w)
			if ok1 && ok2 {
				return cmpResult(op, a.Compare(b))
			}
		}
		if !info.caseExact {
			s, w = strings.ToLower(s), strings.ToLower(w)
		}
		switch op {
		case "co":
			return strings.Contains(s, w)
		case "sw":
			return strings.HasPrefix(s, w)
		case "ew":
			return strings.HasSuffix(s, w)
		}
		return cmpResult(op, strings.Compare(s, w))
	}
	return false
}

func floatCmp(a, b float64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}

func cmpResult(op string, c int) bool {
	switch op {
	case "eq":
		return c == 0
	case "gt":
		return c > 0
	case "ge":
		return c >= 0
	case "lt":
		return c < 0
	case "le":
		return c <= 0
	}
	return false
}

// conjuncts flattens the top-level AND tree of n.
func conjuncts(n node) []node {
	if a, ok := n.(*andNode); ok {
		return append(conjuncts(a.l), conjuncts(a.r)...)
	}
	return []node{n}
}

// referencesAttr reports whether any path in n starts at the named top-level attribute.
func referencesAttr(n node, name string) bool {
	switch t := n.(type) {
	case *andNode:
		return referencesAttr(t.l, name) || referencesAttr(t.r, name)
	case *orNode:
		return referencesAttr(t.l, name) || referencesAttr(t.r, name)
	case *notNode:
		return referencesAttr(t.n, name)
	case *cmpNode:
		return t.path.URN == "" && strings.EqualFold(t.path.Name, name)
	}
	return false
}
