package model

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"unicode"
)

// Authorization details (RFC 9396): JSON objects, each with a type, that say what an access token may do at an API
// in more detail than scopes can ("subscribe to these topics", "read these accounts"). Quisora treats them as data
// it does not interpret: administrators write them into tenant access entries (for users) and onto clients (for their
// client_credentials tokens), and Quisora puts them into the access tokens of the clients registered for their
// type. Of each object it reads only the type and the common field locations (§2.2), which names the APIs it is for:
// one with locations goes only into tokens whose audience holds one of them.
//
// String values may name the token they are issued in with {{sub}} (the user, or the client of a client_credentials
// token), {{org}} and {{tenant}} (ids), replaced when the token is minted: one group access entry can then give each
// member a topic of their own. Any other {{...}} is refused when the details are saved.

// Limits on authorization details.
const (
	MaxAuthDetails      = 16   // objects in one access entry's or client's details, and in a request
	MaxAuthDetailsBytes = 8192 // one access entry's or client's details, and a request's, as JSON
	MaxAuthDetailTypes  = 16   // types a client is registered for
	maxAuthDetailType   = 256
)

// AuthDetail is one authorization detail, with its placeholders replaced.
type AuthDetail struct {
	Type      string
	Locations []string
	JSON      json.RawMessage // the whole object
}

// AuthDetailVars are the values of the placeholders of a token's authorization details.
type AuthDetailVars struct{ Sub, Org, Tenant string }

// ValidAuthDetailType reports whether s can be an authorization details type: 1–256 printable characters without
// white space (types are usually URIs).
func ValidAuthDetailType(s string) bool {
	if s == "" || len(s) > maxAuthDetailType {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || !unicode.IsPrint(r) {
			return false
		}
	}
	return true
}

// ParseAuthDetails reads an authorization_details array (RFC 9396 §2): at most MaxAuthDetails JSON objects, each
// with a valid type, whose common fields, when present, have their shapes (locations, actions, datatypes and
// privileges arrays of strings, identifier a string). It returns the objects, numbers kept as written.
func ParseAuthDetails(raw []byte) ([]map[string]any, error) {
	if len(raw) > MaxAuthDetailsBytes {
		return nil, fmt.Errorf("authorization details are limited to %d bytes", MaxAuthDetailsBytes)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var list []any
	if err := dec.Decode(&list); err != nil || list == nil {
		return nil, errors.New("authorization details must be a JSON array of objects")
	}
	if dec.More() {
		return nil, errors.New("authorization details must be a single JSON array")
	}
	if len(list) > MaxAuthDetails {
		return nil, fmt.Errorf("at most %d authorization details are allowed", MaxAuthDetails)
	}
	out := make([]map[string]any, 0, len(list))
	for i, v := range list {
		obj, ok := v.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("authorization detail %d is not a JSON object", i+1)
		}
		if t, _ := obj["type"].(string); !ValidAuthDetailType(t) {
			return nil, fmt.Errorf("authorization detail %d needs a type: a string of up to %d characters without spaces", i+1, maxAuthDetailType)
		}
		for _, f := range []string{"locations", "actions", "datatypes", "privileges"} {
			if fv, ok := obj[f]; ok && !stringArray(fv) {
				return nil, fmt.Errorf("authorization detail %d: %s must be an array of strings", i+1, f)
			}
		}
		if fv, ok := obj["identifier"]; ok {
			if _, ok := fv.(string); !ok {
				return nil, fmt.Errorf("authorization detail %d: identifier must be a string", i+1)
			}
		}
		out = append(out, obj)
	}
	return out, nil
}

func stringArray(v any) bool {
	a, ok := v.([]any)
	if !ok {
		return false
	}
	for _, e := range a {
		if _, ok := e.(string); !ok {
			return false
		}
	}
	return true
}

// authDetailVars are the placeholders string values may hold.
var authDetailVars = []string{"{{sub}}", "{{org}}", "{{tenant}}"}

// NormAuthDetails validates administrator-written authorization details (ParseAuthDetails, and no placeholder but
// those Quisora fills in) and returns them as compact JSON; nil for none (an empty input or an empty array).
func NormAuthDetails(raw []byte) (json.RawMessage, error) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return nil, nil
	}
	list, err := ParseAuthDetails(raw)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	var bad string
	walkStrings(list, func(s string) string {
		rest := s
		for _, v := range authDetailVars {
			rest = strings.ReplaceAll(rest, v, "")
		}
		if bad == "" && strings.Contains(rest, "{{") {
			bad = s
		}
		return s
	})
	if bad != "" {
		return nil, errors.New("unknown placeholder: only {{sub}}, {{org}} and {{tenant}} are filled in")
	}
	return marshalJSON(list), nil
}

// ExpandAuthDetails returns stored authorization details (NormAuthDetails) with their placeholders replaced by vars.
func ExpandAuthDetails(raw json.RawMessage, vars AuthDetailVars) ([]AuthDetail, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	list, err := ParseAuthDetails(raw)
	if err != nil {
		return nil, err
	}
	r := strings.NewReplacer("{{sub}}", vars.Sub, "{{org}}", vars.Org, "{{tenant}}", vars.Tenant)
	out := make([]AuthDetail, 0, len(list))
	for _, obj := range list {
		obj := walkStrings(obj, func(s string) string {
			if strings.Contains(s, "{{") {
				return r.Replace(s)
			}
			return s
		}).(map[string]any)
		d := AuthDetail{Type: obj["type"].(string), JSON: marshalJSON(obj)}
		if locs, ok := obj["locations"].([]any); ok {
			for _, l := range locs {
				d.Locations = append(d.Locations, l.(string))
			}
		}
		out = append(out, d)
	}
	return out, nil
}

// walkStrings returns v with every string value (not object keys) passed through f.
func walkStrings(v any, f func(string) string) any {
	switch x := v.(type) {
	case string:
		return f(x)
	case []any:
		for i := range x {
			x[i] = walkStrings(x[i], f)
		}
	case []map[string]any:
		for i := range x {
			x[i] = walkStrings(x[i], f).(map[string]any)
		}
	case map[string]any:
		for k := range x {
			x[k] = walkStrings(x[k], f)
		}
	}
	return v
}

// marshalJSON is compact JSON of v, object keys sorted (so equal details are equal bytes), < > & as they are.
func marshalJSON(v any) json.RawMessage {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(v)
	return bytes.TrimRight(b.Bytes(), "\n")
}
