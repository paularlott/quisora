package model

import "strings"

// ReleaseUnique removes unique value v (one of e.Index().Unique) from entity e, after the record lost it to another
// record created before it: an email address or external id is cleared, a name gets the record's short id appended
// (so it stays valid and unique), a passkey whose credential id clashes is disabled (it cannot sign in twice). It
// reports whether e changed. An upstream identity's link cannot be released: it stays unindexed (it no longer signs
// in) and is reported.
func ReleaseUnique(e Entity, v string) bool {
	switch x := e.(type) {
	case *User:
		switch {
		case x.Email != "" && v == UserEmailKey(x.OrgID, x.Email):
			x.Email, x.EmailVerified = "", false
			return true
		case x.ExternalID != "" && v == UserExternalIDKey(x.OrgID, x.ExternalID):
			x.ExternalID = ""
			return true
		case v == UserUsernameKey(x.OrgID, x.Username):
			x.Username = x.Username + "-" + shortID(x.ID)
			return true
		}
		for i, l := range x.LinkedEmails {
			if v == UserEmailKey(x.OrgID, l.Address) {
				x.LinkedEmails = append(x.LinkedEmails[:i:i], x.LinkedEmails[i+1:]...)
				return true
			}
		}
	case *Group:
		switch {
		case x.ExternalID != "" && v == GroupExternalIDKey(x.OrgID, x.ExternalID):
			x.ExternalID = ""
			return true
		case v == GroupNameKey(x.OrgID, x.DisplayName):
			x.DisplayName += " (" + shortID(x.ID) + ")"
			return true
		}
	case *Org:
		if v == OrgNameKey(x.Name) {
			x.Name = x.Name + "-" + shortID(x.ID)
			return true
		}
	case *Tenant:
		if v == TenantNameKey(x.OrgID, x.Name) {
			x.Name = x.Name + "-" + shortID(x.ID)
			return true
		}
	case *Provider:
		if v == x.OrgID+"/n/"+Lower(x.Name) {
			x.Name += " (" + shortID(x.ID) + ")"
			return true
		}
	case *Passkey:
		if !x.Disabled {
			x.Disabled = true
			return true
		}
	}
	return false
}

// shortID is the last six characters of an id (lower case hex for UUIDs).
func shortID(id string) string {
	id = strings.ToLower(strings.ReplaceAll(id, "-", ""))
	if len(id) > 6 {
		return id[len(id)-6:]
	}
	return id
}
