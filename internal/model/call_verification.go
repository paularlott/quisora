package model

import (
	"crypto/sha256"
	"encoding/hex"
	"time"
)

// KindCallVerification holds caller verifications (CallVerification).
const KindCallVerification Kind = "callverification"

// The states of a caller verification.
const (
	VerifyPending   = "pending"   // the code is out: waiting for the customer to enter it
	VerifyConfirmed = "confirmed" // the customer entered the code and confirmed it is them
	VerifyDenied    = "denied"    // the customer entered the code and said it is not them
	VerifyCancelled = "cancelled" // the agent stopped it
	VerifyExpired   = "expired"   // nobody entered the code in time
)

// Who placed the call a verification is for (CallVerification.Direction), as the agent says: the customer called the
// organization (inbound), or the agent called the customer (outbound). The customer is shown it: a scammer passing an
// agent's code on to someone they called makes the agent record an inbound call, which that person sees is not theirs.
const (
	VerifyInbound  = "inbound"
	VerifyOutbound = "outbound"
)

// VerifyCodeFor is how long a caller verification's code may be entered; VerifyKeptFor how long a closed one is kept
// (the audit log keeps the history).
const (
	VerifyCodeFor = 5 * time.Minute
	VerifyKeptFor = 30 * 24 * time.Hour
)

// CallVerification is a support agent confirming that the person on a call is the account holder they say they are: the
// agent (a member of an agent group of an organization that verifies callers) starts it for a user of their own
// organization or of one that lets theirs verify its users, and reads its six-digit code to the caller, who enters it
// on their own account page, sees who is asking, and confirms it is them (after confirming it is them to Quisora: a
// passkey or second factor). It lives with the customer's organization.
type CallVerification struct {
	Meta
	OrgID  string `msgpack:"o" json:"org_id"`   // the customer's organization
	UserID string `msgpack:"ui" json:"user_id"` // the customer
	// AgentOrgID, AgentID: who asks; AgentName, AgentEmail and AgentOrgName as they were then (what the customer is
	// shown, and the record keeps should the agent be removed).
	AgentOrgID   string `msgpack:"ao" json:"agent_org_id"`
	AgentID      string `msgpack:"ai" json:"agent_id"`
	AgentName    string `msgpack:"an" json:"agent_name"`
	AgentEmail   string `msgpack:"ae,omitempty" json:"agent_email,omitempty"`
	AgentOrgName string `msgpack:"aon" json:"agent_org_name"`
	Reason       string `msgpack:"rs,omitempty" json:"reason,omitempty"`
	Direction    string `msgpack:"dir" json:"direction"` // VerifyInbound or VerifyOutbound
	// CodeKey is the hash that finds a pending verification by its code (VerifyCodeKey): the code itself is shown to
	// the agent once and kept nowhere.
	CodeKey string    `msgpack:"ck" json:"-"`
	State   string    `msgpack:"s" json:"state"`
	Expires time.Time `msgpack:"ex" json:"expires"` // when a pending one's code stops working
	// DecidedAt is when it closed (confirmed, denied, cancelled or expired); SecondFactor whether the customer confirmed
	// with a passkey or second factor (else their password alone: an account without one).
	DecidedAt    time.Time `msgpack:"da,omitempty" json:"decided_at,omitempty"`
	SecondFactor bool      `msgpack:"sf,omitempty" json:"second_factor"`
}

func (v *CallVerification) Kind() Kind { return KindCallVerification }

// Pending reports whether v waits for its code (and has not run out).
func (v *CallVerification) Pending(now time.Time) bool {
	return v.State == VerifyPending && now.Before(v.Expires)
}

// due is when housekeeping looks at v: a pending one when its code runs out, a closed one when it is no longer kept.
func (v *CallVerification) due() time.Time {
	if v.State == VerifyPending {
		return v.Expires
	}
	at := v.DecidedAt
	if at.IsZero() {
		at = v.Expires
	}
	return at.Add(VerifyKeptFor)
}

func (v *CallVerification) Index() Index {
	var uq []string
	if v.State == VerifyPending { // finds it by the customer and the code, while the code works
		uq = []string{verifyUnique(v.OrgID, v.UserID, v.CodeKey)}
	}
	return Index{
		Scope:     v.OrgID,
		Partition: v.OrgID,
		Unique:    uq,
		Fields: map[string]any{"user_id": v.UserID, "agent_day": VerifyAgentDay(v.AgentID, v.Created), "state": v.State,
			"created": v.Created, "due": v.due()},
	}
}

// VerifyCodeKey is the CodeKey of code for customer userID: a hash, so the stored record does not hold the code.
func VerifyCodeKey(userID, code string) string {
	h := sha256.Sum256([]byte("quisora-call-verify|" + userID + "|" + code))
	return hex.EncodeToString(h[:16])
}

// VerifyCodeUnique is the unique value a pending verification of customer userID of organization orgID holds.
func VerifyCodeUnique(orgID, userID, code string) string {
	return verifyUnique(orgID, userID, VerifyCodeKey(userID, code))
}

func verifyUnique(orgID, userID, codeKey string) string {
	return orgID + "/vc/" + userID + "/" + codeKey
}

// VerifyAgentDay is the "agent_day" index value of agent agentID's verifications started on at's day (UTC): the
// agent's page lists a day's.
func VerifyAgentDay(agentID string, at time.Time) string {
	return agentID + "/" + at.UTC().Format("2006-01-02")
}
