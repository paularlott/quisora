package service

import (
	"context"
	"strings"
	"unicode"

	"github.com/paularlott/quisora/internal/model"
	"github.com/paularlott/quisora/internal/secure"
)

// Password checks beyond the length (ValidatePassword): NIST SP 800-63B §3.1.1.2 asks a verifier to refuse passwords
// that are commonly used, expected or compromised. Quisora calls nothing outside (no breach-list lookups), so these
// are offline checks for what an attacker tries first: one character over and over, runs along the alphabet or the
// keyboard, a common word dressed up with digits, symbols or l33t, and words that identify the person. They refuse
// little that a person picked with care; a passphrase of ordinary words passes.

// commonWords are the words people build passwords on (checked after leetspeak is undone and leading and trailing
// digits and symbols are removed, so "P@ssw0rd2026!" is "password").
var commonWords = map[string]bool{}

func init() {
	for _, w := range strings.Fields(`
		password passwort passe contrasena senha wachtwoord parola
		welcome letmein changeme secret default login logon access admin administrator root guest user test temp
		qwerty qwertz azerty iloveyou loveyou monkey dragon master shadow sunshine princess football baseball soccer
		hockey superman batman trustno starwars whatever freedom computer internet google microsoft apple samsung
		spring summer autumn winter january february march april may june july august september october november
		december monday tuesday wednesday thursday friday saturday sunday hello company office secure security`) {
		commonWords[w] = true
	}
}

// sequences are runs people type: along the alphabet and digits (both ways) and along keyboard rows and columns.
var sequences = []string{
	"abcdefghijklmnopqrstuvwxyz", "zyxwvutsrqponmlkjihgfedcba", "01234567890", "09876543210",
	"qwertyuiop", "poiuytrewq", "asdfghjkl", "lkjhgfdsa", "zxcvbnm", "mnbvcxz", "qwertzuiop", "azertyuiop",
	"1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p", "qazwsxedcrfvtgbyhnujmikolp",
}

// leet undoes the usual character swaps.
var leet = strings.NewReplacer("0", "o", "1", "i", "3", "e", "4", "a", "5", "s", "7", "t", "8", "b", "9", "g",
	"@", "a", "$", "s", "!", "i", "|", "l", "+", "t")

// weakPassword says why pw is easy to guess ("" when it is not), given words that identify its owner.
func weakPassword(pw string, personal []string) string {
	lower := strings.ToLower(pw)
	if distinct(lower) < 4 {
		return "uses too few different characters"
	}
	if alnum := keepAlnum(lower); len(alnum) >= len(lower)/2 && (inSequence(alnum) || repeats(alnum)) {
		return "is a run of characters along the keyboard or the alphabet, or a short pattern repeated"
	}
	// The word underneath: digits and symbols added at either end removed, l33t undone (both orders, so "P@ss2026"
	// and "@dmin" both come out).
	notLetter := func(r rune) bool { return !unicode.IsLetter(r) }
	for _, plain := range []string{keepAlnum(leet.Replace(strings.TrimFunc(lower, notLetter))),
		keepAlnum(strings.TrimFunc(leet.Replace(lower), notLetter))} {
		if commonWords[plain] || commonWords[strings.TrimSuffix(plain, "s")] {
			return "is a common word with digits or symbols added: choose something less predictable"
		}
		if inSequence(plain) || repeats(plain) && len(plain) >= 4 {
			return "is a run of characters along the keyboard or the alphabet, or a short pattern repeated"
		}
	}
	norm := keepAlnum(leet.Replace(lower))
	for _, p := range personal {
		for _, w := range append(strings.FieldsFunc(strings.ToLower(p), func(r rune) bool {
			return !unicode.IsLetter(r) && !unicode.IsDigit(r)
		}), keepAlnum(strings.ToLower(p))) {
			if w = keepAlnum(leet.Replace(w)); len([]rune(w)) >= 4 && strings.Contains(norm, w) {
				return "contains your name, email address or organization: choose something unrelated to you"
			}
		}
	}
	return ""
}

func distinct(s string) int {
	seen := map[rune]bool{}
	for _, r := range s {
		seen[r] = true
	}
	return len(seen)
}

func keepAlnum(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsLetter(r) || unicode.IsDigit(r) {
			return r
		}
		return -1
	}, s)
}

// inSequence reports whether s (at least 4 characters) lies along one of the sequences.
func inSequence(s string) bool {
	if len(s) < 4 {
		return false
	}
	for _, seq := range sequences {
		if strings.Contains(seq, s) {
			return true
		}
	}
	return false
}

// repeats reports whether s is a pattern of at most 3 characters over and over ("abcabcabc", "121212").
func repeats(s string) bool {
	r := []rune(s)
	for p := 1; p <= 3 && p*2 <= len(r); p++ {
		same := true
		for i := p; i < len(r); i++ {
			if r[i] != r[i-p] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	return false
}

// personalWords are the words that identify u: names, username, the parts of the email address, the organization,
// and the site itself.
func (s *Service) personalWords(ctx context.Context, u *model.User) []string {
	words := []string{u.GivenName, u.FamilyName, u.Username, s.Cfg.UI.SiteName}
	if local, domain, ok := strings.Cut(u.Email, "@"); ok { // split into words by weakPassword
		words = append(words, local)
		if host, _, ok := strings.Cut(domain, "."); ok {
			words = append(words, host)
		}
	}
	if u.OrgID != "" {
		if o, err := s.Orgs.Get(ctx, u.OrgID); err == nil {
			words = append(words, o.Name, o.DisplayName)
		}
	}
	return words
}

// CheckPassword checks a password u is choosing: the length (validatePassword), then that it is not easy to guess
// (weakPassword), with u's own details as words it must not be built on.
func (s *Service) CheckPassword(ctx context.Context, u *model.User, pw string) error {
	pw = secure.NormalizePassword(pw) // judged as it is hashed
	o, err := s.OrgPolicy(ctx, u.OrgID)
	if err != nil {
		return err
	}
	if err := s.validatePassword(o, pw); err != nil {
		return err
	}
	if why := weakPassword(pw, s.personalWords(ctx, u)); why != "" {
		return Invalid("password", why)
	}
	return nil
}
