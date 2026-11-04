package oidc

import "testing"

// Codes of one browser session exchanged at the same moment (applications signed in to at once) all get their tokens:
// each grant is written with the session, so they take turns (grantAttempts) rather than failing with a 503.
func TestCodesOfOneSessionExchangedTogether(t *testing.T) {
	t.Parallel()
	h := setup(t, nil)
	cl, secret := h.newClient(nil)
	c, _ := h.session(h.user)
	const n = 16
	type pair struct{ code, verifier string }
	codes := make([]pair, n)
	for i := range codes {
		v, ch := pkce()
		codes[i] = pair{h.getCode(c, cl, ch, nil), v}
	}
	statuses := make(chan int, n)
	start := make(chan struct{})
	for _, p := range codes {
		go func() {
			<-start
			statuses <- h.exchangeCode(cl, secret, p.code, p.verifier).status
		}()
	}
	close(start)
	for range n {
		if st := <-statuses; st != 200 {
			t.Errorf("an exchange answered %d", st)
		}
	}
}
