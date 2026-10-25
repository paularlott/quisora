package web_test

import (
	"net/url"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

func webtestSystem() *service.Actor { return service.System }

func userInput(name string) service.UserInput {
	s := func(v string) *string { return &v }
	return service.UserInput{GivenName: s(name), Username: s(name), Email: s(name + "@example.com")}
}

func mustURL(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}
