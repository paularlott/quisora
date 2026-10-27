package web

import (
	"net/http/httptest"
	"strings"
	"testing"

	webassets "github.com/paularlott/quisora/web"
)

func TestFooterHTML(t *testing.T) {
	for in, want := range map[string]string{
		"":                        "",
		"Quisora demo · All data": "Quisora demo · All data",
		"Tom & Jerry <3":          "Tom &amp; Jerry &lt;3",
		`© 2026 <a href="https://fortix.com">Fortix</a>`:                `© 2026 <a href="https://fortix.com">Fortix</a>`,
		`<a href="mailto:help@example.com" title="Mail us">Support</a>`: `<a href="mailto:help@example.com" title="Mail us">Support</a>`,
		`<a href="/privacy">Privacy</a>`:                                `<a href="/privacy">Privacy</a>`,
		`<strong>Bold</strong> <em>it</em><br><small>s</small>`:         `<strong>Bold</strong> <em>it</em><br><small>s</small>`,
		// unsafe links lose their href, other attributes go
		`<a href="javascript:alert(1)">x</a>`:                                                `<a>x</a>`,
		`<a href=" JavaScript:alert(1)">x</a>`:                                               `<a>x</a>`,
		`<a href="//evil.example/">x</a>`:                                                    `<a>x</a>`,
		`<a href="https://u:p@example.com/">x</a>`:                                           `<a>x</a>`,
		`<a href="data:text/html,x">x</a>`:                                                   `<a>x</a>`,
		`<a href="https://a.example/" onclick="x()" style="color:red" target="_blank">x</a>`: `<a href="https://a.example/">x</a>`,
		`<span class="x" onmouseover="y()">s</span>`:                                         `<span>s</span>`,
		// other elements go, keeping their text unless they are scripts and the like
		`<div>a</div><img src=x onerror=alert(1)>b`:      `ab`,
		`a<script>alert(1)</script>b<style>p{}</style>c`: `abc`,
		`<svg><script>alert(1)</script></svg>ok`:         `ok`,
		// unbalanced markup is closed, stray end tags dropped
		`<strong>open <em>both`: `<strong>open <em>both</em></strong>`,
		`a</strong>b</a>`:       `ab`,
		`<b><i>x</b>y</i>`:      `<b><i>x</i></b>y`,
		`"quoted" 'single'`:     `&#34;quoted&#34; &#39;single&#39;`,
	} {
		if got := string(FooterHTML(in)); got != want {
			t.Errorf("FooterHTML(%q)\n got %q\nwant %q", in, got, want)
		}
	}
}

// The layouts write the footer as markup.
func TestFooterRendered(t *testing.T) {
	r, err := NewRenderer(webassets.Templates, webassets.Dist)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	r.Render(rec, 200, "not-found", &Page{Data: map[string]any{}, Site: Site{Name: "Q", Footer: FooterHTML(`© 2026 <a href="https://fortix.com">Fortix</a><script>x</script>`)}})
	if body := rec.Body.String(); !strings.Contains(body, `<p>© 2026 <a href="https://fortix.com">Fortix</a></p>`) {
		t.Errorf("footer not rendered as markup:\n%s", body)
	}
}
