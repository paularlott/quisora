package web

import (
	"html/template"
	"net/url"
	"strings"

	"golang.org/x/net/html"
	"golang.org/x/net/html/atom"
)

// footerTags are the elements ui.footer may use; anything else is dropped, keeping its text (but not the contents of
// script, style and similar elements).
var footerTags = map[atom.Atom]bool{
	atom.A: true, atom.B: true, atom.Br: true, atom.Em: true, atom.I: true, atom.Small: true, atom.Span: true,
	atom.Strong: true,
}

// footerDropped are elements whose contents are dropped along with them.
var footerDropped = map[atom.Atom]bool{
	atom.Script: true, atom.Style: true, atom.Template: true, atom.Textarea: true, atom.Title: true, atom.Noscript: true,
	atom.Iframe: true, atom.Object: true, atom.Svg: true, atom.Math: true,
}

// FooterHTML returns ui.footer as markup for the page footer. The footer may hold a little inline HTML (links and text
// emphasis); everything else is removed, attributes other than a link's href and title included, and a link's href
// must be http, https, mailto or a path on this site. Plain text comes out escaped as it would without markup.
func FooterHTML(s string) template.HTML {
	var b strings.Builder
	var open []atom.Atom // allowed elements still open, closed at the end
	skip := 0            // depth inside a dropped element
	z := html.NewTokenizerFragment(strings.NewReader(s), "p")
	for {
		tt := z.Next()
		if tt == html.ErrorToken {
			break
		}
		t := z.Token()
		switch tt {
		case html.TextToken:
			if skip == 0 {
				b.WriteString(html.EscapeString(t.Data))
			}
		case html.StartTagToken, html.SelfClosingTagToken:
			if footerDropped[t.DataAtom] {
				if tt == html.StartTagToken {
					skip++
				}
				continue
			}
			if skip > 0 || !footerTags[t.DataAtom] {
				continue
			}
			b.WriteString("<" + t.DataAtom.String())
			if t.DataAtom == atom.A {
				for _, a := range t.Attr {
					if a.Namespace != "" {
						continue
					}
					switch {
					case a.Key == "href" && footerHref(a.Val):
						b.WriteString(` href="` + html.EscapeString(strings.TrimSpace(a.Val)) + `"`)
					case a.Key == "title":
						b.WriteString(` title="` + html.EscapeString(a.Val) + `"`)
					}
				}
			}
			b.WriteString(">")
			if t.DataAtom != atom.Br && tt == html.StartTagToken {
				open = append(open, t.DataAtom)
			}
		case html.EndTagToken:
			if footerDropped[t.DataAtom] {
				if skip > 0 {
					skip--
				}
				continue
			}
			if skip > 0 {
				continue
			}
			// close up to the matching open element; a stray end tag is ignored
			for i := len(open) - 1; i >= 0; i-- {
				if open[i] == t.DataAtom {
					for j := len(open) - 1; j >= i; j-- {
						b.WriteString("</" + open[j].String() + ">")
					}
					open = open[:i]
					break
				}
			}
		}
	}
	for i := len(open) - 1; i >= 0; i-- {
		b.WriteString("</" + open[i].String() + ">")
	}
	return template.HTML(b.String()) // built from the allowlist above, with every text and attribute escaped
}

// footerHref reports whether a footer link may point at v: an http, https or mailto URL, or a path on this site.
func footerHref(v string) bool {
	v = strings.TrimSpace(v)
	u, err := url.Parse(v)
	if err != nil {
		return false
	}
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u.Host != "" && u.User == nil
	case "mailto":
		return true
	case "":
		return u.Host == "" && strings.HasPrefix(u.Path, "/") && !strings.HasPrefix(v, "//")
	}
	return false
}
