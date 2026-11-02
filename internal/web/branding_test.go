package web

import (
	"regexp"
	"testing"

	"github.com/paularlott/quisora/internal/service"
)

// The stylesheet of any primary colour accepted (white text on it at 4.5:1) gives link text and focus rings that read
// at 4.5:1 on the light and the dark page.
func TestBrandCSSContrast(t *testing.T) {
	text := regexp.MustCompile(`--accent: light-dark\((#[0-9a-f]{6}), (#[0-9a-f]{6})\)`)
	for _, c := range []string{"#1d4ed8", "#0f766e", "#b91c1c", "#000000", "#4b0082", "#767676", "#c2410c"} {
		if service.Contrast(c, "#ffffff") < 4.5 {
			t.Fatalf("%s is not a colour the service accepts", c)
		}
		m := text.FindStringSubmatch(brandCSS(c))
		if m == nil {
			t.Fatalf("%s: %s", c, brandCSS(c))
		}
		if service.Contrast(m[1], "#e6ebfc") < 4.5 || service.Contrast(m[2], "#1c2944") < 4.5 {
			t.Errorf("%s: light %s, dark %s", c, m[1], m[2])
		}
	}
}
