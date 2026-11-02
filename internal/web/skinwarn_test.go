package web_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	logtesting "github.com/paularlott/logger/testing"
	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/webtest"
)

// A skin whose stylesheet styles another name than its folder's (the folder was renamed) is warned of at start, naming
// both; the server starts with it all the same, since the check reads the text, not the CSS, and may be wrong.
func TestSkinOtherNameWarns(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme-skin")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "skin.css"), []byte(`:root[data-skin="acme"]{}`), 0o644); err != nil {
		t.Fatal(err)
	}
	log := logtesting.New()
	env := webtest.New(t, webtest.Options{Log: log, Configure: func(c *config.Config) { c.UI.Skin = dir }})
	if env.Server.Site.Skin != "acme-skin" {
		t.Fatalf("skin not applied: %q", env.Server.Site.Skin)
	}
	for _, e := range log.GetEntries() {
		if e.Level == "warn" && strings.Contains(e.Message, `data-skin="acme"`) && strings.Contains(e.Message, "rename the folder") {
			return
		}
	}
	t.Fatalf("no warning: %v", log.GetEntries())
}
