package cmd

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/cluster"
)

func TestForceStart(t *testing.T) {
	e := newEnv(t, "")
	if _, _, err := e.run(t, "", "force-start"); err == nil || !strings.Contains(err.Error(), "not part of a gossip cluster") {
		t.Fatalf("without cluster.bind: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(make([]byte, 32))
	e = newEnv(t, "[cluster]\nbind = \"127.0.0.1:7946\"\nsize = 2\npeers = [\"127.0.0.1:7947\"]\nkey = \""+key+"\"\n")
	_, errOut, err := e.run(t, "", "force-start")
	if err != nil || !strings.Contains(errOut, "next start") {
		t.Fatalf("force-start: %v %q", err, errOut)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "data", cluster.ForceStartMarker)); err != nil {
		t.Fatalf("marker: %v", err)
	}
}
