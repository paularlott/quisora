package backup

import (
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/paularlott/quisora/internal/config"
	"github.com/paularlott/quisora/internal/secure"
	"github.com/paularlott/quisora/internal/service"
	"github.com/paularlott/quisora/internal/store/memstore"
)

// A backup of a version this build does not read (here: from a newer build) is refused before anything is written.
func TestBackupVersionWindow(t *testing.T) {
	ctx := context.Background()
	cfg := config.Default()
	cfg.Limits.PasswordWorkers = 1
	s, _ := secure.NewSealer(secure.RandomBytes(32))
	src := memstore.New()
	if _, _, err := service.New(cfg, src, s).Bootstrap(ctx, "root@example.com"); err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if _, err := Write(ctx, src, s, &plain); err != nil {
		t.Fatal(err)
	}
	zr, _ := gzip.NewReader(&plain)
	raw, _ := io.ReadAll(zr)
	newer := bytes.Replace(raw, []byte(fmt.Sprintf(`"version":%d`, version)), []byte(`"version":99`), 1)
	var gz bytes.Buffer
	zw := gzip.NewWriter(&gz)
	_, _ = zw.Write(newer)
	_ = zw.Close()
	if _, err := Verify(bytes.NewReader(gz.Bytes()), s, ""); err == nil || !strings.Contains(err.Error(), "not supported by this build") {
		t.Fatalf("a newer backup: %v", err)
	}
}
