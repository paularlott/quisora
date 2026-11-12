package backup

import (
	"bytes"
	"context"
	"fmt"
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
	var plain bytes.Buffer // an encrypted backup, despite the name
	if _, err := WriteWith(ctx, src, s, &plain, Options{Password: covPassword}); err != nil {
		t.Fatal(err)
	}
	raw, _ := Unpack(plain.Bytes(), covPassword)
	newer := bytes.Replace(raw, []byte(fmt.Sprintf(`"version":%d`, version)), []byte(`"version":99`), 1)
	gz, _ := Pack(newer, covPassword)
	if _, err := Verify(bytes.NewReader(gz), s, covPassword); err == nil || !strings.Contains(err.Error(), "not supported by this build") {
		t.Fatalf("a newer backup: %v", err)
	}
}
