//go:build darwin || linux

package vlogs

import (
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// A real partial write (the file-size limit cuts an append short with an error, not a constructed torn line) is
// undone, and the next accepted event replays. The limit is set in a subprocess so it binds nothing else.
func TestSpoolRecoversAfterRealPartialWriteError(t *testing.T) {
	if dir := os.Getenv("QUISORA_SHORT_APPEND_DIR"); dir != "" {
		signal.Ignore(syscall.SIGXFSZ)
		s, err := newSpool(dir, 1)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := s.store([]byte("{\"id\":\"first\"}\n")); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, s.active))
		if err != nil {
			t.Fatal(err)
		}
		var original syscall.Rlimit
		if err := syscall.Getrlimit(syscall.RLIMIT_FSIZE, &original); err != nil {
			t.Fatal(err)
		}
		limited := original
		limited.Cur = uint64(info.Size() + 6)
		if err := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &limited); err != nil {
			t.Fatal(err)
		}
		_, writeErr := s.store([]byte("{\"id\":\"failed-append\"}\n"))
		restoreErr := syscall.Setrlimit(syscall.RLIMIT_FSIZE, &original)
		if restoreErr != nil {
			t.Fatal(restoreErr)
		}
		if writeErr == nil {
			t.Fatal("setup: file-size limit did not reject partial append")
		}
		if _, err := s.store([]byte("{\"id\":\"accepted-after-recovery\"}\n")); err != nil {
			t.Fatal(err)
		}
		if _, body, _, _ := s.oldest(); strings.Join(ids(body), ",") != "first,accepted-after-recovery" {
			t.Fatalf("replay after a real partial-write error (%v): %q", writeErr, body)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestSpoolRecoversAfterRealPartialWriteError$")
	cmd.Env = append(os.Environ(), "QUISORA_SHORT_APPEND_DIR="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}
