//go:build darwin || linux

package vlogs

import (
	"bytes"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
	"testing"
)

// Exercise a real partial os.File.Write error, not only a preconstructed torn
// line. The file-size limit belongs to an isolated test subprocess.
func TestFreshSpoolRecoversAfterRealPartialWriteError(t *testing.T) {
	if dir := os.Getenv("QUISORA_FRESH_SHORT_APPEND_DIR"); dir != "" {
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
		_, body, _, _ := s.oldest()
		if !bytes.Contains(body, []byte("accepted-after-recovery")) {
			t.Fatalf("accepted event lost after real partial-write error %v: replay %s", writeErr, body)
		}
		return
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, "-test.run=^TestFreshSpoolRecoversAfterRealPartialWriteError$")
	cmd.Env = append(os.Environ(), "QUISORA_FRESH_SHORT_APPEND_DIR="+t.TempDir())
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("subprocess: %v\n%s", err, out)
	}
}
