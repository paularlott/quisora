package cmd

import (
	"os"
	"strings"
	"testing"
)

func TestConfirmSignOutNeedsTerminal(t *testing.T) {
	old := os.Stdin
	defer func() { os.Stdin = old }()
	r, w, _ := os.Pipe()
	w.Close()
	os.Stdin = r
	if err := confirmSignOut("everyone", "everyone", true); err == nil || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("%v", err)
	}
}
