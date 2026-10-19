package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// backupPassword gets a backup's password: from passwordFile when given, else from standard input when it is a pipe
// and free (not carrying the backup itself), else by asking on the terminal (twice when confirm: a new backup). It is
// never a flag: a flag's value is visible to anyone on the machine (ps).
func backupPassword(passwordFile string, stdinFree, confirm bool) (string, error) {
	if passwordFile != "" {
		b, err := os.ReadFile(passwordFile)
		if err != nil {
			return "", fmt.Errorf("--password-file: %w", err)
		}
		return nonEmpty(firstLine(b), "--password-file "+passwordFile)
	}
	stdinTTY := term.IsTerminal(int(os.Stdin.Fd()))
	if !stdinTTY && stdinFree {
		b, err := io.ReadAll(io.LimitReader(os.Stdin, 4096))
		if err != nil {
			return "", fmt.Errorf("reading the password from standard input: %w", err)
		}
		return nonEmpty(firstLine(b), "standard input")
	}
	tty := os.Stdin
	if !stdinTTY {
		f, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
		if err != nil {
			return "", errors.New("the backup password is needed: give --password-file, pipe it on standard input, or run on a terminal")
		}
		defer f.Close()
		tty = f
	}
	ask := func(prompt string) (string, error) {
		fmt.Fprint(os.Stderr, prompt)
		b, err := term.ReadPassword(int(tty.Fd()))
		fmt.Fprintln(os.Stderr)
		return string(b), err
	}
	pw, err := ask("Backup password: ")
	if err != nil {
		return "", err
	}
	if confirm {
		again, err := ask("Again: ")
		if err != nil {
			return "", err
		}
		if again != pw {
			return "", errors.New("the passwords do not match")
		}
	}
	return nonEmpty(pw, "the terminal")
}

// firstLine is a password file's or pipe's content up to its first line break (a trailing newline is not part of
// the password).
func firstLine(b []byte) string {
	if i := bytes.IndexAny(b, "\r\n"); i >= 0 {
		b = b[:i]
	}
	return string(b)
}

func nonEmpty(pw, from string) (string, error) {
	if strings.TrimSpace(pw) == "" {
		return "", fmt.Errorf("no backup password from %s", from)
	}
	return pw, nil
}
