package service

import "testing"

func TestWeakPassword(t *testing.T) {
	personal := []string{"Alice", "Example", "alice.smith", "Acme Corp", "Quisora"}
	weak := []string{
		"aaaaaaaaaaaa", "abababababab", "1212121212", // too few characters, repeats
		"1234567890", "abcdefghijk", "qwertyuiop", "asdfghjkl;'", "0987654321", "1qaz2wsx3edc", "zyxwvutsrq", // runs
		"Password2026!", "P@ssw0rd123", "welcome1!!!", "Summ3r2025", "!!Letmein99", "Qwerty12345", "iloveyou12", // common
		"Alice2026!!", "smith-rocks-99", "quisora12345", "Acme2026Corp", // personal
	}
	strong := []string{
		"correct horse battery staple", "a long enough password", "Tr0ub4dor&3xyz", "8475920193",
		"purple-elephant-dances", "Ma ternelle! 1999", "zh7#Lq2!pVw9", "alicorn meadows",
	}
	for _, pw := range weak {
		if weakPassword(pw, personal) == "" {
			t.Errorf("%q accepted", pw)
		}
	}
	for _, pw := range strong {
		if why := weakPassword(pw, personal); why != "" {
			t.Errorf("%q refused: %s", pw, why)
		}
	}
}
