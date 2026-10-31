// Package sshe2e holds the end-to-end test of the SSH certificate authority against a real OpenSSH server
// (docs/design/ssh-ca.md, "Tests"): an in-process Quisora signs certificates, the `quisora ssh` client code (internal/sshcli)
// signs in and fetches the trust files, and the system's ssh logs in to an Ubuntu sshd in a Docker container that
// trusts the tenant's CA, its revocation list and its host CA.
//
// The test is skipped unless QUISORA_SSH_E2E=1 and Docker works (task test-ssh-e2e sets it); it has no other files.
package sshe2e
