package cmd

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/paularlott/cli"
	"github.com/paularlott/quisora/internal/config"
)

func healthcheckCmd(cfg *config.Config, flags []cli.Flag) *cli.Command {
	return &cli.Command{
		Name:  "healthcheck",
		Usage: "Exit 0 when the local server is alive (container health checks); --ready: when it is ready",
		Description: "Requests /healthz (liveness: the process answers) from the server on this host at server.listen " +
			"and exits 0 when it answers 200, 1 otherwise. With --ready it requests /readyz instead (readiness: the " +
			"node serves; a cluster node is not ready while it catches up or is cut off from the majority, which is " +
			"no reason to restart it — use readiness for load balancers, liveness for restarts). The certificate " +
			"is not verified: the request goes to this machine's own listener only.",
		Flags: append(flags, &cli.BoolFlag{Name: "ready", Usage: "Check readiness (/readyz) instead of liveness (/healthz)"}),
		Run: func(ctx context.Context, c *cli.Command) error {
			host, port, err := net.SplitHostPort(cfg.Server.Listen)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); host == "" || ip != nil && ip.IsUnspecified() {
				host = "127.0.0.1"
			}
			client := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // loopback probe of our own listener
				Proxy:           nil,
			}}
			probe, what := "/healthz", "not alive"
			if c.GetBool("ready") {
				probe, what = "/readyz", "not ready"
			}
			resp, err := client.Get("https://" + net.JoinHostPort(host, port) + probe)
			if err != nil {
				return err
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("%s: %s", what, resp.Status)
			}
			return nil
		},
	}
}
