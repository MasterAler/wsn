package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/MasterAler/wsn/internal/config"
	"github.com/MasterAler/wsn/internal/relay"
)

func main() {
	if len(os.Args) > 1 && os.Args[1] == "healthcheck" {
		healthcheck(os.Args[2:])
		return
	}
	flags := flag.NewFlagSet("wsn-server", flag.ExitOnError)
	configPath := flags.String("config", "/etc/wsn/server.json", "relay configuration file")
	_ = flags.Parse(os.Args[1:])
	cfg, err := config.LoadRelay(*configPath)
	if err != nil {
		fatal(err)
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	reload := make(chan config.Relay)
	go watchReload(ctx, *configPath, reload, logger)
	logger.Info("relay starting", "listen", cfg.Listen, "path", cfg.Path, "configured_clients", len(cfg.Clients))
	if err := relay.ListenAndServe(ctx, cfg, reload, logger); err != nil {
		fatal(err)
	}
	logger.Info("relay stopped")
}

// watchReload re-reads the relay configuration on SIGHUP so that clients added
// or revoked on the administrator machine take effect without dropping the
// sessions of everybody else. A configuration that fails to parse is reported
// and the running one is kept.
func watchReload(ctx context.Context, path string, reload chan<- config.Relay, logger *slog.Logger) {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP)
	defer signal.Stop(signals)
	for {
		select {
		case <-ctx.Done():
			return
		case <-signals:
			updated, err := config.LoadRelay(path)
			if err != nil {
				logger.Error("reload failed; keeping the running configuration", "error", err)
				continue
			}
			select {
			case reload <- updated:
			case <-ctx.Done():
				return
			}
		}
	}
}

func healthcheck(args []string) {
	flags := flag.NewFlagSet("healthcheck", flag.ExitOnError)
	url := flags.String("url", "http://127.0.0.1:8080/healthz", "health URL")
	_ = flags.Parse(args)
	client := http.Client{Timeout: 3 * time.Second}
	response, err := client.Get(*url)
	if err != nil {
		fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		fatal(fmt.Errorf("healthcheck returned %s", response.Status))
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wsn-server:", err)
	os.Exit(1)
}
