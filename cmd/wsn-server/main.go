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
	logger.Info("relay starting", "listen", cfg.Listen, "path", cfg.Path, "configured_clients", len(cfg.Clients))
	if err := relay.ListenAndServe(ctx, cfg, logger); err != nil {
		fatal(err)
	}
	logger.Info("relay stopped")
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
