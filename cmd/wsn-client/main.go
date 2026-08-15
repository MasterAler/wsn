package main

import (
	"flag"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"

	clientcore "github.com/MasterAler/wsn/internal/client"
	"github.com/MasterAler/wsn/internal/config"
	"github.com/MasterAler/wsn/internal/daemon"
	"github.com/MasterAler/wsn/internal/netcheck"
)

func main() {
	flags := flag.NewFlagSet("wsn-client", flag.ExitOnError)
	configPath := flags.String("config", "/etc/wsn/client.json", "client configuration file")
	checkNetwork := flags.String("check-network", "", "validate routes as client or gateway, then exit")
	egress := flags.String("egress", "", "gateway egress interface for route validation")
	_ = flags.Parse(os.Args[1:])
	logOutput, serviceLog, err := daemon.LogOutput(filepath.Dir(*configPath))
	if err != nil {
		fatal(err)
	}
	defer logOutput.Close()
	cfg, err := config.LoadClient(*configPath)
	if err != nil {
		fatalTo(logOutput, serviceLog, err)
	}
	if *checkNetwork != "" {
		switch *checkNetwork {
		case "client":
			fatalIf(netcheck.Client(cfg))
		case "gateway":
			if *egress == "" {
				fatal(fmt.Errorf("-egress is required for gateway validation"))
			}
			fatalIf(netcheck.Gateway(cfg, *egress))
		default:
			fatal(fmt.Errorf("-check-network must be client or gateway"))
		}
		fmt.Println("network configuration is safe to install")
		return
	}
	logger := slog.New(slog.NewJSONHandler(logOutput, nil))
	runner, err := clientcore.New(cfg, logger)
	if err != nil {
		fatalTo(logOutput, serviceLog, err)
	}
	if err := daemon.Run("WSNClient", runner.Run); err != nil {
		fatalTo(logOutput, serviceLog, err)
	}
}

func fatalIf(err error) {
	if err != nil {
		fatal(err)
	}
}

func fatal(err error) {
	fmt.Fprintln(os.Stderr, "wsn-client:", err)
	os.Exit(1)
}

func fatalTo(output io.Writer, serviceLog bool, err error) {
	if serviceLog {
		fmt.Fprintln(output, "wsn-client:", err)
	}
	fatal(err)
}
