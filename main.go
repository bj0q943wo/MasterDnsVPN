package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/BurntSushi/toml"
)

// Version information
const (
	AppName    = "MasterDnsVPN"
	AppVersion = "1.0.0"
)

// Config holds the top-level configuration loaded from the TOML file.
type Config struct {
	General  GeneralConfig  `toml:"general"`
	DNS      DNSConfig      `toml:"dns"`
	Tunnel   TunnelConfig   `toml:"tunnel"`
	Security SecurityConfig `toml:"security"`
}

// GeneralConfig contains general application settings.
type GeneralConfig struct {
	Mode       string `toml:"mode"`        // "client" or "server"
	LogLevel   string `toml:"log_level"`   // "debug", "info", "warn", "error"
	ConfigFile string `toml:"config_file"` // path to config file
}

// DNSConfig contains DNS-related settings.
type DNSConfig struct {
	ListenAddr  string   `toml:"listen_addr"`
	Upstream    []string `toml:"upstream"`
	Domains     []string `toml:"domains"`
	CacheEnable bool     `toml:"cache_enable"`
	CacheTTL    int      `toml:"cache_ttl"`
}

// TunnelConfig contains VPN tunnel settings.
type TunnelConfig struct {
	ServerAddr string `toml:"server_addr"`
	ServerPort int    `toml:"server_port"`
	LocalPort  int    `toml:"local_port"`
	Protocol   string `toml:"protocol"`  // "udp" or "tcp"
	MTU        int    `toml:"mtu"`
}

// SecurityConfig contains authentication and encryption settings.
type SecurityConfig struct {
	Token      string `toml:"token"`
	Encrypt    bool   `toml:"encrypt"`
	CipherSuite string `toml:"cipher_suite"`
}

func main() {
	// Parse command-line flags
	configPath := flag.String("config", "client_config.toml", "Path to configuration file")
	showVersion := flag.Bool("version", false, "Show version information")
	mode := flag.String("mode", "", "Override run mode: client or server")
	flag.Parse()

	if *showVersion {
		fmt.Printf("%s v%s\n", AppName, AppVersion)
		os.Exit(0)
	}

	log.Printf("Starting %s v%s", AppName, AppVersion)

	// Load configuration
	cfg, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config from %s: %v", *configPath, err)
	}

	// Override mode from flag if provided
	if *mode != "" {
		cfg.General.Mode = *mode
	}

	if cfg.General.Mode == "" {
		log.Fatal("Run mode must be specified (client or server)")
	}

	log.Printf("Running in %s mode", cfg.General.Mode)

	// Set up graceful shutdown
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// Start the appropriate service based on mode
	errCh := make(chan error, 1)
	switch cfg.General.Mode {
	case "client":
		go func() {
			errCh <- runClient(cfg)
		}()
	case "server":
		go func() {
			errCh <- runServer(cfg)
		}()
	default:
		log.Fatalf("Unknown mode: %s (expected 'client' or 'server')", cfg.General.Mode)
	}

	// Wait for signal or error
	select {
	case sig := <-sigCh:
		log.Printf("Received signal %s, shutting down...", sig)
	case err := <-errCh:
		if err != nil {
			log.Fatalf("Service error: %v", err)
		}
	}

	log.Println("Shutdown complete.")
}

// loadConfig reads and parses the TOML configuration file.
func loadConfig(path string) (*Config, error) {
	var cfg Config
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("decode config: %w", err)
	}
	return &cfg, nil
}

// runClient initialises and starts the VPN client.
func runClient(cfg *Config) error {
	log.Printf("Client connecting to %s:%d via %s",
		cfg.Tunnel.ServerAddr, cfg.Tunnel.ServerPort, cfg.Tunnel.Protocol)
	// TODO: implement client logic
	select {}
}

// runServer initialises and starts the VPN server.
func runServer(cfg *Config) error {
	log.Printf("Server listening on port %d via %s",
		cfg.Tunnel.ServerPort, cfg.Tunnel.Protocol)
	// TODO: implement server logic
	select {}
}
