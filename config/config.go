// Package config provides configuration structures and loading utilities
// for the MasterDnsVPN client and server.
package config

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
)

// ClientConfig holds all configuration options for the VPN client.
type ClientConfig struct {
	General  GeneralConfig  `toml:"general"`
	Server   ServerConfig   `toml:"server"`
	DNS      DNSConfig      `toml:"dns"`
	Tunnel   TunnelConfig   `toml:"tunnel"`
	Logging  LoggingConfig  `toml:"logging"`
}

// GeneralConfig contains general settings shared between client and server.
type GeneralConfig struct {
	Mode       string `toml:"mode"`        // "client" or "server"
	ConfigFile string `toml:"config_file"` // Path to config file
}

// ServerConfig holds the remote server connection details.
type ServerConfig struct {
	Host     string `toml:"host"`      // Server hostname or IP
	Port     int    `toml:"port"`      // Server port
	Password string `toml:"password"`  // Authentication password
	Protocol string `toml:"protocol"`  // "tcp" or "udp"
	Timeout  int    `toml:"timeout"`   // Connection timeout in seconds
}

// DNSConfig holds DNS-over-VPN tunnel settings.
type DNSConfig struct {
	Enabled       bool     `toml:"enabled"`        // Enable DNS tunneling
	ListenAddr    string   `toml:"listen_addr"`    // Local DNS listen address
	ListenPort    int      `toml:"listen_port"`    // Local DNS listen port
	UpstreamDNS   []string `toml:"upstream_dns"`   // Upstream DNS servers
	DomainSuffix  string   `toml:"domain_suffix"`  // Domain suffix for tunneling
	MaxPacketSize int      `toml:"max_packet_size"` // Max DNS packet size in bytes
}

// TunnelConfig holds virtual network tunnel interface settings.
type TunnelConfig struct {
	Interface  string `toml:"interface"`   // TUN interface name
	LocalIP    string `toml:"local_ip"`    // Local tunnel IP address
	RemoteIP   string `toml:"remote_ip"`   // Remote tunnel IP address
	SubnetMask string `toml:"subnet_mask"` // Tunnel subnet mask
	MTU        int    `toml:"mtu"`         // Maximum Transmission Unit
}

// LoggingConfig controls log output behavior.
type LoggingConfig struct {
	Level  string `toml:"level"`   // "debug", "info", "warn", "error"
	File   string `toml:"file"`    // Log file path (empty = stdout)
	Format string `toml:"format"`  // "text" or "json"
}

// LoadClientConfig reads and parses a TOML configuration file.
// Returns a populated ClientConfig or an error if loading fails.
func LoadClientConfig(path string) (*ClientConfig, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, fmt.Errorf("config file not found: %s", path)
	}

	var cfg ClientConfig
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config file: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	return &cfg, nil
}

// Validate checks that required configuration fields are set and valid.
func (c *ClientConfig) Validate() error {
	if c.Server.Host == "" {
		return fmt.Errorf("server.host is required")
	}
	if c.Server.Port <= 0 || c.Server.Port > 65535 {
		return fmt.Errorf("server.port must be between 1 and 65535")
	}
	if c.Server.Protocol != "tcp" && c.Server.Protocol != "udp" {
		return fmt.Errorf("server.protocol must be \"tcp\" or \"udp\"")
	}
	if c.Tunnel.MTU <= 0 {
		c.Tunnel.MTU = 1500 // Set default MTU
	}
	if c.DNS.MaxPacketSize <= 0 {
		c.DNS.MaxPacketSize = 512 // Set default DNS packet size
	}
	return nil
}

// ServerAddress returns the formatted server address string (host:port).
func (s *ServerConfig) ServerAddress() string {
	return fmt.Sprintf("%s:%d", s.Host, s.Port)
}

// DNSListenAddress returns the formatted DNS listen address string.
func (d *DNSConfig) DNSListenAddress() string {
	return fmt.Sprintf("%s:%d", d.ListenAddr, d.ListenPort)
}
