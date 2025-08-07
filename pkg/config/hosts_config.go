// pkg/config/hosts_config.go

package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// HostsConfig represents the configuration for multiple hosts
type HostsConfig struct {
	Defaults DefaultConfig
	Hosts    []HostEntry
	Groups   map[string][]HostEntry
}

// DefaultConfig holds default settings for all hosts
type DefaultConfig struct {
	User                string
	Port                string
	Password            string // SSH password
	SSHKeyFile          string
	SSHTimeout          int
	ParallelConnections int
	// Privilege escalation settings
	Become       bool
	BecomeMethod string
	BecomeUser   string
	BecomePass   string
	BecomeFlags  string
}

// HostEntry represents a single host configuration
type HostEntry struct {
	Hostname   string
	Port       string
	User       string
	Password   string // SSH password
	SSHKeyFile string
	Type       string // "rhel" or "satellite"
	Group      string
	// Privilege escalation settings
	Become       bool
	BecomeMethod string
	BecomeUser   string
	BecomePass   string
	BecomeFlags  string
}

// NewHostsConfig creates a new hosts configuration with defaults
func NewHostsConfig() *HostsConfig {
	return &HostsConfig{
		Defaults: DefaultConfig{
			User:                "root",
			Port:                "22",
			Password:            "",
			SSHKeyFile:          "",
			SSHTimeout:          30,
			ParallelConnections: 5,
			Become:              false,
			BecomeMethod:        "sudo",
			BecomeUser:          "root",
			BecomePass:          "",
			BecomeFlags:         "",
		},
		Hosts:  []HostEntry{},
		Groups: make(map[string][]HostEntry),
	}
}

// LoadFromFile loads hosts configuration from an INI-style file
func (hc *HostsConfig) LoadFromFile(filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return fmt.Errorf("failed to open hosts file: %v", err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	currentGroup := ""
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		// Check for group headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentGroup = strings.Trim(line, "[]")

			// Handle special sections - support various naming conventions
			if currentGroup == "defaults" || currentGroup == "all:vars" {
				currentGroup = "defaults"
			} else if strings.Contains(currentGroup, "_hosts") || strings.Contains(currentGroup, "hosts") {
				// Initialize group if it doesn't exist
				if _, exists := hc.Groups[currentGroup]; !exists {
					hc.Groups[currentGroup] = []HostEntry{}
				}
			} else {
				// Initialize any other group
				if _, exists := hc.Groups[currentGroup]; !exists {
					hc.Groups[currentGroup] = []HostEntry{}
				}
			}
			continue
		}

		// Handle defaults section
		if currentGroup == "defaults" {
			if err := hc.parseDefaultLine(line); err != nil {
				// Don't fail on parse errors, just skip the line
				continue
			}
			continue
		}

		// Skip lines that look like variable assignments in host groups
		if strings.Contains(line, "=") && !strings.Contains(line, " ") {
			continue
		}

		// Parse host entry
		host, err := hc.parseHostLine(line, currentGroup)
		if err != nil {
			// Skip invalid host lines
			continue
		}

		// Apply defaults to host
		hc.applyDefaultsToHost(&host)

		// Add to appropriate collections
		hc.Hosts = append(hc.Hosts, host)
		if currentGroup != "" {
			hc.Groups[currentGroup] = append(hc.Groups[currentGroup], host)
		}
	}

	if err := scanner.Err(); err != nil {
		return fmt.Errorf("error reading hosts file: %v", err)
	}

	return nil
}

// parseDefaultLine parses a default configuration line
func (hc *HostsConfig) parseDefaultLine(line string) error {
	// Handle both = with and without spaces
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return fmt.Errorf("invalid default line format: %s", line)
	}

	key := strings.TrimSpace(parts[0])
	value := strings.TrimSpace(parts[1])

	// Remove ALL types of quotes (single, double, backticks)
	value = strings.Trim(value, "\"'`")
	// Also handle cases where quotes might be in the middle
	value = strings.ReplaceAll(value, "\"", "")

	switch key {
	case "user", "ssh_user":
		hc.Defaults.User = value
	case "port", "ssh_port":
		hc.Defaults.Port = value
	case "password", "ssh_password":
		hc.Defaults.Password = value
	case "ssh_key_file", "ssh_key":
		hc.Defaults.SSHKeyFile = expandPath(value)
	case "ssh_timeout", "timeout":
		if timeout, err := strconv.Atoi(value); err == nil {
			hc.Defaults.SSHTimeout = timeout
		}
	case "parallel_connections", "parallel":
		if parallel, err := strconv.Atoi(value); err == nil {
			hc.Defaults.ParallelConnections = parallel
		}
	case "become":
		hc.Defaults.Become = parseBool(value)
	case "become_method":
		hc.Defaults.BecomeMethod = value
	case "become_user":
		hc.Defaults.BecomeUser = value
	case "become_pass", "become_password":
		hc.Defaults.BecomePass = value
	case "become_flags":
		hc.Defaults.BecomeFlags = value
	}

	return nil
}

// parseHostLine parses a host configuration line
func (hc *HostsConfig) parseHostLine(line string, group string) (HostEntry, error) {
	host := HostEntry{
		Group: group,
		Type:  "rhel", // Default type
	}

	// Split by whitespace to get hostname and variables
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return host, fmt.Errorf("empty host line")
	}

	// First part is the hostname
	host.Hostname = parts[0]

	// Validate hostname
	if host.Hostname == "" || strings.HasPrefix(host.Hostname, "#") {
		return host, fmt.Errorf("invalid hostname")
	}

	// Parse variables (key=value pairs)
	for i := 1; i < len(parts); i++ {
		if strings.Contains(parts[i], "=") {
			keyValue := strings.SplitN(parts[i], "=", 2)
			if len(keyValue) != 2 {
				continue
			}

			key := strings.TrimSpace(keyValue[0])
			value := strings.TrimSpace(keyValue[1])

			// Remove quotes
			value = strings.Trim(value, "\"'`")

			switch key {
			case "user", "ssh_user":
				host.User = value
			case "port", "ssh_port":
				host.Port = value
			case "password", "ssh_password":
				host.Password = value
			case "ssh_key_file", "ssh_key":
				host.SSHKeyFile = expandPath(value)
			case "type":
				host.Type = value
			case "become":
				host.Become = parseBool(value)
			case "become_method":
				host.BecomeMethod = value
			case "become_user":
				host.BecomeUser = value
			case "become_pass", "become_password":
				host.BecomePass = value
			case "become_flags":
				host.BecomeFlags = value
			}
		}
	}

	return host, nil
}

// applyDefaultsToHost applies default values to a host entry
func (hc *HostsConfig) applyDefaultsToHost(host *HostEntry) {
	if host.Port == "" {
		host.Port = hc.Defaults.Port
	}
	if host.User == "" {
		host.User = hc.Defaults.User
	}
	if host.Password == "" {
		host.Password = hc.Defaults.Password
	}
	if host.SSHKeyFile == "" {
		host.SSHKeyFile = hc.Defaults.SSHKeyFile
	}

	// Apply privilege escalation defaults
	// Only apply become if not explicitly set in host line
	if !host.Become && hc.Defaults.Become {
		host.Become = hc.Defaults.Become
	}

	if host.BecomeMethod == "" {
		host.BecomeMethod = hc.Defaults.BecomeMethod
	}
	if host.BecomeUser == "" {
		host.BecomeUser = hc.Defaults.BecomeUser
	}
	if host.BecomePass == "" {
		host.BecomePass = hc.Defaults.BecomePass
	}
	if host.BecomeFlags == "" {
		host.BecomeFlags = hc.Defaults.BecomeFlags
	}
}

// GetAllHosts returns all configured hosts
func (hc *HostsConfig) GetAllHosts() []HostEntry {
	return hc.Hosts
}

// GetHostsByGroup returns hosts in a specific group
func (hc *HostsConfig) GetHostsByGroup(group string) []HostEntry {
	return hc.Groups[group]
}

// GetHost returns a specific host by name
func (hc *HostsConfig) GetHost(hostname string) (*HostEntry, bool) {
	for _, host := range hc.Hosts {
		if host.Hostname == hostname {
			return &host, true
		}
	}
	return nil, false
}

// expandPath expands ~ and environment variables in file paths
func expandPath(path string) string {
	if path == "" {
		return ""
	}

	// Expand ~ to home directory
	if strings.HasPrefix(path, "~/") {
		home, err := os.UserHomeDir()
		if err == nil {
			path = filepath.Join(home, path[2:])
		}
	}

	// Expand environment variables
	path = os.ExpandEnv(path)

	return path
}

// parseBool parses various boolean representations
func parseBool(value string) bool {
	value = strings.ToLower(strings.TrimSpace(value))
	return value == "true" || value == "yes" || value == "1" || value == "on"
}
