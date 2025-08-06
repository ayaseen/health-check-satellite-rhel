// pkg/utils/command_executor.go

package utils

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

// CommandExecutor interface defines methods for executing commands
type CommandExecutor interface {
	RunCommand(name string, args ...string) (string, error)
	RunCommandWithTimeout(name string, timeout int, args ...string) (string, error)
	GetHostname() string
	IsLocal() bool
	Close() error
}

// LocalExecutor executes commands locally
type LocalExecutor struct {
	hostname     string
	useSudo      bool
	sudoMethod   string
	sudoUser     string
	sudoPassword string
}

// RemoteExecutor executes commands via SSH
type RemoteExecutor struct {
	hostname   string
	connection *SSHConnection
	mu         sync.Mutex
}

// executorInstance holds the current executor instance
var (
	executorInstance CommandExecutor
	executorMux      sync.RWMutex
)

// NewLocalExecutor creates a new local executor
func NewLocalExecutor() (*LocalExecutor, error) {
	hostname, err := RunCommand("hostname", "-f")
	if err != nil {
		hostname = "localhost"
	}
	return &LocalExecutor{
		hostname:   strings.TrimSpace(hostname),
		useSudo:    false,
		sudoMethod: "sudo",
		sudoUser:   "root",
	}, nil
}

// NewLocalExecutorWithSudo creates a new local executor with sudo configuration
func NewLocalExecutorWithSudo(useSudo bool, sudoMethod, sudoUser, sudoPassword string) (*LocalExecutor, error) {
	hostname, err := RunCommand("hostname", "-f")
	if err != nil {
		hostname = "localhost"
	}
	return &LocalExecutor{
		hostname:     strings.TrimSpace(hostname),
		useSudo:      useSudo,
		sudoMethod:   sudoMethod,
		sudoUser:     sudoUser,
		sudoPassword: sudoPassword,
	}, nil
}

// NewRemoteExecutor creates a new remote executor
func NewRemoteExecutor(config *SSHConfig) (*RemoteExecutor, error) {
	conn, err := NewSSHConnection(config)
	if err != nil {
		return nil, err
	}

	// Connect with retry logic
	maxRetries := 3
	var lastErr error

	for i := 0; i < maxRetries; i++ {
		if i > 0 {
			time.Sleep(time.Second * 2) // Wait before retry
		}

		if err := conn.Connect(); err != nil {
			lastErr = err
			continue
		}

		// Connection successful, get hostname
		hostname, err := conn.RunCommandWithTimeout("hostname", 5, "-f")
		if err != nil {
			hostname = config.Host
		}

		return &RemoteExecutor{
			hostname:   strings.TrimSpace(hostname),
			connection: conn,
		}, nil
	}

	return nil, fmt.Errorf("failed to establish SSH connection after %d attempts: %v", maxRetries, lastErr)
}

// RunCommand executes a command locally
func (e *LocalExecutor) RunCommand(name string, args ...string) (string, error) {
	// Apply sudo if configured
	if e.useSudo {
		return e.runWithSudo(name, args...)
	}
	return RunCommand(name, args...)
}

// RunCommandWithTimeout executes a command locally with timeout
func (e *LocalExecutor) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	// Apply sudo if configured
	if e.useSudo {
		return e.runWithSudoTimeout(name, timeout, args...)
	}
	return RunCommandWithTimeout(name, timeout, args...)
}

// runWithSudo executes a command with sudo
func (e *LocalExecutor) runWithSudo(name string, args ...string) (string, error) {
	var cmd string

	// Build the original command
	originalCmd := name
	if len(args) > 0 {
		// Properly escape arguments
		escapedArgs := make([]string, len(args))
		for i, arg := range args {
			escapedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
		}
		originalCmd = fmt.Sprintf("%s %s", name, strings.Join(escapedArgs, " "))
	}

	// Apply sudo based on method
	switch e.sudoMethod {
	case "su":
		if e.sudoPassword != "" {
			// su with password is complex - for now just use without password
			cmd = fmt.Sprintf("su - %s -c '%s'", e.sudoUser, originalCmd)
		} else {
			cmd = fmt.Sprintf("su - %s -c '%s'", e.sudoUser, originalCmd)
		}
		return RunCommand("bash", "-c", cmd)
	default: // sudo
		if e.sudoPassword != "" {
			// Use echo to provide password to sudo
			escapedPass := strings.ReplaceAll(e.sudoPassword, "'", "'\\''")
			cmd = fmt.Sprintf("echo '%s' | sudo -S -u %s %s", escapedPass, e.sudoUser, originalCmd)
			return RunCommand("bash", "-c", cmd)
		} else {
			// Try sudo without password (NOPASSWD)
			return RunCommand("sudo", append([]string{"-u", e.sudoUser, name}, args...)...)
		}
	}
}

// runWithSudoTimeout executes a command with sudo and timeout
func (e *LocalExecutor) runWithSudoTimeout(name string, timeout int, args ...string) (string, error) {
	var cmd string

	// Build the original command with timeout
	originalCmd := fmt.Sprintf("timeout %d %s", timeout, name)
	if len(args) > 0 {
		// Properly escape arguments
		escapedArgs := make([]string, len(args))
		for i, arg := range args {
			escapedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
		}
		originalCmd = fmt.Sprintf("timeout %d %s %s", timeout, name, strings.Join(escapedArgs, " "))
	}

	// Apply sudo based on method
	switch e.sudoMethod {
	case "su":
		cmd = fmt.Sprintf("su - %s -c '%s'", e.sudoUser, originalCmd)
		return RunCommand("bash", "-c", cmd)
	default: // sudo
		if e.sudoPassword != "" {
			// Use echo to provide password to sudo
			escapedPass := strings.ReplaceAll(e.sudoPassword, "'", "'\\''")
			cmd = fmt.Sprintf("echo '%s' | sudo -S -u %s %s", escapedPass, e.sudoUser, originalCmd)
			return RunCommand("bash", "-c", cmd)
		} else {
			// Try sudo without password (NOPASSWD)
			return RunCommand("sudo", append([]string{"-u", e.sudoUser, "timeout", fmt.Sprintf("%d", timeout), name}, args...)...)
		}
	}
}

// GetHostname returns the hostname
func (e *LocalExecutor) GetHostname() string {
	return e.hostname
}

// IsLocal returns true for local executor
func (e *LocalExecutor) IsLocal() bool {
	return true
}

// Close does nothing for local executor
func (e *LocalExecutor) Close() error {
	return nil
}

// RunCommand executes a command remotely
func (e *RemoteExecutor) RunCommand(name string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Ensure connection is still alive
	if e.connection == nil {
		return "", fmt.Errorf("remote connection is not established")
	}

	// Use a default timeout of 30 seconds for all commands
	return e.connection.RunCommandWithTimeout(name, 30, args...)
}

// RunCommandWithTimeout executes a command remotely with timeout
func (e *RemoteExecutor) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Ensure connection is still alive
	if e.connection == nil {
		return "", fmt.Errorf("remote connection is not established")
	}

	return e.connection.RunCommandWithTimeout(name, timeout, args...)
}

// GetHostname returns the remote hostname
func (e *RemoteExecutor) GetHostname() string {
	return e.hostname
}

// IsLocal returns false for remote executor
func (e *RemoteExecutor) IsLocal() bool {
	return false
}

// Close closes the remote connection
func (e *RemoteExecutor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	if e.connection != nil {
		return e.connection.Close()
	}
	return nil
}

// SetExecutor sets the global executor instance
func SetExecutor(executor CommandExecutor) {
	executorMux.Lock()
	defer executorMux.Unlock()

	// Close previous executor if it's a remote executor
	if executorInstance != nil && !executorInstance.IsLocal() {
		executorInstance.Close()
	}

	executorInstance = executor
}

// GetExecutor returns the current executor instance
func GetExecutor() CommandExecutor {
	executorMux.RLock()
	defer executorMux.RUnlock()

	if executorInstance == nil {
		// Default to local executor
		local, _ := NewLocalExecutor()
		return local
	}
	return executorInstance
}

// ExecuteCommand is a wrapper that uses the current executor
// This allows existing code to work with minimal changes
func ExecuteCommand(name string, args ...string) (string, error) {
	executor := GetExecutor()
	return executor.RunCommand(name, args...)
}

// ExecuteCommandWithTimeout is a wrapper that uses the current executor
func ExecuteCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	executor := GetExecutor()
	return executor.RunCommandWithTimeout(name, timeout, args...)
}
