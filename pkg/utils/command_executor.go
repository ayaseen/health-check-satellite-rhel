// pkg/utils/command_executor.go

package utils

import (
	"fmt"
	"strings"
	"sync"
)

// CommandExecutor interface defines methods for executing commands
type CommandExecutor interface {
	RunCommand(name string, args ...string) (string, error)
	RunCommandWithTimeout(name string, timeout int, args ...string) (string, error)
	GetHostname() string
	IsLocal() bool
}

// LocalExecutor executes commands locally
type LocalExecutor struct {
	hostname string
}

// RemoteExecutor executes commands via SSH
type RemoteExecutor struct {
	hostname   string
	connection *SSHConnection
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
	return &LocalExecutor{hostname: strings.TrimSpace(hostname)}, nil
}

// NewRemoteExecutor creates a new remote executor
func NewRemoteExecutor(config *SSHConfig) (*RemoteExecutor, error) {
	conn, err := NewSSHConnection(config)
	if err != nil {
		return nil, err
	}

	if err := conn.Connect(); err != nil {
		return nil, err
	}

	// Get remote hostname
	hostname, err := conn.RunCommand("hostname", "-f")
	if err != nil {
		hostname = config.Host
	}

	return &RemoteExecutor{
		hostname:   strings.TrimSpace(hostname),
		connection: conn,
	}, nil
}

// RunCommand executes a command locally
func (e *LocalExecutor) RunCommand(name string, args ...string) (string, error) {
	return RunCommand(name, args...)
}

// RunCommandWithTimeout executes a command locally with timeout
func (e *LocalExecutor) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	return RunCommandWithTimeout(name, timeout, args...)
}

// GetHostname returns the hostname
func (e *LocalExecutor) GetHostname() string {
	return e.hostname
}

// IsLocal returns true for local executor
func (e *LocalExecutor) IsLocal() bool {
	return true
}

// RunCommand executes a command remotely
func (e *RemoteExecutor) RunCommand(name string, args ...string) (string, error) {
	// Ensure connection is still alive
	if e.connection == nil || e.connection.Client == nil {
		return "", fmt.Errorf("remote connection is not established")
	}

	return e.connection.RunCommand(name, args...)
}

// RunCommandWithTimeout executes a command remotely with timeout
func (e *RemoteExecutor) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	// Ensure connection is still alive
	if e.connection == nil || e.connection.Client == nil {
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
	if e.connection != nil {
		return e.connection.Close()
	}
	return nil
}

// SetExecutor sets the global executor instance
func SetExecutor(executor CommandExecutor) {
	executorMux.Lock()
	defer executorMux.Unlock()
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
