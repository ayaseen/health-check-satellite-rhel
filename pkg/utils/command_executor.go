// pkg/utils/command_executor.go

package utils

import (
	"fmt"
	"os/exec"
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
	// Get hostname locally
	cmd := exec.Command("hostname", "-f")
	output, err := cmd.CombinedOutput()
	hostname := "localhost"
	if err == nil {
		hostname = strings.TrimSpace(string(output))
	}

	return &LocalExecutor{
		hostname:   hostname,
		useSudo:    false,
		sudoMethod: "sudo",
		sudoUser:   "root",
	}, nil
}

// NewLocalExecutorWithSudo creates a new local executor with sudo configuration
func NewLocalExecutorWithSudo(useSudo bool, sudoMethod, sudoUser, sudoPassword string) (*LocalExecutor, error) {
	exec, err := NewLocalExecutor()
	if err != nil {
		return nil, err
	}
	exec.useSudo = useSudo
	exec.sudoMethod = sudoMethod
	exec.sudoUser = sudoUser
	exec.sudoPassword = sudoPassword
	return exec, nil
}

// NewRemoteExecutor creates a new remote executor
func NewRemoteExecutor(config *SSHConfig) (*RemoteExecutor, error) {
	conn, err := NewSSHConnection(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH connection: %v", err)
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

		// Connection successful, test it
		testOutput, err := conn.RunCommandWithTimeout("echo", 5, "test")
		if err != nil {
			lastErr = fmt.Errorf("connection test failed: %v", err)
			conn.Close()
			continue
		}

		if !strings.Contains(testOutput, "test") {
			lastErr = fmt.Errorf("unexpected test output: %s", testOutput)
			conn.Close()
			continue
		}

		// Get hostname from remote system
		hostname := config.Host
		hostnameOutput, err := conn.RunCommandWithTimeout("hostname", 5, "-f")
		if err == nil && hostnameOutput != "" {
			hostname = strings.TrimSpace(hostnameOutput)
		}

		return &RemoteExecutor{
			hostname:   hostname,
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

	// Direct local execution
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// RunCommandWithTimeout executes a command locally with timeout
func (e *LocalExecutor) RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	// Apply sudo if configured
	if e.useSudo {
		return e.runWithSudoTimeout(name, timeout, args...)
	}

	// Build timeout command
	timeoutArgs := []string{fmt.Sprintf("%d", timeout), name}
	timeoutArgs = append(timeoutArgs, args...)
	cmd := exec.Command("timeout", timeoutArgs...)
	output, err := cmd.CombinedOutput()
	return string(output), err
}

// runWithSudo executes a command with sudo
func (e *LocalExecutor) runWithSudo(name string, args ...string) (string, error) {
	// Build the command
	var cmd *exec.Cmd

	switch e.sudoMethod {
	case "su":
		// Build command string
		cmdStr := name
		if len(args) > 0 {
			escapedArgs := make([]string, len(args))
			for i, arg := range args {
				escapedArgs[i] = fmt.Sprintf("'%s'", strings.ReplaceAll(arg, "'", "'\\''"))
			}
			cmdStr = fmt.Sprintf("%s %s", name, strings.Join(escapedArgs, " "))
		}
		cmd = exec.Command("su", "-", e.sudoUser, "-c", cmdStr)
	default: // sudo
		sudoArgs := []string{"-u", e.sudoUser}
		if e.sudoPassword != "" {
			sudoArgs = append(sudoArgs, "-S")
		}
		sudoArgs = append(sudoArgs, name)
		sudoArgs = append(sudoArgs, args...)
		cmd = exec.Command("sudo", sudoArgs...)

		if e.sudoPassword != "" {
			cmd.Stdin = strings.NewReader(e.sudoPassword + "\n")
		}
	}

	output, err := cmd.CombinedOutput()
	return string(output), err
}

// runWithSudoTimeout executes a command with sudo and timeout
func (e *LocalExecutor) runWithSudoTimeout(name string, timeout int, args ...string) (string, error) {
	// For local with sudo and timeout, combine them
	timeoutArgs := []string{fmt.Sprintf("%d", timeout), name}
	timeoutArgs = append(timeoutArgs, args...)
	return e.runWithSudo("timeout", timeoutArgs...)
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
// THIS IS THE KEY METHOD FOR REMOTE EXECUTION
func (e *RemoteExecutor) RunCommand(name string, args ...string) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	// Ensure connection is still alive
	if e.connection == nil {
		return "", fmt.Errorf("remote connection is not established")
	}

	// For remote execution, we need to be careful with command building
	// If the command is already "bash -c", just pass it through
	if name == "bash" && len(args) >= 2 && args[0] == "-c" {
		// This is already a bash command, execute as-is
		return e.connection.RunCommandWithTimeout(name, 60, args...)
	}

	// For simple commands, execute directly
	return e.connection.RunCommandWithTimeout(name, 60, args...)
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
		err := e.connection.Close()
		e.connection = nil
		return err
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
func ExecuteCommand(name string, args ...string) (string, error) {
	executor := GetExecutor()
	return executor.RunCommand(name, args...)
}

// ExecuteCommandWithTimeout is a wrapper that uses the current executor
func ExecuteCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	executor := GetExecutor()
	return executor.RunCommandWithTimeout(name, timeout, args...)
}
