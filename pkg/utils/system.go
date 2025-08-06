// pkg/utils/system.go

package utils

import (
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"

	"github.com/alexmullins/zip"
)

// IsRHEL checks if the system is running RHEL
func IsRHEL() bool {
	// Check for the presence of /etc/redhat-release
	if _, err := os.Stat("/etc/redhat-release"); err == nil {
		// Read the file to confirm it's RHEL (not CentOS, Fedora, etc.)
		content, err := os.ReadFile("/etc/redhat-release")
		if err == nil {
			contentStr := strings.ToLower(string(content))
			return strings.Contains(contentStr, "red hat")
		}
	}

	// Secondary check via rpm
	cmd := exec.Command("rpm", "-q", "redhat-release")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// IsSatellite checks if the system is running Red Hat Satellite
func IsSatellite() bool {
	// Check for satellite-installer
	_, err := exec.LookPath("satellite-installer")
	if err == nil {
		return true
	}

	// Check for key Satellite packages
	satellitePackages := []string{"satellite", "katello", "foreman"}
	for _, pkg := range satellitePackages {
		cmd := exec.Command("rpm", "-q", pkg)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	// Check for key Satellite services
	satelliteServices := []string{"foreman", "postgresql", "pulp"}
	for _, svc := range satelliteServices {
		cmd := exec.Command("systemctl", "status", svc)
		if err := cmd.Run(); err == nil {
			return true
		}
	}

	return false
}

// RunningAsRoot checks if the tool is running with root/sudo privileges
func RunningAsRoot() bool {
	return os.Geteuid() == 0
}

// RunCommand executes a command and returns its output
// This now uses the executor interface to support both local and remote execution
func RunCommand(name string, args ...string) (string, error) {
	executor := GetExecutor()
	if executor != nil && !executor.IsLocal() {
		// Use the remote executor
		return executor.RunCommand(name, args...)
	}

	// Local execution
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), fmt.Errorf("command '%s %s' failed: %v", name, strings.Join(args, " "), err)
	}
	return string(output), nil
}

// RunCommandWithTimeout executes a command with a timeout
// This now uses the executor interface to support both local and remote execution
func RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	executor := GetExecutor()
	if executor != nil && !executor.IsLocal() {
		// Use the remote executor
		return executor.RunCommandWithTimeout(name, timeout, args...)
	}

	// Local execution with timeout
	timeoutArg := fmt.Sprintf("timeout %d %s %s", timeout, name, strings.Join(args, " "))

	cmd := exec.Command("bash", "-c", timeoutArg)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if strings.Contains(string(output), "timed out") || strings.Contains(err.Error(), "exit status 124") {
			return string(output), fmt.Errorf("command timed out after %d seconds", timeout)
		}
		return string(output), fmt.Errorf("command '%s' failed: %v", timeoutArg, err)
	}
	return string(output), nil
}

// CompressWithPassword compresses a file with password protection
func CompressWithPassword(sourcePath string, password string) (string, error) {
	// Check if source exists
	if _, err := os.Stat(sourcePath); err != nil {
		return "", fmt.Errorf("source file does not exist: %v", err)
	}

	// Create output filename
	outputPath := sourcePath + ".zip"

	// Create a new zip file
	zipFile, err := os.Create(outputPath)
	if err != nil {
		return "", fmt.Errorf("failed to create zip file: %v", err)
	}
	defer zipFile.Close()

	// Create a new zip writer with password
	zipWriter := zip.NewWriter(zipFile)
	defer zipWriter.Close()

	// Open the source file
	sourceFile, err := os.Open(sourcePath)
	if err != nil {
		return "", fmt.Errorf("failed to open source file: %v", err)
	}
	defer sourceFile.Close()

	// Get file info
	fileInfo, err := sourceFile.Stat()
	if err != nil {
		return "", fmt.Errorf("failed to get file info: %v", err)
	}

	// Create a new file header
	header, err := zip.FileInfoHeader(fileInfo)
	if err != nil {
		return "", fmt.Errorf("failed to create file header: %v", err)
	}

	// Set compression method
	header.Method = zip.Deflate

	// Set password
	header.SetPassword(password)

	// Create a writer for this file
	writer, err := zipWriter.CreateHeader(header)
	if err != nil {
		return "", fmt.Errorf("failed to create file in zip: %v", err)
	}

	// Copy the file contents
	_, err = io.Copy(writer, sourceFile)
	if err != nil {
		return "", fmt.Errorf("failed to write file to zip: %v", err)
	}

	return outputPath, nil
}

// GetRedHatVersion returns the major version of RHEL (e.g., "7", "8", "9")
func GetRedHatVersion() string {
	content, err := os.ReadFile("/etc/redhat-release")
	if err != nil {
		return "8" // Default to RHEL 8
	}

	// Parse version from content
	// Example: "Red Hat Enterprise Linux release 8.9 (Ootpa)"
	contentStr := string(content)
	parts := strings.Fields(contentStr)

	for i, part := range parts {
		if part == "release" && i+1 < len(parts) {
			version := parts[i+1]
			// Extract major version
			if dotIndex := strings.Index(version, "."); dotIndex > 0 {
				return version[:dotIndex]
			}
			return version
		}
	}

	return "8" // Default to RHEL 8
}
