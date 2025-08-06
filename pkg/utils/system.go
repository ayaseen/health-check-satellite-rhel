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
	// Use the executor to check remotely
	executor := GetExecutor()
	if executor != nil {
		// Check for /etc/redhat-release file
		output, err := executor.RunCommand("cat", "/etc/redhat-release")
		if err == nil && strings.Contains(strings.ToLower(output), "red hat") {
			return true
		}

		// Secondary check via rpm
		output, err = executor.RunCommand("rpm", "-q", "redhat-release")
		if err == nil && !strings.Contains(output, "not installed") {
			return true
		}
	}

	return false
}

// IsSatellite checks if the system is running Red Hat Satellite
func IsSatellite() bool {
	executor := GetExecutor()
	if executor != nil {
		// Check for satellite-installer
		output, err := executor.RunCommand("which", "satellite-installer")
		if err == nil && output != "" {
			return true
		}

		// Check for key Satellite packages
		satellitePackages := []string{"satellite", "katello", "foreman"}
		for _, pkg := range satellitePackages {
			output, err = executor.RunCommand("rpm", "-q", pkg)
			if err == nil && !strings.Contains(output, "not installed") {
				return true
			}
		}

		// Check for key Satellite services
		satelliteServices := []string{"foreman", "foreman-proxy"}
		for _, svc := range satelliteServices {
			output, err = executor.RunCommand("systemctl", "is-active", svc)
			if err == nil && strings.TrimSpace(output) == "active" {
				return true
			}
		}
	}

	return false
}

// RunningAsRoot checks if the tool is running with root/sudo privileges
func RunningAsRoot() bool {
	executor := GetExecutor()
	if executor != nil && !executor.IsLocal() {
		// For remote systems, check if we can run privileged commands
		output, err := executor.RunCommand("id", "-u")
		if err == nil {
			return strings.TrimSpace(output) == "0"
		}
	}

	// Local check
	return os.Geteuid() == 0
}

// RunCommand executes a command and returns its output
// This now uses the executor interface to support both local and remote execution
func RunCommand(name string, args ...string) (string, error) {
	executor := GetExecutor()
	if executor != nil {
		return executor.RunCommand(name, args...)
	}

	// Fallback to local execution if no executor
	cmd := exec.Command(name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), nil
}

// RunCommandWithTimeout executes a command with a timeout
func RunCommandWithTimeout(name string, timeout int, args ...string) (string, error) {
	executor := GetExecutor()
	if executor != nil {
		return executor.RunCommandWithTimeout(name, timeout, args...)
	}

	// Fallback to local execution
	cmd := exec.Command("timeout", fmt.Sprintf("%d", timeout), name)
	cmd.Args = append(cmd.Args, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return string(output), err
	}
	return string(output), nil
}

// CompressWithPassword compresses a file with password protection
func CompressWithPassword(sourcePath string, password string) (string, error) {
	// Generate output filename
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
	// Use the executor to get version remotely
	executor := GetExecutor()
	if executor != nil {
		output, err := executor.RunCommand("cat", "/etc/redhat-release")
		if err == nil {
			// Parse version from content
			// Example: "Red Hat Enterprise Linux release 8.9 (Ootpa)"
			contentStr := string(output)
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
		}

		// Try alternative method
		output, err = executor.RunCommand("rpm", "-E", "%{rhel}")
		if err == nil {
			version := strings.TrimSpace(output)
			if version != "" && version != "%{rhel}" {
				return version
			}
		}
	}

	return "8" // Default to RHEL 8
}
