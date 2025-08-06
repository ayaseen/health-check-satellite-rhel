// cmd/multi.go

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/config"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// newMultiCmd creates the multi-host subcommand
func newMultiCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "multi",
		Short: "Run health checks on multiple hosts",
		Long: `Performs health checks on multiple Red Hat Enterprise Linux systems
and Red Hat Satellite servers based on a hosts configuration file.
Generates individual reports for each host and a consolidated summary report.`,
		RunE: runMultiHostCommand,
	}

	// Add multi-host specific flags
	cmd.Flags().String("hosts-file", "hosts.ini", "Path to hosts configuration file")
	cmd.Flags().Int("max-parallel", 5, "Maximum number of parallel connections")
	cmd.Flags().Bool("summary-only", false, "Generate only summary reports (skip individual reports)")
	cmd.Flags().String("report-level", "standard", "Report verbosity level (summary|standard|detailed|full)")

	return cmd
}

// runMultiHostCommand is the main entry point for multi-host checks
func runMultiHostCommand(cmd *cobra.Command, args []string) error {
	// Set multi-host mode
	multiHostMode = true
	defer func() { multiHostMode = false }()

	// Get flags
	hostsFilePath, _ := cmd.Flags().GetString("hosts-file")
	maxParallel, _ := cmd.Flags().GetInt("max-parallel")
	summaryOnly, _ := cmd.Flags().GetBool("summary-only")
	reportLevel, _ := cmd.Flags().GetString("report-level")

	// Load hosts configuration
	hostsConfig := config.NewHostsConfig()
	if err := hostsConfig.LoadFromFile(hostsFilePath); err != nil {
		return fmt.Errorf("failed to load hosts file: %v", err)
	}

	// Override parallel connections if specified
	if maxParallel > 0 {
		hostsConfig.Defaults.ParallelConnections = maxParallel
	}

	allHosts := hostsConfig.GetAllHosts()
	if len(allHosts) == 0 {
		return fmt.Errorf("no hosts found in configuration file")
	}

	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║        Multi-Host Health Check Execution         ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
	fmt.Printf("Hosts to check:       %d\n", len(allHosts))
	fmt.Printf("Parallel connections: %d\n", hostsConfig.Defaults.ParallelConnections)
	fmt.Printf("Report level:         %s\n", reportLevel)
	fmt.Printf("\n")

	// Create output directory structure
	timestamp := time.Now().Format("20060102-150405")
	baseOutputDir := filepath.Join("reports", fmt.Sprintf("multi-host-%s", timestamp))
	hostsOutputDir := filepath.Join(baseOutputDir, "hosts")

	if err := os.MkdirAll(hostsOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directories: %v", err)
	}

	// Initialize summary report
	summaryReport := report.NewSummaryReport(baseOutputDir)

	// Create a SINGLE progress bar with cleaner settings
	bar := progressbar.NewOptions(len(allHosts),
		progressbar.OptionSetWriter(os.Stderr),
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(40),
		progressbar.OptionSetDescription("[cyan]Processing[reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]█[reset]",
			SaucerHead:    "[green]█[reset]",
			SaucerPadding: "░",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionShowIts(),
		progressbar.OptionSetItsString("hosts"),
		progressbar.OptionThrottle(100*time.Millisecond),
		progressbar.OptionClearOnFinish(),
	)

	// Track execution status
	type hostResult struct {
		hostname string
		hostType string
		report   *report.AsciiDocReport
		err      error
		duration time.Duration
	}

	results := make(chan hostResult, len(allHosts))
	statusUpdates := make(chan string, 100)

	// Goroutine to update progress bar description
	go func() {
		for status := range statusUpdates {
			bar.Describe(status)
		}
	}()

	// Process hosts
	var wg sync.WaitGroup
	sem := make(chan struct{}, hostsConfig.Defaults.ParallelConnections)

	startTime := time.Now()

	// Track currently processing hosts
	processingHosts := make(map[string]bool)
	var processingMutex sync.Mutex

	for _, host := range allHosts {
		wg.Add(1)
		go func(hostEntry config.HostEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			// Update status
			processingMutex.Lock()
			processingHosts[hostEntry.Hostname] = true
			currentHosts := []string{}
			for h := range processingHosts {
				currentHosts = append(currentHosts, h)
			}
			if len(currentHosts) > 0 {
				statusUpdates <- fmt.Sprintf("[cyan]%s[reset]", strings.Join(currentHosts, ", "))
			}
			processingMutex.Unlock()

			hostStart := time.Now()
			result := hostResult{
				hostname: hostEntry.Hostname,
				hostType: hostEntry.Type,
			}

			if !summaryOnly {
				// Run health check on this host
				hostReport, err := executeHostCheck(hostEntry, hostsOutputDir, hostsConfig.Defaults, reportLevel)
				if err != nil {
					result.err = err
				} else {
					result.report = hostReport
				}
			} else {
				// Summary-only mode - just test connectivity
				err := testHostConnectivity(hostEntry, hostsConfig.Defaults)
				if err != nil {
					result.err = err
				}
			}

			result.duration = time.Since(hostStart)

			// Remove from processing
			processingMutex.Lock()
			delete(processingHosts, hostEntry.Hostname)
			processingMutex.Unlock()

			// Update progress
			bar.Add(1)

			// Send result
			results <- result
		}(host)
	}

	// Wait for all goroutines to complete
	go func() {
		wg.Wait()
		close(results)
		close(statusUpdates)
	}()

	// Collect results
	var successHosts []config.HostEntry
	var failedHosts []config.HostEntry

	for result := range results {
		if result.err != nil {
			failedHosts = append(failedHosts, config.HostEntry{Hostname: result.hostname, Type: result.hostType})
		} else {
			successHosts = append(successHosts, config.HostEntry{Hostname: result.hostname, Type: result.hostType})
			if result.report != nil {
				summaryReport.AddHostReport(result.hostname, result.report)
			}
		}
	}

	// Clear the progress bar
	bar.Finish()
	fmt.Printf("\n")

	// Print results summary
	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║                  Results Summary                 ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")

	// Show successful hosts
	if len(successHosts) > 0 {
		fmt.Printf("✓ Successful (%d):\n", len(successHosts))
		for _, host := range successHosts {
			fmt.Printf("  • %s\n", host.Hostname)
		}
		fmt.Printf("\n")
	}

	// Show failed hosts
	if len(failedHosts) > 0 {
		fmt.Printf("✗ Failed (%d):\n", len(failedHosts))
		for _, host := range failedHosts {
			fmt.Printf("  • %s\n", host.Hostname)
		}
		fmt.Printf("\n")
	}

	// Generate summary reports
	if len(successHosts) > 0 {
		fmt.Printf("Generating summary reports...\n")
		if err := summaryReport.GenerateAllReports(); err != nil {
			fmt.Printf("Warning: Failed to generate summary reports: %v\n", err)
		}
	}

	// Display final summary
	totalDuration := time.Since(startTime).Round(time.Second)

	fmt.Printf("\n")
	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║              Execution Complete                  ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")
	fmt.Printf("Total hosts:     %d\n", len(allHosts))
	fmt.Printf("Successful:      %d\n", len(successHosts))
	fmt.Printf("Failed:          %d\n", len(failedHosts))
	fmt.Printf("Total duration:  %s\n", totalDuration)
	fmt.Printf("\n")
	fmt.Printf("Reports location: %s\n", baseOutputDir)
	fmt.Printf("  • Summary:      %s-infrastructure-summary.adoc\n", timestamp)
	fmt.Printf("  • Critical:     %s-critical-issues.adoc\n", timestamp)
	if !summaryOnly {
		fmt.Printf("  • Individual:   %s/\n", hostsOutputDir)
	}
	fmt.Printf("\n")

	return nil
}

// executeHostCheck executes health check on a single host
func executeHostCheck(host config.HostEntry, outputDir string, defaults config.DefaultConfig, reportLevel string) (*report.AsciiDocReport, error) {
	// Create SSH configuration
	sshConfig := &utils.SSHConfig{
		Host:     host.Hostname,
		Port:     host.Port,
		User:     host.User,
		Password: host.Password,
		KeyFile:  host.SSHKeyFile,
		Timeout:  time.Duration(defaults.SSHTimeout) * time.Second,
		// Add privilege escalation settings
		Become:       host.Become,
		BecomeMethod: host.BecomeMethod,
		BecomeUser:   host.BecomeUser,
		BecomePass:   host.BecomePass,
		BecomeFlags:  host.BecomeFlags,
	}

	// Create remote executor
	remoteExec, err := utils.NewRemoteExecutor(sshConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to connect: %v", err)
	}
	defer remoteExec.Close()

	// Set the executor for this host - this is critical!
	utils.SetExecutor(remoteExec)

	// Ensure we reset to local executor when done
	defer func() {
		localExec, _ := utils.NewLocalExecutor()
		utils.SetExecutor(localExec)
	}()

	// Create output file path
	outputFile := filepath.Join(outputDir, fmt.Sprintf("%s-health-check.adoc",
		sanitizeFilename(host.Hostname)))

	// Create report generator
	reportGenerator := report.NewAsciiDocReport(outputFile)

	// Determine system type and run appropriate checks
	if host.Type == "satellite" {
		reportGenerator.Initialize(host.Hostname, "Satellite Health Check Report")

		// Skip cluster checks for Satellite
		originalSkipCategories := skipCategories
		if skipCategories == nil {
			skipCategories = []string{"cluster"}
		} else if !contains(skipCategories, "cluster") {
			skipCategories = append(skipCategories, "cluster")
		}

		// Run satellite checks (this will include RHEL checks)
		if err := executeSatelliteChecks(reportGenerator, reportLevel); err != nil {
			skipCategories = originalSkipCategories
			return nil, err
		}

		skipCategories = originalSkipCategories
	} else {
		reportGenerator.Initialize(host.Hostname, "RHEL Health Check Report")

		// Run RHEL checks
		if err := executeRHELChecks(reportGenerator, reportLevel); err != nil {
			return nil, err
		}
	}

	// Generate the report
	if _, err := reportGenerator.Generate(); err != nil {
		return nil, fmt.Errorf("failed to generate report: %v", err)
	}

	// Cache the report
	report.CacheHostReport(host.Hostname, reportGenerator)

	// Save check results to JSON
	if err := report.SaveCheckResults(outputFile, reportGenerator); err != nil {
		// Log warning but don't fail - suppress in multi-host mode
		if !multiHostMode {
			fmt.Printf("Warning: failed to save check results for %s: %v\n", host.Hostname, err)
		}
	}

	return reportGenerator, nil
}

// testHostConnectivity tests basic connectivity to a host
func testHostConnectivity(host config.HostEntry, defaults config.DefaultConfig) error {
	// Create SSH configuration
	sshConfig := &utils.SSHConfig{
		Host:         host.Hostname,
		Port:         host.Port,
		User:         host.User,
		Password:     host.Password,
		KeyFile:      host.SSHKeyFile,
		Timeout:      time.Duration(defaults.SSHTimeout) * time.Second,
		Become:       host.Become,
		BecomeMethod: host.BecomeMethod,
		BecomeUser:   host.BecomeUser,
		BecomePass:   host.BecomePass,
		BecomeFlags:  host.BecomeFlags,
	}

	// Create remote executor
	remoteExec, err := utils.NewRemoteExecutor(sshConfig)
	if err != nil {
		return fmt.Errorf("failed to connect: %v", err)
	}
	defer remoteExec.Close()

	// Test connection
	output, err := remoteExec.RunCommandWithTimeout("echo", 5, "connection_test")
	if err != nil {
		return fmt.Errorf("connection test failed: %v", err)
	}

	if !strings.Contains(output, "connection_test") {
		return fmt.Errorf("unexpected response from connection test")
	}

	return nil
}

// Helper function to mask password for display
func maskPassword(password string) string {
	if password == "" {
		return "[NOT SET]"
	}
	if len(password) <= 4 {
		return "****"
	}
	return password[:2] + strings.Repeat("*", len(password)-4) + password[len(password)-2:]
}

// executeRHELChecks runs RHEL checks for multi-host mode
func executeRHELChecks(reportGenerator *report.AsciiDocReport, reportLevel string) error {
	// Create a mock command
	cmd := newRhelCmd()

	// The existing runRhelChecks function will use the global executor
	// which we've already set to the remote executor
	return runRhelChecks(cmd, []string{})
}

// executeSatelliteChecks runs Satellite checks for multi-host mode
func executeSatelliteChecks(reportGenerator *report.AsciiDocReport, reportLevel string) error {
	// Create a mock command
	cmd := newSatelliteCmd()

	// The existing runSatelliteChecks function will use the global executor
	// which we've already set to the remote executor
	return runSatelliteChecks(cmd, []string{})
}
