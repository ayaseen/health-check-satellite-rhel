// cmd/root.go

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

var (
	outputFile        string
	verboseOutput     bool
	parallelExecution bool
	skipCategories    []string
	includeCategories []string
	timeout           int
	hostsFile         string // New flag for hosts file
	multiHostMode     bool   // Flag to indicate multi-host mode
	rootCmd           = &cobra.Command{
		Use:   "health-check",
		Short: "Red Hat Enterprise Linux and Satellite Health Check Tool",
		Long: `A comprehensive health check tool for Red Hat Enterprise Linux systems
and Red Hat Satellite servers. This tool performs various checks to evaluate
the health and configuration of your systems and generates detailed reports.`,
		RunE: autoDetectAndRun,
	}
)

// Execute executes the root command
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&outputFile, "output", "o", "", "Output file path (default is automatically generated)")
	rootCmd.PersistentFlags().BoolVarP(&verboseOutput, "verbose", "v", false, "Enable verbose output")
	rootCmd.PersistentFlags().BoolVarP(&parallelExecution, "parallel", "p", true, "Run checks in parallel")
	rootCmd.PersistentFlags().StringSliceVarP(&skipCategories, "skip", "s", nil, "Categories to skip")
	rootCmd.PersistentFlags().StringSliceVarP(&includeCategories, "include", "i", nil, "Only include specified categories")
	rootCmd.PersistentFlags().IntVarP(&timeout, "timeout", "t", 30, "Timeout in seconds for individual checks")
	rootCmd.PersistentFlags().StringVarP(&hostsFile, "hosts", "H", "", "Hosts configuration file for multi-host checks")

	// Add subcommands
	rootCmd.AddCommand(newRhelCmd())
	rootCmd.AddCommand(newSatelliteCmd())
	rootCmd.AddCommand(newMultiCmd()) // New command for multi-host checks
}

// autoDetectAndRun automatically detects if running on RHEL or Satellite and runs appropriate checks
func autoDetectAndRun(cmd *cobra.Command, args []string) error {
	// Check if hosts file is provided
	if hostsFile != "" {
		fmt.Println("Hosts file provided, running multi-host checks...")
		return runMultiHostChecks(cmd, args)
	}

	// Original single-host behavior
	fmt.Println("Auto-detecting system type...")

	// Set up local executor
	localExec, err := utils.NewLocalExecutor()
	if err != nil {
		return fmt.Errorf("failed to create local executor: %v", err)
	}
	utils.SetExecutor(localExec)

	if utils.IsSatellite() {
		fmt.Println("Detected Red Hat Satellite server!")

		// If running on Satellite, add cluster to skipCategories if not already there
		// This ensures we skip only cluster.go checks but include all other RHEL checks
		if skipCategories == nil {
			skipCategories = []string{"cluster"}
		} else if !contains(skipCategories, "cluster") {
			skipCategories = append(skipCategories, "cluster")
		}

		// Create a new Satellite command, but don't override args
		satCmd := newSatelliteCmd()

		// Don't pass the args here, just run directly
		return runSatelliteChecks(satCmd, []string{})
	} else if utils.IsRHEL() {
		fmt.Println("Detected Red Hat Enterprise Linux system!")

		// Create a new RHEL command, but don't override args
		rhelCmd := newRhelCmd()

		// Don't pass the args here, just run directly
		return runRhelChecks(rhelCmd, []string{})
	} else {
		return fmt.Errorf("this does not appear to be a Red Hat Enterprise Linux or Satellite system")
	}
}

// contains checks if a string is present in a slice of strings
func contains(slice []string, item string) bool {
	for _, s := range slice {
		if strings.ToLower(s) == strings.ToLower(item) {
			return true
		}
	}
	return false
}

// generateDefaultOutputFilename generates a default output filename based on hostname and check type
func generateDefaultOutputFilename(checkType string) string {
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown-host"
	}

	// Sanitize hostname for use in filename
	timestamp := time.Now().Format("20060102-150405")

	// Create output directory if it doesn't exist
	outputDir := "reports"
	if err := os.MkdirAll(outputDir, 0755); err != nil {
		outputDir = "."
	}

	return filepath.Join(outputDir, fmt.Sprintf("%s-%s-health-check-%s.adoc",
		sanitizeFilename(hostname), checkType, timestamp))
}

// sanitizeFilename removes or replaces characters that are problematic in filenames
func sanitizeFilename(filename string) string {
	replacer := strings.NewReplacer(
		"/", "-",
		"\\", "-",
		":", "-",
		"*", "",
		"?", "",
		"\"", "",
		"<", "",
		">", "",
		"|", "-",
		" ", "_",
	)
	return replacer.Replace(filename)
}

// runChecks is a helper function to run checks with progress reporting
func runChecks(checkName string, totalChecks int, runCheckFunc func(int, *progressbar.ProgressBar)) {
	// In multi-host mode, suppress individual check progress
	if multiHostMode {
		// Create a dummy progress bar that doesn't display
		bar := &progressbar.ProgressBar{}
		runCheckFunc(totalChecks, bar)
		return
	}

	// Original behavior for single host mode
	startTime := time.Now()
	fmt.Printf("Starting %s Health Check...\n", checkName)

	// Initialize progress bar
	bar := progressbar.NewOptions(totalChecks,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription(fmt.Sprintf("[cyan]Running %s health checks[reset]", checkName)),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
	)

	// Run checks
	runCheckFunc(totalChecks, bar)

	elapsedTime := time.Since(startTime)
	bar.Clear()
	fmt.Printf("Health check completed in %s!\n", elapsedTime)
}

// isCategoryEnabled checks if a category should be executed based on skip/include filters
func isCategoryEnabled(category string, skipCategories, includeCategories []string) bool {
	// If include list is specified, only run categories in that list
	if len(includeCategories) > 0 {
		return contains(includeCategories, category)
	}

	// Otherwise, run all categories except those in skip list
	return !contains(skipCategories, category)
}

// runSequentialChecks runs checks sequentially
func runSequentialChecks(checks []func(*report.AsciiDocReport), reportGenerator *report.AsciiDocReport, bar *progressbar.ProgressBar) {
	for _, checkFunc := range checks {
		checkFunc(reportGenerator)
		bar.Add(1)
	}
}

// runParallelChecks runs checks in parallel
func runParallelChecks(checks []func(*report.AsciiDocReport), reportGenerator *report.AsciiDocReport, bar *progressbar.ProgressBar) {
	var wg sync.WaitGroup
	// Use a semaphore to limit concurrent checks
	sem := make(chan struct{}, 5) // Limit to 5 concurrent checks

	for _, checkFunc := range checks {
		wg.Add(1)
		go func(fn func(*report.AsciiDocReport)) {
			defer wg.Done()
			sem <- struct{}{}        // Acquire semaphore
			defer func() { <-sem }() // Release semaphore

			fn(reportGenerator)
			bar.Add(1)
		}(checkFunc)
	}

	wg.Wait()
}

// compressReportIfNeeded compresses the report based on environment variables
func compressReportIfNeeded(reportPath string) (string, error) {
	// Check if compression is requested via environment variable
	compress := os.Getenv("COMPRESS_REPORT")
	password := os.Getenv("REPORT_PASSWORD")

	if compress != "true" && compress != "1" {
		return reportPath, nil
	}

	// If no password is set, generate a default one
	if password == "" {
		password = "redhat123" // Default password
	}

	compressedPath, err := utils.CompressWithPassword(reportPath, password)
	if err != nil {
		return reportPath, fmt.Errorf("failed to compress report: %v", err)
	}

	// Optionally remove the original file
	if os.Getenv("REMOVE_UNCOMPRESSED") == "true" {
		os.Remove(reportPath)
	}

	fmt.Printf("Report compressed with password: %s\n", password)
	return compressedPath, nil
}

// runMultiHostChecks runs health checks on multiple hosts
func runMultiHostChecks(cmd *cobra.Command, args []string) error {
	// Set multi-host mode flag
	multiHostMode = true
	defer func() { multiHostMode = false }()

	// Load hosts configuration
	hostsConfig := config.NewHostsConfig()
	if err := hostsConfig.LoadFromFile(hostsFile); err != nil {
		return fmt.Errorf("failed to load hosts file: %v", err)
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

	// Create a single progress bar for all hosts
	totalTasks := len(allHosts)
	bar := progressbar.NewOptions(totalTasks,
		progressbar.OptionEnableColorCodes(true),
		progressbar.OptionShowCount(),
		progressbar.OptionSetWidth(50),
		progressbar.OptionSetDescription("[cyan]Checking hosts[reset]"),
		progressbar.OptionSetTheme(progressbar.Theme{
			Saucer:        "[green]=[reset]",
			SaucerHead:    "[green]>[reset]",
			SaucerPadding: " ",
			BarStart:      "[",
			BarEnd:        "]",
		}),
		progressbar.OptionOnCompletion(func() {
			fmt.Printf("\n")
		}),
	)

	// Track execution status
	type hostResult struct {
		hostname string
		hostType string
		report   *report.AsciiDocReport
		err      error
		duration time.Duration
		filepath string
	}

	results := make(chan hostResult, len(allHosts))
	statusUpdates := make(chan string, len(allHosts))

	// Start a goroutine to update the progress bar description
	go func() {
		for status := range statusUpdates {
			bar.Describe(status)
		}
	}()

	// Process hosts
	var wg sync.WaitGroup
	sem := make(chan struct{}, hostsConfig.Defaults.ParallelConnections)

	startTime := time.Now()

	for _, host := range allHosts {
		wg.Add(1)
		go func(hostEntry config.HostEntry) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			hostStart := time.Now()
			result := hostResult{
				hostname: hostEntry.Hostname,
				hostType: hostEntry.Type,
			}

			// Update status
			statusUpdates <- fmt.Sprintf("[cyan]Checking[reset] %s", hostEntry.Hostname)

			// Run health check on this host
			hostReport, reportPath, err := runRemoteHostCheckWithPath(hostEntry, hostsOutputDir, hostsConfig.Defaults)
			if err != nil {
				result.err = err
			} else {
				result.report = hostReport
				result.filepath = reportPath
			}

			result.duration = time.Since(hostStart)
			results <- result

			// Update progress
			bar.Add(1)
		}(host)
	}

	// Close channels when done
	go func() {
		wg.Wait()
		close(results)
		close(statusUpdates)
	}()

	// Collect results
	var successHosts []hostResult
	var failedHosts []hostResult

	for result := range results {
		if result.err != nil {
			failedHosts = append(failedHosts, result)
		} else if result.report != nil {
			successHosts = append(successHosts, result)

			// Load the actual report data from the generated file
			if result.filepath != "" {
				loadedReport := report.NewAsciiDocReport(result.filepath)
				if err := loadedReport.LoadFromFile(result.filepath); err == nil {
					summaryReport.AddHostReport(result.hostname, loadedReport)
				} else {
					// If loading fails, use the original report
					summaryReport.AddHostReport(result.hostname, result.report)
				}
			} else {
				summaryReport.AddHostReport(result.hostname, result.report)
			}
		}
	}

	// Clear the progress bar line
	fmt.Printf("\r\033[K")

	totalDuration := time.Since(startTime)

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
			fmt.Printf("  • %-30s [%s] (%s)\n", host.hostname, host.hostType, host.duration)
		}
		fmt.Printf("\n")
	}

	// Show failed hosts
	if len(failedHosts) > 0 {
		fmt.Printf("✗ Failed (%d):\n", len(failedHosts))
		for _, host := range failedHosts {
			fmt.Printf("  • %-30s %v\n", host.hostname, host.err)
		}
		fmt.Printf("\n")
	}

	// Generate summary reports
	fmt.Printf("Generating summary reports...\n")
	if err := summaryReport.GenerateAllReports(); err != nil {
		return fmt.Errorf("failed to generate summary reports: %v", err)
	}

	// Final summary
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
	fmt.Printf("  • Summary:      ...-infrastructure-summary.adoc\n")
	fmt.Printf("  • Critical:     ...-critical-issues.adoc\n")
	fmt.Printf("  • Individual:   hosts/\n")
	fmt.Printf("\n")

	return nil
}

// runRemoteHostCheckWithPath runs health check and returns both report and filepath
func runRemoteHostCheckWithPath(host config.HostEntry, outputDir string, defaults config.DefaultConfig) (*report.AsciiDocReport, string, error) {
	// Create SSH configuration
	sshConfig := &utils.SSHConfig{
		Host:     host.Hostname,
		Port:     host.Port,
		User:     host.User,
		Password: host.Password,
		KeyFile:  host.SSHKeyFile,
		Timeout:  time.Duration(defaults.SSHTimeout) * time.Second,
	}

	// Create remote executor
	remoteExec, err := utils.NewRemoteExecutor(sshConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create remote executor: %v", err)
	}
	defer remoteExec.Close()

	// Set the executor for this host
	utils.SetExecutor(remoteExec)

	// Generate the output file path
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-health-check.adoc", sanitizeFilename(host.Hostname)))

	// Determine host type and run checks
	var report *report.AsciiDocReport
	if host.Type == "satellite" {
		report, err = runRemoteSatelliteCheckWithPath(host.Hostname, outputPath)
	} else {
		report, err = runRemoteRHELCheckWithPath(host.Hostname, outputPath)
	}

	if err != nil {
		return nil, "", err
	}

	return report, outputPath, nil
}

// runRemoteHostCheck is the original function for backward compatibility
func runRemoteHostCheck(host config.HostEntry, outputDir string, defaults config.DefaultConfig) (*report.AsciiDocReport, error) {
	report, _, err := runRemoteHostCheckWithPath(host, outputDir, defaults)
	return report, err
}

// runRemoteRHELCheckWithPath runs RHEL checks and returns the report with path
func runRemoteRHELCheckWithPath(hostname string, outputPath string) (*report.AsciiDocReport, error) {
	// Save current outputFile
	originalOutputFile := outputFile

	// Set output file for this host
	outputFile = outputPath

	// Store the current report to capture it after runRhelChecks
	var capturedReport *report.AsciiDocReport

	// Hook to capture the report - we'll modify runRhelChecks to set this
	rhelReportHook = func(r *report.AsciiDocReport) {
		capturedReport = r
	}

	// Create a mock command for runRhelChecks
	cmd := newRhelCmd()

	// Run the checks - this will populate the report
	if err := runRhelChecks(cmd, []string{}); err != nil {
		outputFile = originalOutputFile
		rhelReportHook = nil
		return nil, err
	}

	// Clear the hook
	rhelReportHook = nil

	// Restore original outputFile
	outputFile = originalOutputFile

	// If we captured a report, return it
	if capturedReport != nil {
		return capturedReport, nil
	}

	// Otherwise create a new report and load from file
	report := report.NewAsciiDocReport(outputPath)
	report.Initialize(hostname, "RHEL Health Check Report")

	return report, nil
}

// runRemoteRHELCheck for backward compatibility
func runRemoteRHELCheck(hostname string, outputDir string) (*report.AsciiDocReport, error) {
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-health-check.adoc", sanitizeFilename(hostname)))
	return runRemoteRHELCheckWithPath(hostname, outputPath)
}

// runRemoteSatelliteCheckWithPath runs Satellite checks and returns the report with path
func runRemoteSatelliteCheckWithPath(hostname string, outputPath string) (*report.AsciiDocReport, error) {
	// Save current outputFile
	originalOutputFile := outputFile

	// Set output file for this host
	outputFile = outputPath

	// Store the current report to capture it after runSatelliteChecks
	var capturedReport *report.AsciiDocReport

	// Hook to capture the report - we'll modify runSatelliteChecks to set this
	satelliteReportHook = func(r *report.AsciiDocReport) {
		capturedReport = r
	}

	// Create a mock command for runSatelliteChecks
	cmd := newSatelliteCmd()

	// Add cluster to skip categories for Satellite
	originalSkipCategories := skipCategories
	if skipCategories == nil {
		skipCategories = []string{"cluster"}
	} else if !contains(skipCategories, "cluster") {
		skipCategories = append(skipCategories, "cluster")
	}

	// Run the checks - this will populate the report
	if err := runSatelliteChecks(cmd, []string{}); err != nil {
		skipCategories = originalSkipCategories
		outputFile = originalOutputFile
		satelliteReportHook = nil
		return nil, err
	}

	// Clear the hook
	satelliteReportHook = nil

	// Restore original values
	skipCategories = originalSkipCategories
	outputFile = originalOutputFile

	// If we captured a report, return it
	if capturedReport != nil {
		return capturedReport, nil
	}

	// Otherwise create a new report and load from file
	report := report.NewAsciiDocReport(outputPath)
	report.Initialize(hostname, "Satellite Health Check Report")

	return report, nil
}

// runRemoteSatelliteCheck for backward compatibility
func runRemoteSatelliteCheck(hostname string, outputDir string) (*report.AsciiDocReport, error) {
	outputPath := filepath.Join(outputDir, fmt.Sprintf("%s-health-check.adoc", sanitizeFilename(hostname)))
	return runRemoteSatelliteCheckWithPath(hostname, outputPath)
}

// Report hooks - these are set by runRemoteRHELCheck and runRemoteSatelliteCheck
var (
	rhelReportHook      func(*report.AsciiDocReport)
	satelliteReportHook func(*report.AsciiDocReport)
)
