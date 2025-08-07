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

	cmd.Flags().String("hosts-file", "hosts.ini", "Path to hosts configuration file")
	cmd.Flags().Int("max-parallel", 5, "Maximum number of parallel connections")
	cmd.Flags().Bool("summary-only", false, "Generate only summary reports (skip individual reports)")
	cmd.Flags().String("report-level", "standard", "Report verbosity level (summary|standard|detailed|full)")

	return cmd
}

func runMultiHostCommand(cmd *cobra.Command, args []string) error {
	multiHostMode = true
	defer func() { multiHostMode = false }()

	hostsFilePath, _ := cmd.Flags().GetString("hosts-file")
	maxParallel, _ := cmd.Flags().GetInt("max-parallel")
	summaryOnly, _ := cmd.Flags().GetBool("summary-only")
	reportLevel, _ := cmd.Flags().GetString("report-level")

	// Load hosts configuration
	hostsConfig := config.NewHostsConfig()
	if err := hostsConfig.LoadFromFile(hostsFilePath); err != nil {
		return fmt.Errorf("failed to load hosts file: %v", err)
	}

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
	fmt.Printf("\n")

	// Print hosts we're going to check
	fmt.Printf("Hosts:\n")
	for _, h := range allHosts {
		fmt.Printf("  - %s (user=%s, password=%v)\n", h.Hostname, h.User, h.Password != "")
	}
	fmt.Printf("\n")

	// Create output directory
	timestamp := time.Now().Format("20060102-150405")
	baseOutputDir := filepath.Join("reports", fmt.Sprintf("multi-host-%s", timestamp))
	hostsOutputDir := filepath.Join(baseOutputDir, "hosts")

	if err := os.MkdirAll(hostsOutputDir, 0755); err != nil {
		return fmt.Errorf("failed to create output directories: %v", err)
	}

	summaryReport := report.NewSummaryReport(baseOutputDir)

	// Simple progress bar
	bar := progressbar.NewOptions(len(allHosts),
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
	)

	type hostResult struct {
		hostname string
		hostType string
		report   *report.AsciiDocReport
		err      error
		duration time.Duration
	}

	results := make(chan hostResult, len(allHosts))
	var wg sync.WaitGroup
	sem := make(chan struct{}, hostsConfig.Defaults.ParallelConnections)

	startTime := time.Now()

	// Process each host
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

			// SHOW WHAT'S HAPPENING
			fmt.Printf("\n[%s] Starting connection...\n", hostEntry.Hostname)

			// Create SSH configuration
			sshConfig := &utils.SSHConfig{
				Host:         hostEntry.Hostname,
				Port:         hostEntry.Port,
				User:         hostEntry.User,
				Password:     hostEntry.Password,
				KeyFile:      hostEntry.SSHKeyFile,
				Timeout:      time.Duration(hostsConfig.Defaults.SSHTimeout) * time.Second,
				Become:       hostEntry.Become,
				BecomeMethod: hostEntry.BecomeMethod,
				BecomeUser:   hostEntry.BecomeUser,
				BecomePass:   hostEntry.BecomePass,
				BecomeFlags:  hostEntry.BecomeFlags,
			}

			// TRY TO CONNECT WITH TIMEOUT
			fmt.Printf("[%s] Creating SSH connection (timeout=%v)...\n",
				hostEntry.Hostname, sshConfig.Timeout)

			connectDone := make(chan struct {
				exec *utils.RemoteExecutor
				err  error
			}, 1)

			go func() {
				exec, err := utils.NewRemoteExecutor(sshConfig)
				connectDone <- struct {
					exec *utils.RemoteExecutor
					err  error
				}{exec, err}
			}()

			// Wait for connection with timeout
			select {
			case res := <-connectDone:
				if res.err != nil {
					fmt.Printf("[%s] ✗ CONNECTION FAILED: %v\n", hostEntry.Hostname, res.err)
					result.err = res.err
					result.duration = time.Since(hostStart)
					bar.Add(1)
					results <- result
					return
				}

				fmt.Printf("[%s] ✓ Connected successfully\n", hostEntry.Hostname)

				// Test command execution
				fmt.Printf("[%s] Testing command execution...\n", hostEntry.Hostname)
				output, err := res.exec.RunCommandWithTimeout("echo", 5, "test")
				if err != nil {
					fmt.Printf("[%s] ✗ Command test failed: %v\n", hostEntry.Hostname, err)
					res.exec.Close()
					result.err = fmt.Errorf("command execution failed: %v", err)
				} else {
					fmt.Printf("[%s] ✓ Command test passed: %s\n",
						hostEntry.Hostname, strings.TrimSpace(output))

					// Run actual health checks
					if !summaryOnly {
						fmt.Printf("[%s] Running health checks...\n", hostEntry.Hostname)

						utils.SetExecutor(res.exec)
						defer func() {
							localExec, _ := utils.NewLocalExecutor()
							utils.SetExecutor(localExec)
						}()

						outputFile := filepath.Join(hostsOutputDir,
							fmt.Sprintf("%s-health-check.adoc", sanitizeFilename(hostEntry.Hostname)))

						reportGenerator := report.NewAsciiDocReport(outputFile)

						if hostEntry.Type == "satellite" {
							reportGenerator.Initialize(hostEntry.Hostname, "Satellite Health Check Report")
							// Skip cluster checks
							originalSkip := skipCategories
							skipCategories = append(skipCategories, "cluster")
							err = executeSatelliteChecks(reportGenerator, reportLevel)
							skipCategories = originalSkip
						} else {
							reportGenerator.Initialize(hostEntry.Hostname, "RHEL Health Check Report")
							err = executeRHELChecks(reportGenerator, reportLevel)
						}

						if err != nil {
							fmt.Printf("[%s] ✗ Health checks failed: %v\n", hostEntry.Hostname, err)
							result.err = err
						} else {
							fmt.Printf("[%s] ✓ Health checks completed\n", hostEntry.Hostname)
							reportGenerator.Generate()
							result.report = reportGenerator
						}
					}

					res.exec.Close()
				}

			case <-time.After(30 * time.Second):
				fmt.Printf("[%s] ✗ CONNECTION TIMEOUT after 30 seconds!\n", hostEntry.Hostname)
				result.err = fmt.Errorf("connection timeout")
			}

			result.duration = time.Since(hostStart)
			bar.Add(1)
			results <- result
		}(host)
	}

	// Wait for completion
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	var successHosts []hostResult
	var failedHosts []hostResult

	for result := range results {
		if result.err != nil {
			failedHosts = append(failedHosts, result)
		} else {
			successHosts = append(successHosts, result)
			if result.report != nil {
				summaryReport.AddHostReport(result.hostname, result.report)
			}
		}
	}

	bar.Finish()
	fmt.Printf("\n\n")

	// Show results
	fmt.Printf("╔══════════════════════════════════════════════════╗\n")
	fmt.Printf("║                  Results Summary                 ║\n")
	fmt.Printf("╚══════════════════════════════════════════════════╝\n")
	fmt.Printf("\n")

	if len(successHosts) > 0 {
		fmt.Printf("✓ Successful (%d):\n", len(successHosts))
		for _, h := range successHosts {
			fmt.Printf("  • %s (%v)\n", h.hostname, h.duration)
		}
		fmt.Printf("\n")
	}

	if len(failedHosts) > 0 {
		fmt.Printf("✗ Failed (%d):\n", len(failedHosts))
		for _, h := range failedHosts {
			fmt.Printf("  • %s: %v\n", h.hostname, h.err)
		}
		fmt.Printf("\n")
	}

	// Generate summary reports
	if len(successHosts) > 0 && !summaryOnly {
		fmt.Printf("Generating summary reports...\n")
		summaryReport.GenerateAllReports()
	}

	totalDuration := time.Since(startTime).Round(time.Second)
	fmt.Printf("\nTotal execution time: %s\n", totalDuration)
	fmt.Printf("Reports location: %s\n", baseOutputDir)

	return nil
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
