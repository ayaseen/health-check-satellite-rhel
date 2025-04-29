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

	// Add subcommands
	rootCmd.AddCommand(newRhelCmd())
	rootCmd.AddCommand(newSatelliteCmd())
}

// autoDetectAndRun automatically detects if running on RHEL or Satellite and runs appropriate checks
func autoDetectAndRun(cmd *cobra.Command, args []string) error {
	fmt.Println("Auto-detecting system type...")

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
	// Convert to lowercase for case-insensitive comparison
	categoryLower := strings.ToLower(category)

	// If includeCategories is specified, only run those categories
	if len(includeCategories) > 0 {
		for _, includeCat := range includeCategories {
			if strings.ToLower(includeCat) == categoryLower {
				return true
			}
		}
		return false
	}

	// Otherwise, run all categories except those in skipCategories
	for _, skipCat := range skipCategories {
		if strings.ToLower(skipCat) == categoryLower {
			return false
		}
	}

	return true
}

// compressReportIfNeeded compresses the report file with a password
func compressReportIfNeeded(outputPath string) (string, error) {
	// Use fixed password for all reports - no need to specify on command line
	password := "7e5eed48001f9a407bbb87b29c32871b"

	// Only compress if there's a password set
	if password == "" {
		return outputPath, nil
	}

	zipPath, err := utils.CompressWithPassword(outputPath, password)
	if err != nil {
		return "", fmt.Errorf("failed to compress report: %v", err)
	}

	fmt.Printf("Report compressed with password protection: %s\n", zipPath)

	// Delete the original file after successful compression
	if err := os.Remove(outputPath); err != nil {
		fmt.Printf("Warning: Could not remove original file %s: %v\n", outputPath, err)
	}

	return zipPath, nil
}

// runParallelChecks runs checks in parallel with progress tracking
func runParallelChecks(checks []func(*report.AsciiDocReport), reportGenerator *report.AsciiDocReport, progressBar *progressbar.ProgressBar) {
	var wg sync.WaitGroup
	var mutex sync.Mutex

	// Function to update progress safely
	updateProgress := func() {
		mutex.Lock()
		progressBar.Add(1)
		mutex.Unlock()
	}

	// Run each check in a goroutine
	for _, check := range checks {
		wg.Add(1)
		go func(checkFunc func(*report.AsciiDocReport)) {
			defer wg.Done()
			checkFunc(reportGenerator)
			updateProgress()
		}(check)
	}

	// Wait for all checks to complete
	wg.Wait()
}

// runSequentialChecks runs checks sequentially with progress tracking
func runSequentialChecks(checks []func(*report.AsciiDocReport), reportGenerator *report.AsciiDocReport, progressBar *progressbar.ProgressBar) {
	for _, check := range checks {
		check(reportGenerator)
		progressBar.Add(1)
	}
}
