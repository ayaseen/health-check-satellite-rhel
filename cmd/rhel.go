// cmd/rhel.go

package cmd

import (
	"fmt"
	"os"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/checks/rhel"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// newRhelCmd creates the RHEL subcommand
func newRhelCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rhel",
		Short: "Run RHEL health checks",
		Long: `Performs comprehensive health checks on a Red Hat Enterprise Linux system.
This includes system information, memory, disk, security, and other checks.`,
		RunE: runRhelChecks,
	}

	// Add RHEL-specific flags
	cmd.Flags().Bool("skip-network", false, "Skip network-related checks")
	cmd.Flags().Bool("skip-performance", false, "Skip performance-related checks")

	return cmd
}

// runRhelChecks performs all RHEL health checks
func runRhelChecks(cmd *cobra.Command, args []string) error {
	// Check if running as root
	if !utils.RunningAsRoot() {
		fmt.Println("WARNING: This tool should be run with root/sudo privileges for complete results.")
		fmt.Println("Some checks may fail or provide incomplete information.")
	}

	// Parse command flags
	skipNetwork, _ := cmd.Flags().GetBool("skip-network")
	skipPerformance, _ := cmd.Flags().GetBool("skip-performance")

	// Convert these to categories to skip
	if skipNetwork {
		skipCategories = append(skipCategories, "network")
	}
	if skipPerformance {
		skipCategories = append(skipCategories, "performance")
	}

	// Create a new report
	hostname, _ := os.Hostname()

	// If outputFile is not set, generate a default one
	if outputFile == "" {
		outputFile = generateDefaultOutputFilename("rhel")
	}

	// Initialize the report generator
	reportGenerator := report.NewAsciiDocReport(outputFile)
	reportGenerator.Initialize(hostname, "RHEL Health Check Report")

	// Create a map of all available check functions
	allChecks := map[string][]func(*report.AsciiDocReport){
		"system":      {rhel.RunSystemInfoChecks},
		"time":        {rhel.RunTimeChecks},
		"memory":      {rhel.RunMemoryChecks},
		"disk":        {rhel.RunDiskChecks},
		"performance": {rhel.RunCPUChecks, rhel.RunPerformanceChecks},
		"network":     {rhel.RunNetworkChecks, rhel.RunConnectivityChecks, rhel.RunHANetworkingChecks},
		"security":    {rhel.RunSecurityChecks, rhel.RunComplianceChecks},
		"services":    {rhel.RunServicesChecks},
		"logs":        {rhel.RunLogsChecks, rhel.RunMonitoringChecks},
		"packages":    {rhel.RunPackagesChecks},
		//"cluster":       {rhel.RunClusterChecks},
		"auth":    {rhel.RunAuthChecks},
		"backup":  {rhel.RunBackupChecks},
		"kernel":  {rhel.RunKernelChecks},
		"storage": {rhel.RunStorageChecks, rhel.RunStorageConsiderationsChecks},
	}

	// Build the list of enabled checks
	var enabledChecks []func(*report.AsciiDocReport)
	var totalChecks int

	for category, checks := range allChecks {
		if isCategoryEnabled(category, skipCategories, includeCategories) {
			enabledChecks = append(enabledChecks, checks...)
			totalChecks += len(checks)
		}
	}

	// Run the checks with progress tracking
	runChecks("RHEL", totalChecks, func(total int, bar *progressbar.ProgressBar) {
		if parallelExecution {
			runParallelChecks(enabledChecks, reportGenerator, bar)
		} else {
			runSequentialChecks(enabledChecks, reportGenerator, bar)
		}
	})

	// Generate and save the report
	outputPath, err := reportGenerator.Generate()
	if err != nil {
		return fmt.Errorf("failed to generate report: %v", err)
	}

	// Compress the report with password protection automatically
	finalPath, err := compressReportIfNeeded(outputPath)
	if err != nil {
		fmt.Printf("Warning: %v\n", err)
	}

	fmt.Printf("Report saved to: %s\n", finalPath)
	return nil
}
