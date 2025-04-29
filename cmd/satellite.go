// cmd/satellite.go

package cmd

import (
	"fmt"
	"os"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/checks/rhel"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/checks/satellite"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"github.com/schollz/progressbar/v3"
	"github.com/spf13/cobra"
)

// newSatelliteCmd creates the Satellite subcommand
func newSatelliteCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "satellite",
		Short: "Run Satellite health checks",
		Long: `Performs comprehensive health checks on a Red Hat Satellite server.
This includes all RHEL checks plus Satellite-specific checks for content management,
host management, database health, and Satellite services.`,
		RunE: runSatelliteChecks,
	}

	// Add Satellite-specific flags
	cmd.Flags().Bool("skip-rhel", false, "Skip RHEL health checks")
	cmd.Flags().Bool("skip-content-sync", false, "Skip content synchronization checks")
	cmd.Flags().Bool("skip-host", false, "Skip host management checks")
	cmd.Flags().Bool("skip-sync-plans", false, "Skip sync plan checks")
	cmd.Flags().Bool("skip-virtwho", false, "Skip virt-who configuration checks")
	cmd.Flags().String("organization", "", "Organization to check (checks all organizations if not specified)")

	return cmd
}

// runSatelliteChecks performs all Satellite health checks
func runSatelliteChecks(cmd *cobra.Command, args []string) error {
	// Check if running as root
	if !utils.RunningAsRoot() {
		fmt.Println("WARNING: This tool should be run with root/sudo privileges for complete results.")
		fmt.Println("Some checks may fail or provide incomplete information.")
	}

	// Parse command flags
	skipRhel, _ := cmd.Flags().GetBool("skip-rhel")
	skipContentSync, _ := cmd.Flags().GetBool("skip-content-sync")
	skipHost, _ := cmd.Flags().GetBool("skip-host")
	skipSyncPlans, _ := cmd.Flags().GetBool("skip-sync-plans")
	skipVirtWho, _ := cmd.Flags().GetBool("skip-virtwho")
	organization, _ := cmd.Flags().GetString("organization")

	// Verify this is a Satellite server
	if !utils.IsSatellite() {
		return fmt.Errorf("this does not appear to be a Red Hat Satellite server - required packages or services not found")
	}

	// Create a new report
	hostname, _ := os.Hostname()

	// If outputFile is not set, generate a default one
	if outputFile == "" {
		outputFile = generateDefaultOutputFilename("satellite")
	}

	// Initialize the report generator
	reportGenerator := report.NewAsciiDocReport(outputFile)
	reportGenerator.Initialize(hostname, "Satellite Health Check Report")

	// Track total number of checks
	var totalChecks int
	var enabledChecks []func(*report.AsciiDocReport)

	// Convert skip flags to categories to skip
	if skipRhel {
		skipCategories = append(skipCategories, "rhel")
	}
	if skipContentSync {
		skipCategories = append(skipCategories, "content")
	}
	if skipHost {
		skipCategories = append(skipCategories, "host")
	}
	if skipSyncPlans {
		skipCategories = append(skipCategories, "sync_plans")
	}
	if skipVirtWho {
		skipCategories = append(skipCategories, "virtwho")
	}

	// Add RHEL checks if not skipped
	if !skipRhel {
		// Create a map of all RHEL check functions - INCLUDE ALL CHECKS EXCEPT CLUSTER
		rhelChecks := map[string][]func(*report.AsciiDocReport){
			"system":      {rhel.RunSystemInfoChecks},
			"time":        {rhel.RunTimeChecks},
			"memory":      {rhel.RunMemoryChecks},
			"storage":     {rhel.RunDiskChecks, rhel.RunStorageConsiderationsChecks},
			"performance": {}, // Skip RHEL performance checks as Satellite has its own performance checks
			"network":     {rhel.RunNetworkChecks, rhel.RunConnectivityChecks, rhel.RunHANetworkingChecks},
			"security":    {}, // Skip RHEL security checks as Satellite has its own security checks
			"services":    {rhel.RunServicesChecks},
			"logs":        {rhel.RunLogsChecks}, // Skip RHEL monitoring checks
			"packages":    {rhel.RunPackagesChecks},
			"auth":        {rhel.RunAuthChecks},
			"backup":      {}, // Skip RHEL backup checks as Satellite has its own backup checks
			"kernel":      {rhel.RunKernelChecks},
			"compliance":  {rhel.RunComplianceChecks}, // Skip RHEL storage checks as Satellite has its own storage checks
			// Intentionally excluding "cluster" category which contains cluster.go checks
		}

		// Add enabled RHEL checks
		for category, checks := range rhelChecks {
			if isCategoryEnabled(category, skipCategories, includeCategories) {
				enabledChecks = append(enabledChecks, checks...)
				totalChecks += len(checks)
			}
		}
	}

	// Add Satellite-specific checks
	satelliteChecks := map[string][]func(*report.AsciiDocReport){
		"system":        {satellite.RunSystemChecks},
		"storage":       {satellite.RunStorageChecks},
		"database":      {satellite.RunDatabaseChecks},
		"content":       {getContentCheckFunc(skipContentSync, organization)},
		"capsule":       {satellite.RunCapsuleChecks},
		"performance":   {satellite.RunPerformanceChecks},
		"security":      {satellite.RunSecurityChecks},
		"tasks":         {satellite.RunTasksChecks},
		"backup":        {satellite.RunBackupChecks},
		"monitoring":    {satellite.RunMonitoringChecks, satellite.RunMonitoringIntegrationChecks},
		"configuration": {satellite.RunConfigurationChecks},
		"subscription":  {getSubscriptionCheckFunc(organization)},
		"consistency":   {satellite.RunConsistencyChecks},
		"orchestration": {satellite.RunOrchestrationChecks},
		"plugin":        {satellite.RunPluginChecks},
		"proxy":         {satellite.RunProxyChecks},
		"provisioning":  {satellite.RunProvisioningChecks},
		"user":          {satellite.RunUserChecks},
		"legacy":        {satellite.RunLegacyChecks},
		"insights":      {satellite.RunInsightsChecks},
		"host":          {satellite.RunHostManagementChecks},
		"sync_plans":    {satellite.RunSyncPlanChecks},
		"virtwho":       {satellite.RunVirtWhoChecks},
	}

	// Add enabled Satellite checks
	for category, checks := range satelliteChecks {
		if isCategoryEnabled(category, skipCategories, includeCategories) {
			enabledChecks = append(enabledChecks, checks...)
			totalChecks += len(checks)
		}
	}

	// Run the checks with progress tracking
	runChecks("Satellite", totalChecks, func(total int, bar *progressbar.ProgressBar) {
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

// getContentCheckFunc returns a function that runs content checks with the right parameters
func getContentCheckFunc(skipContentSync bool, organization string) func(*report.AsciiDocReport) {
	if skipContentSync {
		// Return an empty function as we're skipping content sync
		return func(r *report.AsciiDocReport) {}
	}

	return func(r *report.AsciiDocReport) {
		satellite.RunContentChecks(r, organization)
	}
}

// getSubscriptionCheckFunc returns a function that runs subscription checks with the right parameters
func getSubscriptionCheckFunc(organization string) func(*report.AsciiDocReport) {
	return func(r *report.AsciiDocReport) {
		satellite.RunSubscriptionChecks(r, organization)
	}
}
