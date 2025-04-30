// pkg/checks/satellite/content.go

package satellite

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunContentChecks performs Satellite content management checks
// This function has a special signature with an organization parameter
func RunContentChecks(r *report.AsciiDocReport, organization string) {
	// Check sync status of repositories
	checkRepositorySyncStatus(r, organization)

	// Check Content Views status
	checkContentViewStatus(r, organization)

	// Check sync plans
	checkSyncPlans(r, organization)

	// Check orphaned content
	checkOrphanedContent(r)

	// Perform detailed analysis of sync plans
	checkSyncPlanDetails(r)
}

// Updated functions for pkg/checks/satellite/content.go

// checkRepositorySyncStatus verifies the sync status of repositories
func checkRepositorySyncStatus(r *report.AsciiDocReport, organization string) {
	checkID := "satellite-repo-sync"
	checkName := "Repository Sync Status"
	checkDesc := "Validates sync status of repositories."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get default organization ID if none provided
	if organization == "" {
		organization = getDefaultOrganizationID()
	}

	// Build command using the safe organization flag function
	repoCmd := "hammer repository list --fields id,name,content_type,sync_state,last_sync"
	if organization != "" {
		repoCmd += safeOrganizationFlag(organization)
	}

	repoOutput, err := utils.RunCommand("bash", "-c", repoCmd)

	var detail strings.Builder
	detail.WriteString("Repository Sync Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving repository information:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve repository information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.AddRecommendation(&check.Result, "Try running 'hammer organization list' to find the correct organization ID")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/managing_red_hat_subscriptions_content-management",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	// Format repository output in asciidoc table
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(repoOutput)
	detail.WriteString("\n----\n\n")

	// Get more details about failed syncs
	failedSyncCmd := "hammer task list --search 'action  ~ Synchronize repository state=stopped result=warning or result=error' --order='started_at DESC' --per-page=10"
	failedSyncOutput, _ := utils.RunCommand("bash", "-c", failedSyncCmd)

	if !strings.Contains(failedSyncOutput, "No tasks found") {
		detail.WriteString("Recent Failed Sync Tasks:\n\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(failedSyncOutput)
		detail.WriteString("\n----\n\n")
	}

	// Count repositories by sync state
	neverSynced := 0
	failedSync := 0
	oldSync := 0
	runningSync := 0
	totalRepos := 0

	lines := strings.Split(repoOutput, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "|") {
			continue
		}

		totalRepos++

		// Check for never synced
		if strings.Contains(line, "Never synced") {
			neverSynced++
		}

		// Check for failed sync
		if strings.Contains(line, "failed") {
			failedSync++
		}

		// Check for running sync
		if strings.Contains(line, "running") {
			runningSync++
		}

		// Check for old syncs (more than 30 days)
		if lastSyncDate := extractLastSyncDate(line); lastSyncDate != "" {
			syncTime, err := time.Parse("2006-01-02 15:04:05 MST", lastSyncDate)
			if err == nil {
				if time.Since(syncTime) > 30*24*time.Hour {
					oldSync++
				}
			}
		}
	}

	// Adjust for header rows
	if totalRepos >= 3 {
		totalRepos -= 3 // Adjust for header rows and separator
	} else {
		totalRepos = 0
	}

	// Format summary in a nice table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Repository Sync Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Metric|Count\n")
	detail.WriteString(fmt.Sprintf("|Total repositories|%d\n", totalRepos))
	detail.WriteString(fmt.Sprintf("|Never synced|%d\n", neverSynced))
	detail.WriteString(fmt.Sprintf("|Failed sync|%d\n", failedSync))
	detail.WriteString(fmt.Sprintf("|Not synced in 30+ days|%d\n", oldSync))
	detail.WriteString(fmt.Sprintf("|Currently syncing|%d\n", runningSync))
	detail.WriteString("|===\n")

	// Check if we have significant issues
	if failedSync > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d repositories have failed sync status", failedSync),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate and resolve failed repository syncs")
		report.AddRecommendation(&check.Result, "Check specific repository errors in the Satellite web UI")
	} else if neverSynced > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d repositories have never been synced", neverSynced),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Sync repositories or disable unused ones")
	} else if oldSync > totalRepos/2 && totalRepos > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d repositories have not been synced in over 30 days", oldSync),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set up sync plans for regular repository updates")
		report.AddRecommendation(&check.Result, "Consider disabling unused repositories")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Repository sync status looks good",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/managing_red_hat_subscriptions_content-management",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkContentViewStatus checks if Content Views are published and promoted correctly
func checkContentViewStatus(r *report.AsciiDocReport, organization string) {
	checkID := "satellite-content-views"
	checkName := "Content Views Status"
	checkDesc := "Checks if Content Views are published and promoted correctly."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get default organization ID if none provided
	if organization == "" {
		organization = getDefaultOrganizationID()
	}

	// Build command using the safe organization flag function
	cvCmd := "hammer content-view list --fields id,name,composite,last_published,repositories,content_host_count"
	if organization != "" {
		cvCmd += safeOrganizationFlag(organization)
	}

	cvOutput, err := utils.RunCommand("bash", "-c", cvCmd)

	var detail strings.Builder
	detail.WriteString("Content Views Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving Content View information:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve Content View information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.AddRecommendation(&check.Result, "Try running 'hammer organization list' to find the correct organization ID")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/managing_content_views_content-management",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cvOutput)
	detail.WriteString("\n----\n\n")

	// Get more detailed information about content view versions
	cvVersionsCmd := "hammer content-view version list --per-page 20 --order=content_view_id,version"
	if organization != "" {
		cvVersionsCmd += safeOrganizationFlag(organization)
	}

	cvVersionsOutput, _ := utils.RunCommand("bash", "-c", cvVersionsCmd)
	detail.WriteString("Content View Versions:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cvVersionsOutput)
	detail.WriteString("\n----\n\n")

	// Get lifecycle environments
	lcEnvCmd := "hammer lifecycle-environment list"
	if organization != "" {
		lcEnvCmd += safeOrganizationFlag(organization)
	}

	lcEnvOutput, _ := utils.RunCommand("bash", "-c", lcEnvCmd)
	detail.WriteString("Lifecycle Environments:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(lcEnvOutput)
	detail.WriteString("\n----\n\n")

	// Analyze Content View status
	neverPublished := 0
	oldPublication := 0
	unusedViews := 0
	totalViews := 0

	lines := strings.Split(cvOutput, "\n")
	for _, line := range lines {
		if !strings.Contains(line, "|") {
			continue
		}

		totalViews++

		// Check for never published
		if strings.Contains(line, "Never published") {
			neverPublished++
		}

		// Check for old publication (more than 90 days)
		if lastPublished := extractLastSyncDate(line); lastPublished != "" {
			pubTime, err := time.Parse("2006-01-02 15:04:05 MST", lastPublished)
			if err == nil {
				if time.Since(pubTime) > 90*24*time.Hour {
					oldPublication++
				}
			}
		}

		// Check for unused content views (no hosts)
		if strings.Contains(line, "| 0 |") {
			unusedViews++
		}
	}

	// Adjust for header rows
	if totalViews >= 3 {
		totalViews -= 3 // Adjust for header rows and separator
	} else {
		totalViews = 0
	}

	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Content Views Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Metric|Count\n")
	detail.WriteString(fmt.Sprintf("|Total Content Views|%d\n", totalViews))
	detail.WriteString(fmt.Sprintf("|Never published|%d\n", neverPublished))
	detail.WriteString(fmt.Sprintf("|Not published in 90+ days|%d\n", oldPublication))
	detail.WriteString(fmt.Sprintf("|Unused (no hosts)|%d\n", unusedViews))
	detail.WriteString("|===\n\n")

	// Check for recent Content View publish tasks with issues
	cvTasksCmd := "hammer task list --search 'action ~ \"Publish content view\" state=stopped result=warning or result=error'"
	cvTasksOutput, _ := utils.RunCommand("bash", "-c", cvTasksCmd)

	if !strings.Contains(cvTasksOutput, "No tasks found") {
		detail.WriteString("Recent Content View Publish Issues:\n\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(cvTasksOutput)
		detail.WriteString("\n----\n")
	}

	// Evaluate overall status
	if neverPublished > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d Content Views have never been published", neverPublished),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Publish unused Content Views or remove them")
	} else if oldPublication > totalViews/2 && totalViews > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d Content Views have not been published in over 90 days", oldPublication),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Update Content Views regularly to include security updates")
	} else if unusedViews > totalViews/2 && totalViews > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d Content Views are not used by any hosts", unusedViews),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider removing or consolidating unused Content Views")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Content Views appear to be properly maintained",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/managing_content_views_content-management",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSyncPlans verifies sync plans are scheduled and running successfully
func checkSyncPlans(r *report.AsciiDocReport, organization string) {
	checkID := "satellite-sync-plans"
	checkName := "Sync Plans"
	checkDesc := "Ensures sync plans are scheduled and running successfully."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get default organization ID if none provided
	if organization == "" {
		organization = getDefaultOrganizationID()
	}

	// Build command using the safe organization flag function
	syncPlanCmd := "hammer sync-plan list"
	if organization != "" {
		syncPlanCmd += safeOrganizationFlag(organization)
	}

	syncPlanOutput, err := utils.RunCommand("bash", "-c", syncPlanCmd)

	var detail strings.Builder
	detail.WriteString("Sync Plans Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving Sync Plan information:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve Sync Plan information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.AddRecommendation(&check.Result, "Try running 'hammer organization list' to find the correct organization ID")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/synchronizing_content_between_servers_content-management",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(syncPlanOutput)
	detail.WriteString("\n----\n\n")

	// Get more detailed information about each sync plan if there are any
	totalSyncPlans := 0
	lines := strings.Split(syncPlanOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			totalSyncPlans++
		}
	}

	// Get detailed info about each sync plan
	if totalSyncPlans > 0 {
		// Get sync plan IDs
		syncPlanIDsCmd := "hammer sync-plan list"
		if organization != "" {
			syncPlanIDsCmd += safeOrganizationFlag(organization)
		}
		syncPlanIDsCmd += " | grep -v '\\-\\-\\-' | grep -v '^ID' | awk '{print $1}' | grep -v '^$'"
		syncPlanIDsOutput, _ := utils.RunCommand("bash", "-c", syncPlanIDsCmd)

		syncPlanIDs := strings.Split(strings.TrimSpace(syncPlanIDsOutput), "\n")

		detail.WriteString("Detailed Sync Plan Information:\n\n")

		// Only show detail for first 3 sync plans to avoid too much output
		maxPlansToShow := 3
		plansShown := 0
		for _, id := range syncPlanIDs {
			if id == "" {
				continue
			}

			if plansShown >= maxPlansToShow {
				detail.WriteString("... more sync plans exist (output limited) ...\n\n")
				break
			}

			detailCmd := fmt.Sprintf("hammer sync-plan info --id %s", id)
			if organization != "" {
				detailCmd += safeOrganizationFlag(organization)
			}
			detailOutput, _ := utils.RunCommand("bash", "-c", detailCmd)

			detail.WriteString(fmt.Sprintf("[source, bash]\n----\n# Sync Plan ID: %s\n", id))
			detail.WriteString(detailOutput)
			detail.WriteString("\n----\n\n")
			plansShown++
		}
	}

	// Check for recent sync tasks
	syncTasksCmd := "hammer task list --search 'action ~ \"Synchronize repository\" state=stopped' --order='started_at DESC' --per-page=10"
	syncTasksOutput, _ := utils.RunCommand("bash", "-c", syncTasksCmd)

	detail.WriteString("Recent Sync Tasks:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(syncTasksOutput)
	detail.WriteString("\n----\n\n")

	// Count failed sync tasks
	failedSyncs := 0
	successfulSyncs := 0

	lines = strings.Split(syncTasksOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "| error |") || strings.Contains(line, "| warning |") {
			failedSyncs++
		}
		if strings.Contains(line, "| success |") {
			successfulSyncs++
		}
	}

	// Get repositories without sync plans - use correct organization flag
	reposWithoutSyncCmd := "hammer repository list"
	if organization != "" {
		reposWithoutSyncCmd += safeOrganizationFlag(organization)
	}
	reposWithoutSyncCmd += " --fields id,name,sync_plan_name --per-page 999 | grep 'Sync Plan:' | grep -v -i -E '[a-zA-Z0-9_-]+ *\\|'"
	reposWithoutSyncOutput, _ := utils.RunCommand("bash", "-c", reposWithoutSyncCmd)

	reposWithoutSync := 0
	lines = strings.Split(reposWithoutSyncOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") {
			reposWithoutSync++
		}
	}

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Sync Tasks Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Metric|Count\n")
	detail.WriteString(fmt.Sprintf("|Total Sync Plans|%d\n", totalSyncPlans))
	detail.WriteString(fmt.Sprintf("|Recent Successful Syncs|%d\n", successfulSyncs))
	detail.WriteString(fmt.Sprintf("|Recent Failed Syncs|%d\n", failedSyncs))
	detail.WriteString(fmt.Sprintf("|Repositories without Sync Plans|%d\n", reposWithoutSync))
	detail.WriteString("|===\n\n")

	// Evaluate overall status
	if totalSyncPlans == 0 && reposWithoutSync > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"No sync plans configured but repositories exist",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Create sync plans to keep content updated")
		report.AddRecommendation(&check.Result, "Configure daily or weekly sync schedules based on content importance")
	} else if failedSyncs > successfulSyncs && (failedSyncs+successfulSyncs) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d of %d recent sync tasks have failed", failedSyncs, failedSyncs+successfulSyncs),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate failed sync tasks")
		report.AddRecommendation(&check.Result, "Check Satellite logs for sync errors")
	} else if reposWithoutSync > 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d repositories are not associated with any sync plan", reposWithoutSync),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Associate repositories with sync plans")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Sync plans appear to be properly configured",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/synchronizing_content_between_servers_content-management",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// extractLastSyncDate extracts the last sync date from a repository list line
func extractLastSyncDate(line string) string {
	// Example pattern: "| 2023-05-20 14:30:45 UTC |"
	re := regexp.MustCompile(`\|\s+(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\s+[A-Z]{3})\s+\|`)
	match := re.FindStringSubmatch(line)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// checkOrphanedContent checks for orphaned or unused content
func checkOrphanedContent(r *report.AsciiDocReport) {
	checkID := "satellite-orphaned-content"
	checkName := "Orphaned Content"
	checkDesc := "Checks for orphaned or unused content that can be cleaned up."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Run dry-run orphaned content check
	orphanedCmd := "foreman-rake katello:delete_orphaned_content --dry-run"
	orphanedOutput, err := utils.RunCommand("bash", "-c", orphanedCmd)

	var detail strings.Builder
	detail.WriteString("Orphaned Content Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error checking for orphaned content:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n", err.Error()))
		detail.WriteString("\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(orphanedOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for orphaned puppet modules
	puppetModulesCmd := "foreman-rake katello:clean_backend_objects --dry-run"
	puppetModulesOutput, _ := utils.RunCommand("bash", "-c", puppetModulesCmd)

	if !strings.Contains(puppetModulesOutput, "ERROR") {
		detail.WriteString("Orphaned Backend Objects:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(puppetModulesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check Pulp disk usage
	pulpDiskUsageCmd := "du -sh /var/lib/pulp /var/lib/pulp/content"
	pulpDiskUsageOutput, _ := utils.RunCommand("bash", "-c", pulpDiskUsageCmd)

	detail.WriteString("Pulp Disk Usage:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pulpDiskUsageOutput)
	detail.WriteString("\n----\n\n")

	// Get published content view version count
	cvVersionsCountCmd := "hammer content-view version list --per-page 1 | grep Total | awk '{print $2}'"
	cvVersionsCountOutput, _ := utils.RunCommand("bash", "-c", cvVersionsCountCmd)
	cvVersionsCount := 0
	fmt.Sscanf(strings.TrimSpace(cvVersionsCountOutput), "%d", &cvVersionsCount)

	// Parse orphaned content count
	orphanedCount := 0
	if !strings.Contains(orphanedOutput, "ERROR") && !strings.Contains(orphanedOutput, "No orphaned content") {
		re := regexp.MustCompile(`(\d+) orphaned content`)
		match := re.FindStringSubmatch(orphanedOutput)
		if len(match) > 1 {
			orphanedCount, _ = strconv.Atoi(match[1])
		}
	}

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Content Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Count\n")
	detail.WriteString(fmt.Sprintf("|Total Content View Versions|%d\n", cvVersionsCount))
	detail.WriteString(fmt.Sprintf("|Orphaned Content Items|%d\n", orphanedCount))

	// Add more specific details if available
	if strings.Contains(orphanedOutput, "docker_manifests") {
		detail.WriteString("|Orphaned Docker manifests|Yes\n")
	}
	if strings.Contains(orphanedOutput, "rpms") {
		detail.WriteString("|Orphaned RPMs|Yes\n")
	}
	detail.WriteString("|===\n\n")

	// Evaluate results
	if orphanedCount > 1000 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Large amount of orphaned content (%d items)", orphanedCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Run cleanup task: foreman-rake katello:delete_orphaned_content")
		report.AddRecommendation(&check.Result, "Schedule regular orphaned content cleanup")
	} else if cvVersionsCount > 50 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of content view versions (%d)", cvVersionsCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Clean up old content view versions to free disk space")
		report.AddRecommendation(&check.Result, "Set content view version limits in Satellite settings")
	} else if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not properly check for orphaned content",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Run orphaned content check manually: foreman-rake katello:delete_orphaned_content --dry-run")
	} else if orphanedCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d orphaned content items", orphanedCount),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Run cleanup task to free disk space: foreman-rake katello:delete_orphaned_content")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No significant orphaned content found",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
