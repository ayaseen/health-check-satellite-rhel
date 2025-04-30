// pkg/checks/satellite/tasks.go

package satellite

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunTasksChecks performs Satellite tasks checks
func RunTasksChecks(r *report.AsciiDocReport) {
	// Check for paused or stuck tasks
	checkTaskStatus(r)

	// Check task cleanup configuration
	checkTaskCleanup(r)

	// Check expired tokens
	checkExpiredTokens(r)
}

// checkTaskStatus checks for paused or stuck tasks in the queue
func checkTaskStatus(r *report.AsciiDocReport) {
	checkID := "satellite-task-status"
	checkName := "Task Queue Status"
	checkDesc := "Checks for paused or stuck tasks in the Satellite task queue."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// List all tasks using hammer
	tasksCmd := "hammer task list --search 'state != stopped' --per-page 100"
	tasksOutput, err := utils.RunCommand("bash", "-c", tasksCmd)

	var detail strings.Builder
	detail.WriteString("Task Queue Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving task list:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve task list",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/monitoring_resources_admin#Managing_Tasks_admin",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("Active Tasks:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(tasksOutput)
	detail.WriteString("\n----\n\n")

	// Count running tasks by state
	runningTasks := countTasksByState(tasksOutput, "running")
	pausedTasks := countTasksByState(tasksOutput, "paused")
	pendingTasks := countTasksByState(tasksOutput, "pending")
	planningTasks := countTasksByState(tasksOutput, "planning")

	// Get long-running tasks (more than 1 hour) if applicable
	longRunningCmd := "hammer task list --search 'started_at < \"1 hour ago\" AND state = running' --per-page 50"
	longRunningOutput, _ := utils.RunCommand("bash", "-c", longRunningCmd)

	if longRunningOutput != "" && !strings.Contains(longRunningOutput, "No tasks found") {
		detail.WriteString("Long-Running Tasks (>1 hour):\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(longRunningOutput)
		detail.WriteString("\n----\n\n")
	}

	// Create a task summary table
	detail.WriteString("Task Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Task State|Count\n")
	detail.WriteString(fmt.Sprintf("|Running tasks|%d\n", runningTasks))
	detail.WriteString(fmt.Sprintf("|Paused tasks|%d\n", pausedTasks))
	detail.WriteString(fmt.Sprintf("|Pending tasks|%d\n", pendingTasks))
	detail.WriteString(fmt.Sprintf("|Planning tasks|%d\n", planningTasks))
	detail.WriteString("|===\n\n")

	// Check for task issues
	if pausedTasks > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d paused tasks in the task queue", pausedTasks),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Resume or cancel paused tasks using the Satellite web UI")
		report.AddRecommendation(&check.Result, "Check the task details for any errors that caused the pause")
	} else if pendingTasks > 10 {
		// High number of pending tasks could indicate a backlog
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of pending tasks (%d) in the queue", pendingTasks),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check if dynflow services are running properly")
		report.AddRecommendation(&check.Result, "Consider increasing the number of task workers")
	} else if runningTasks > 20 {
		// Many concurrent running tasks could impact performance
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of running tasks (%d) may impact performance", runningTasks),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor system performance while tasks are running")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Task queue appears to be healthy",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/monitoring_resources_admin#Managing_Tasks_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// countTasksByState counts the number of tasks in a specific state
func countTasksByState(output string, state string) int {
	count := 0
	lines := strings.Split(output, "\n")

	for _, line := range lines {
		if strings.Contains(strings.ToLower(line), strings.ToLower(state)) {
			count++
		}
	}

	return count
}

// checkTaskCleanup verifies automatic task cleanup is configured
func checkTaskCleanup(r *report.AsciiDocReport) {
	checkID := "satellite-task-cleanup"
	checkName := "Task Cleanup Configuration"
	checkDesc := "Checks if automatic task cleanup is configured properly."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get task cleanup settings
	settingsCmd := "hammer settings list --search 'name ~ task_'"
	settingsOutput, err := utils.RunCommand("bash", "-c", settingsCmd)

	var detail strings.Builder
	detail.WriteString("Task Cleanup Configuration:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving task cleanup settings:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))
	} else {
		detail.WriteString("Task Cleanup Settings:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(settingsOutput)
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

	// Get last yum update
	lastUpdateCmd := "hammer task list --search 'action ~ \"Clean\" or action ~ \"Remove\\ orphans\" state = stopped' --order='started_at desc' --per-page 1"
	lastUpdateOutput, _ := utils.RunCommand("bash", "-c", lastUpdateCmd)

	detail.WriteString("Last Cleanup Task:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(lastUpdateOutput)
	detail.WriteString("\n----\n\n")

	// Parse settings to determine if cleanup is properly configured
	taskCleanupEnabled := false
	taskCleanupDays := 0

	lines := strings.Split(settingsOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "task_cleanup_size") || strings.Contains(line, "task_cleanup_days") {
			fields := strings.Fields(line)
			if len(fields) > 1 {
				// Extract numeric value
				for _, field := range fields {
					if val, err := strconv.Atoi(field); err == nil {
						if val > 0 {
							taskCleanupEnabled = true
							if strings.Contains(line, "task_cleanup_days") {
								taskCleanupDays = val
							}
						}
						break
					}
				}
			}
		}
	}

	// Get current task counts
	tasksCountCmd := "hammer task list --per-page 1 | grep 'Total:' | awk '{print $2}'"
	tasksCountOutput, _ := utils.RunCommand("bash", "-c", tasksCountCmd)
	totalTasks := 0
	fmt.Sscanf(strings.TrimSpace(tasksCountOutput), "%d", &totalTasks)

	// Create a summary table
	detail.WriteString("Task Cleanup Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Setting|Value\n")
	detail.WriteString(fmt.Sprintf("|Total Tasks in Database|%d\n", totalTasks))
	detail.WriteString(fmt.Sprintf("|Task Cleanup Enabled|%s\n", boolToYesNo(taskCleanupEnabled)))

	if taskCleanupDays > 0 {
		detail.WriteString(fmt.Sprintf("|Task Cleanup Days|%d\n", taskCleanupDays))
	} else {
		detail.WriteString("|Task Cleanup Days|Not configured\n")
	}
	detail.WriteString("|===\n\n")

	// Evaluate results
	if !taskCleanupEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Automatic task cleanup may not be properly configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure task_cleanup_days and task_cleanup_size settings")
		report.AddRecommendation(&check.Result, "Recommended settings: task_cleanup_days=30, task_cleanup_size=1000")
	} else if totalTasks > 10000 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of tasks in database (%d)", totalTasks),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Run manual task cleanup to reduce database size")
		report.AddRecommendation(&check.Result, "Consider decreasing task_cleanup_days setting")
	} else if taskCleanupDays > 90 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Task cleanup retention period is very long (%d days)", taskCleanupDays),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider reducing task_cleanup_days to 30-60 days")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Task cleanup is properly configured",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/monitoring_resources_admin#Managing_Tasks_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/3362821") // Satellite task cleanup recommendations

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkExpiredTokens checks for expired tokens and orphaned tasks
func checkExpiredTokens(r *report.AsciiDocReport) {
	checkID := "satellite-expired-tokens"
	checkName := "Expired Tokens and Orphaned Objects"
	checkDesc := "Checks for expired tokens, orphaned tasks, and other cleanup items."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get token counts
	tokenCmd := "echo 'Token.count; Token.where(\"expires < '\\'now\\''\").count' | foreman-rake console"
	tokenOutput, err := utils.RunCommand("bash", "-c", tokenCmd)

	var detail strings.Builder
	detail.WriteString("Token and Orphaned Object Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving token information:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))
	} else {
		detail.WriteString("Token Information:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(tokenOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for orphaned template invocations (job invocations without hosts)
	// This is just a count query and doesn't delete anything
	orphanedJobsCmd := "echo 'JobInvocation.where(\"id NOT IN (SELECT DISTINCT job_invocation_id FROM template_invocations)\").count' | foreman-rake console"
	orphanedJobsOutput, jobErr := utils.RunCommand("bash", "-c", orphanedJobsCmd)

	if jobErr == nil {
		detail.WriteString("Orphaned Job Invocations:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(orphanedJobsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Parse results
	totalTokens := 0
	expiredTokens := 0

	if err == nil {
		lines := strings.Split(tokenOutput, "\n")
		for i, line := range lines {
			numStr := strings.TrimSpace(line)
			// Try to extract numbers
			for _, word := range strings.Fields(numStr) {
				if val, err := strconv.Atoi(word); err == nil {
					if i == 0 {
						totalTokens = val
					} else if i == 1 {
						expiredTokens = val
					}
					break
				}
			}
		}
	}

	// Parse orphaned jobs
	orphanedJobs := 0
	if jobErr == nil {
		for _, line := range strings.Split(orphanedJobsOutput, "\n") {
			numStr := strings.TrimSpace(line)
			// Try to extract numbers
			for _, word := range strings.Fields(numStr) {
				if val, err := strconv.Atoi(word); err == nil {
					orphanedJobs = val
					break
				}
			}
		}
	}

	// Create a summary table
	detail.WriteString("Summary:\n\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Count\n")
	detail.WriteString(fmt.Sprintf("|Total tokens|%d\n", totalTokens))
	detail.WriteString(fmt.Sprintf("|Expired tokens|%d\n", expiredTokens))
	detail.WriteString(fmt.Sprintf("|Orphaned job invocations|%d\n", orphanedJobs))
	detail.WriteString("|===\n\n")

	// Add cleanup commands for reference
	detail.WriteString("Cleanup Commands Reference:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString("# To clear expired sessions/tokens\n")
	detail.WriteString("foreman-rake db:sessions:clear\n\n")
	detail.WriteString("# To clean orphaned objects\n")
	detail.WriteString("foreman-rake katello:clean_backend_objects\n")
	detail.WriteString("\n----\n\n")

	// Evaluate results
	if expiredTokens > 1000 || (totalTokens > 0 && float64(expiredTokens)/float64(totalTokens) > 0.5) {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of expired tokens (%d)", expiredTokens),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Clean up expired tokens using foreman-rake task")
		report.AddRecommendation(&check.Result, "Run: foreman-rake db:sessions:clear")
	} else if orphanedJobs > 100 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("High number of orphaned job invocations (%d)", orphanedJobs),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Run cleanup job for orphaned job invocations")
	} else if err != nil || jobErr != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not fully check for expired tokens or orphaned objects",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Run token cleanup manually as a precaution")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No significant token or orphaned object issues found",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/migrating_from_internal_databases_to_external_databases_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1498873") // Satellite maintenance tasks

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
