// pkg/checks/satellite/backup.go

package satellite

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunBackupChecks Implementation of the stub function declared in checks.go
func RunBackupChecks(r *report.AsciiDocReport) {
	// Check if backup procedures are in place
	checkBackupProcedures(r)
}

// BackupInfo represents information about a detected backup
type BackupInfo struct {
	Date      time.Time
	Location  string
	Type      string // online, offline, etc.
	Completed bool
}

// checkBackupProcedures confirms Satellite backup procedures are in place and tested
func checkBackupProcedures(r *report.AsciiDocReport) {
	checkID := "satellite-backup-procedures"
	checkName := "Backup Procedures"
	checkDesc := "Confirms Satellite backup procedures are in place and tested."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Backup Procedures Analysis:\n\n")

	// Check backup tools
	backupToolsCmd := "which foreman-maintain satellite-maintain katello-backup satellite-backup 2>/dev/null || echo 'No backup tools found'"
	backupToolsOutput, _ := utils.RunCommand("bash", "-c", backupToolsCmd)

	detail.WriteString("Backup Tools:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(backupToolsOutput)
	detail.WriteString("\n----\n\n")

	// More robust checks for backup history in logs, including compressed logs
	// First, check regular logs for backup operations
	regularLogCmd := "grep -E 'backup|restore' /var/log/foreman-maintain/foreman-maintain.log | grep -E 'Running.*backup|Scenario.*Backup.*finished' | sort -r | head -50"
	regularLogOutput, _ := utils.RunCommand("bash", "-c", regularLogCmd)

	// Then check compressed logs from the last two weeks
	compressedLogCmd := "find /var/log/foreman-maintain/ -name 'foreman-maintain.log-*.gz' -mtime -14 -exec zgrep -E 'backup|restore' {} \\; | grep -E 'Running.*backup|Scenario.*Backup.*finished' | sort -r | head -50"
	compressedLogOutput, _ := utils.RunCommand("bash", "-c", compressedLogCmd)

	// Also check non-compressed rotated logs from the last two weeks
	rotatedLogCmd := "find /var/log/foreman-maintain/ -name 'foreman-maintain.log-*' -not -name '*.gz' -mtime -14 -exec grep -E 'backup|restore' {} \\; | grep -E 'Running.*backup|Scenario.*Backup.*finished' | sort -r | head -50"
	rotatedLogOutput, _ := utils.RunCommand("bash", "-c", rotatedLogCmd)

	// Combine all log outputs
	foreman_maintain_log_output := regularLogOutput
	if compressedLogOutput != "" {
		foreman_maintain_log_output += "\n" + compressedLogOutput
	}
	if rotatedLogOutput != "" {
		foreman_maintain_log_output += "\n" + rotatedLogOutput
	}

	detail.WriteString("Recent Backup Commands and Completions in Logs:\n\n")
	if foreman_maintain_log_output == "" {
		detail.WriteString("No backup commands found in logs\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(foreman_maintain_log_output)
		detail.WriteString("\n----\n\n")
	}

	// More robust check for completed backup steps in logs, including compressed logs
	regular_steps_cmd := "grep -E 'Execution step.*backup.*finished|Scenario.*Backup.*finished' /var/log/foreman-maintain/foreman-maintain.log | sort -r | head -20"
	regular_steps_output, _ := utils.RunCommand("bash", "-c", regular_steps_cmd)

	compressed_steps_cmd := "find /var/log/foreman-maintain/ -name 'foreman-maintain.log-*.gz' -mtime -14 -exec zgrep -E 'Execution step.*backup.*finished|Scenario.*Backup.*finished' {} \\; | sort -r | head -20"
	compressed_steps_output, _ := utils.RunCommand("bash", "-c", compressed_steps_cmd)

	rotated_steps_cmd := "find /var/log/foreman-maintain/ -name 'foreman-maintain.log-*' -not -name '*.gz' -mtime -14 -exec grep -E 'Execution step.*backup.*finished|Scenario.*Backup.*finished' {} \\; | sort -r | head -20"
	rotated_steps_output, _ := utils.RunCommand("bash", "-c", rotated_steps_cmd)

	// Combine all step outputs
	backup_steps_output := regular_steps_output
	if compressed_steps_output != "" {
		backup_steps_output += "\n" + compressed_steps_output
	}
	if rotated_steps_output != "" {
		backup_steps_output += "\n" + rotated_steps_output
	}

	detail.WriteString("Recent Completed Backup Steps:\n\n")
	if backup_steps_output == "" {
		detail.WriteString("No completed backup steps found in logs\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(backup_steps_output)
		detail.WriteString("\n----\n\n")
	}

	// Extract backup information from logs
	backupInfoMap := make(map[string]BackupInfo)

	// Parse backup commands from logs
	parseBackupCommands(foreman_maintain_log_output, backupInfoMap)

	// Parse backup completions to determine if backups finished
	parseBackupCompletions(backup_steps_output, backupInfoMap)

	// Get most recent complete backup
	var mostRecentBackup time.Time
	var mostRecentLocation string
	var mostRecentType string

	// Count successful recent backups (last 30 days)
	recentSuccessfulBackups := 0

	// Show backup summary in chronological order
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Backup History Summary:\n\n")

	// Convert map to sorted array for display
	var backupInfoArr []BackupInfo
	for _, info := range backupInfoMap {
		backupInfoArr = append(backupInfoArr, info)
	}

	if len(backupInfoArr) == 0 {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[cols=\"1,1,1,1\", options=\"header\"]\n|===\n")
		detail.WriteString("|Date|Location|Type|Status\n")

		// Sort by date (most recent first)
		sort.Slice(backupInfoArr, func(i, j int) bool {
			return backupInfoArr[i].Date.After(backupInfoArr[j].Date)
		})

		// Display sorted backups
		for _, info := range backupInfoArr {
			status := "Unknown"
			if info.Completed {
				status = "Completed"

				// Update most recent backup info
				if mostRecentBackup.IsZero() || info.Date.After(mostRecentBackup) {
					mostRecentBackup = info.Date
					mostRecentLocation = info.Location
					mostRecentType = info.Type
				}

				// Count recent successful backups
				if time.Since(info.Date) < 30*24*time.Hour {
					recentSuccessfulBackups++
				}
			} else {
				status = "Incomplete/Unknown"
			}

			detail.WriteString(fmt.Sprintf("|%s|%s|%s|%s\n",
				info.Date.Format("2006-01-02 15:04:05"),
				info.Location,
				info.Type,
				status))
		}
		detail.WriteString("|===\n\n")
	}

	// Add backup summary
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Backup Summary:\n\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Metric|Value\n")
	detail.WriteString(fmt.Sprintf("|Recent successful backups (last 30 days)|%d\n", recentSuccessfulBackups))

	if !mostRecentBackup.IsZero() {
		detail.WriteString(fmt.Sprintf("|Most recent backup date|%s\n", mostRecentBackup.Format("2006-01-02 15:04:05")))
		detail.WriteString(fmt.Sprintf("|Days since last backup|%.1f\n", time.Since(mostRecentBackup).Hours()/24.0))
		detail.WriteString(fmt.Sprintf("|Most recent backup location|%s\n", mostRecentLocation))
		detail.WriteString(fmt.Sprintf("|Most recent backup type|%s\n", mostRecentType))
	}
	detail.WriteString("|===\n\n")

	// Check for backup cron jobs
	cronCmd := "grep -r 'foreman-maintain\\|satellite-maintain\\|backup' /etc/cron* /var/spool/cron 2>/dev/null"
	cronOutput, _ := utils.RunCommand("bash", "-c", cronCmd)

	detail.WriteString("Backup Cron Jobs:\n\n")
	if cronOutput == "" {
		detail.WriteString("No backup cron jobs found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(cronOutput)
		detail.WriteString("\n----\n\n")
	}

	// Evaluate results
	if recentSuccessfulBackups == 0 {
		check.Result = report.NewResult(report.StatusCritical,
			"No recent backups found in logs",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Implement regular backup procedure immediately")
		report.AddRecommendation(&check.Result, "Use satellite-maintain backup or foreman-maintain backup for consistent backups")
		report.AddRecommendation(&check.Result, "Set up a cron job for automated backups")
	} else if !mostRecentBackup.IsZero() && time.Since(mostRecentBackup) > 14*24*time.Hour {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Last backup is %.1f days old", time.Since(mostRecentBackup).Hours()/24.0),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Perform a backup immediately")
		report.AddRecommendation(&check.Result, "Ensure backup automation is working properly")
	} else if recentSuccessfulBackups < 2 && cronOutput == "" {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Only %d recent backup found and no cron job configured", recentSuccessfulBackups),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Set up automated backups via cron")
		report.AddRecommendation(&check.Result, "Implement a regular backup schedule")
	} else if recentSuccessfulBackups > 0 {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Found %d recent backups in logs", recentSuccessfulBackups),
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Backup status could not be properly determined",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify backup procedures manually")
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/backing-up-satellite-server-and-capsule_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	//report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/3033621") // Satellite backup best practices

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// parseBackupCommands extracts information about backup commands from log output
func parseBackupCommands(logOutput string, backupInfoMap map[string]BackupInfo) {
	// Example log line: "I, [2025-04-24 23:38:22-0400 #2603]  INFO -- : Running foreman-maintain command with arguments [["backup", "offline", "--skip-pulp-content", "/root/backup"]]"
	lines := strings.Split(logOutput, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Extract date
		dateMatch := regexp.MustCompile(`\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{4})`).FindStringSubmatch(line)
		if len(dateMatch) < 2 {
			continue
		}

		dateStr := dateMatch[1]
		date, err := time.Parse("2006-01-02 15:04:05-0700", dateStr)
		if err != nil {
			continue
		}

		// Check if this is a backup command
		if strings.Contains(line, "Running") && strings.Contains(line, "backup") {
			// Extract command details
			cmdMatch := regexp.MustCompile(`Running .*?command with arguments \[\["backup", "(.*?)"(.*)\]\]`).FindStringSubmatch(line)
			if len(cmdMatch) < 2 {
				continue
			}

			// Extract backup type
			backupType := cmdMatch[1] // online, offline, etc.

			// Extract location (path argument)
			locationMatch := regexp.MustCompile(`"(/[^"]+)"`).FindStringSubmatch(cmdMatch[2])
			location := "Unknown"
			if len(locationMatch) >= 2 {
				location = locationMatch[1]
			}

			// Use date as key to avoid duplicates
			key := date.Format("2006-01-02 15:04:05")
			backupInfoMap[key] = BackupInfo{
				Date:      date,
				Location:  location,
				Type:      backupType,
				Completed: false, // Will be updated by completion info
			}
		}
	}
}

// parseBackupCompletions identifies completed backups from log output
func parseBackupCompletions(logOutput string, backupInfoMap map[string]BackupInfo) {
	// Look for final backup completion markers:
	// "I, [2025-04-24 23:41:07-0400 #2603]  INFO -- : === Scenario 'Backup' finished ==="
	// Or compression step completion:
	// "I, [2025-04-24 23:40:07-0400 #2603]  INFO -- : --- Execution step 'Compress backup data to save space' [backup-compress-data] finished ---"

	lines := strings.Split(logOutput, "\n")
	for _, line := range lines {
		if line == "" {
			continue
		}

		// Extract date
		dateMatch := regexp.MustCompile(`\[(\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}[+-]\d{4})`).FindStringSubmatch(line)
		if len(dateMatch) < 2 {
			continue
		}

		dateStr := dateMatch[1]
		date, err := time.Parse("2006-01-02 15:04:05-0700", dateStr)
		if err != nil {
			continue
		}

		// Check if this is a completion message
		isCompletion := strings.Contains(line, "Scenario 'Backup' finished") ||
			(strings.Contains(line, "backup-compress-data") && strings.Contains(line, "finished"))

		if isCompletion {
			// Find the closest backup command (within reasonable time period, like 30 minutes)
			// This handles cases where the backup takes some time to complete
			var closestKey string
			var closestDiff time.Duration = 30 * time.Minute // Maximum time allowed

			for key, info := range backupInfoMap {
				if info.Completed {
					continue // Skip already completed backups
				}

				timeDiff := date.Sub(info.Date)
				if timeDiff >= 0 && timeDiff < closestDiff {
					closestDiff = timeDiff
					closestKey = key
				}
			}

			// Update the closest backup to mark it as completed
			if closestKey != "" {
				info := backupInfoMap[closestKey]
				info.Completed = true
				backupInfoMap[closestKey] = info
			}
		}
	}
}
