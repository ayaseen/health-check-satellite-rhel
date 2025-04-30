// pkg/checks/rhel/backup.go

package rhel

import (
	"fmt"
	"strings"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunBackupChecks performs backup related checks
func RunBackupChecks(r *report.AsciiDocReport) {
	// Confirm backup systems and snapshot availability
	checkBackupSystems(r)

	// Test recovery process
	checkRecoveryProcess(r)

	// Validate application-level backups
	checkApplicationBackups(r)
}

// checkBackupSystems confirms backup systems and snapshot availability
func checkBackupSystems(r *report.AsciiDocReport) {
	checkID := "backup-systems"
	checkName := "Backup Systems"
	checkDesc := "Confirms backup systems and snapshot availability."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Look for common backup tools
	backupToolsCmd := "rpm -qa | grep -E '(backup|rsync|amanda|bacula|borg|duplicity|restic|bareos)' || echo 'No backup tools detected'"
	backupToolsOutput, _ := utils.RunCommand("bash", "-c", backupToolsCmd)

	// Check for cron jobs related to backups
	cronBackupsCmd := "cat /etc/cron.d/* /var/spool/cron/* 2>/dev/null | grep -iE '(backup|dump|rsync|tar|copy)' || echo 'No backup cron jobs found'"
	cronBackupsOutput, _ := utils.RunCommand("bash", "-c", cronBackupsCmd)

	// Check for backup directories
	backupDirsCmd := "ls -l /backup /var/backup /opt/backup /data/backup ~/backup 2>/dev/null || echo 'No common backup directories found'"
	backupDirsOutput, _ := utils.RunCommand("bash", "-c", backupDirsCmd)

	// Check for mounted backup volumes
	backupMountsCmd := "df -h | grep -i backup || echo 'No backup mounts found'"
	backupMountsOutput, _ := utils.RunCommand("bash", "-c", backupMountsCmd)

	// Check for LVM snapshots
	lvmSnapshotsCmd := "lvs | grep snap || echo 'No LVM snapshots found'"
	lvmSnapshotsOutput, _ := utils.RunCommand("bash", "-c", lvmSnapshotsCmd)

	var detail strings.Builder
	detail.WriteString("Backup Tools Installed:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(backupToolsOutput, "No backup tools detected") {
		detail.WriteString("No common backup tools detected\n")
	} else {
		detail.WriteString(backupToolsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Backup Cron Jobs:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(cronBackupsOutput, "No backup cron jobs found") {
		detail.WriteString("No backup cron jobs found\n")
	} else {
		detail.WriteString(cronBackupsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Backup Directories:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(backupDirsOutput, "No common backup directories found") {
		detail.WriteString("No common backup directories found\n")
	} else {
		detail.WriteString(backupDirsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Backup Mounts:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(backupMountsOutput, "No backup mounts found") {
		detail.WriteString("No backup mounts found\n")
	} else {
		detail.WriteString(backupMountsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("LVM Snapshots:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(lvmSnapshotsOutput, "No LVM snapshots found") {
		detail.WriteString("No LVM snapshots found\n")
	} else {
		detail.WriteString(lvmSnapshotsOutput)
	}
	detail.WriteString("\n----\n")

	// Determine if backups are configured
	noBackupTools := strings.Contains(backupToolsOutput, "No backup tools detected")
	noCronJobs := strings.Contains(cronBackupsOutput, "No backup cron jobs found")
	noBackupDirs := strings.Contains(backupDirsOutput, "No common backup directories found")
	noBackupMounts := strings.Contains(backupMountsOutput, "No backup mounts found")
	noSnapshots := strings.Contains(lvmSnapshotsOutput, "No LVM snapshots found")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate backup system availability
	if noBackupTools && noCronJobs && noBackupDirs && noBackupMounts && noSnapshots {
		check.Result = report.NewResult(report.StatusWarning,
			"No backup system detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Implement a backup strategy for this system")
		report.AddRecommendation(&check.Result, "Consider tools like rsync, borgbackup, or enterprise backup solutions")
		report.AddRecommendation(&check.Result, "Set up regular backup schedules using cron")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/system_design_guide/backup-and-recovery", rhelVersion))
	} else if (noBackupTools && noCronJobs) || (noBackupDirs && noBackupMounts && noSnapshots) {
		check.Result = report.NewResult(report.StatusWarning,
			"Backup system may be incomplete",
			report.ResultKeyRecommended)

		if noBackupTools && noCronJobs {
			report.AddRecommendation(&check.Result, "No backup tools or scheduled jobs detected")
			report.AddRecommendation(&check.Result, "Install and configure backup tools and scheduled jobs")
		}

		if noBackupDirs && noBackupMounts && noSnapshots {
			report.AddRecommendation(&check.Result, "No backup storage locations detected")
			report.AddRecommendation(&check.Result, "Configure backup storage (local directories, network mounts, or snapshots)")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/logical_volume_manager_administration/lvm_snapshots", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Backup system appears to be configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkRecoveryProcess tests recovery process readiness
func checkRecoveryProcess(r *report.AsciiDocReport) {
	checkID := "backup-recovery"
	checkName := "Recovery Process"
	checkDesc := "Validates recovery process documentation and testing."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Look for recovery documentation
	recoveryDocsCmd := "find /root /home /etc /usr/local/etc /opt -name '*recover*' -o -name '*restore*' -o -name '*dr*' 2>/dev/null | grep -v '.o$\\|.so || echo 'No recovery documentation found'"
	recoveryDocsOutput, _ := utils.RunCommand("bash", "-c", recoveryDocsCmd)

	// Check for recovery scripts
	recoveryScriptsCmd := "find /root /home /etc /usr/local/bin /opt -name '*.sh' -type f -exec grep -l 'recover\\|restore' {} \\; 2>/dev/null || echo 'No recovery scripts found'"
	recoveryScriptsOutput, _ := utils.RunCommand("bash", "-c", recoveryScriptsCmd)

	// Check for restore logs or evidence of recovery testing
	restoreLogsCmd := "find /var/log -name '*restore*' -o -name '*recover*' -o -name '*backup*' -type f 2>/dev/null || echo 'No recovery logs found'"
	restoreLogsOutput, _ := utils.RunCommand("bash", "-c", restoreLogsCmd)

	// Get the most recent backup/restore log if any exist
	var logContent string
	if !strings.Contains(restoreLogsOutput, "No recovery logs found") {
		logFiles := strings.Split(restoreLogsOutput, "\n")
		if len(logFiles) > 0 && logFiles[0] != "" {
			// Get the content of the first log file
			logContentCmd := fmt.Sprintf("tail -20 %s 2>/dev/null || echo 'Cannot read log file'", logFiles[0])
			logContent, _ = utils.RunCommand("bash", "-c", logContentCmd)
		}
	}

	var detail strings.Builder
	detail.WriteString("Recovery Documentation:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(recoveryDocsOutput, "No recovery documentation found") {
		detail.WriteString("No recovery documentation found\n")
	} else {
		detail.WriteString(recoveryDocsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Recovery Scripts:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(recoveryScriptsOutput, "No recovery scripts found") {
		detail.WriteString("No recovery scripts found\n")
	} else {
		detail.WriteString(recoveryScriptsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Restore/Recovery Logs:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(restoreLogsOutput, "No recovery logs found") {
		detail.WriteString("No recovery logs found\n")
	} else {
		detail.WriteString(restoreLogsOutput)
	}
	detail.WriteString("\n----\n")

	if logContent != "" {
		detail.WriteString("\nMost Recent Log Content (last 20 lines):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(logContent)
		detail.WriteString("\n----\n")
	}

	// Determine if recovery process is documented
	noRecoveryDocs := strings.Contains(recoveryDocsOutput, "No recovery documentation found")
	noRecoveryScripts := strings.Contains(recoveryScriptsOutput, "No recovery scripts found")
	noRestoreLogs := strings.Contains(restoreLogsOutput, "No recovery logs found")

	// Check if any restore logs are recent (within 90 days)
	hasRecentRestoreTest := false
	if !noRestoreLogs {
		restoreFiles := strings.Split(restoreLogsOutput, "\n")
		for _, file := range restoreFiles {
			if file == "" {
				continue
			}

			// Get file modification time
			fileStatCmd := fmt.Sprintf("stat -c '%%Y' %s 2>/dev/null || echo '0'", file)
			fileStatOutput, _ := utils.RunCommand("bash", "-c", fileStatCmd)

			// Convert to timestamp
			var timestamp int64
			fmt.Sscanf(strings.TrimSpace(fileStatOutput), "%d", &timestamp)

			if timestamp > 0 {
				modTime := time.Unix(timestamp, 0)
				ninetyDaysAgo := time.Now().AddDate(0, 0, -90)

				if modTime.After(ninetyDaysAgo) {
					hasRecentRestoreTest = true
					break
				}
			}
		}
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate recovery process
	if noRecoveryDocs && noRecoveryScripts {
		check.Result = report.NewResult(report.StatusWarning,
			"No recovery process documentation or scripts found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Create documentation for the system recovery process")
		report.AddRecommendation(&check.Result, "Develop and test recovery scripts")
		report.AddRecommendation(&check.Result, "Schedule regular recovery testing")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/system_design_guide/backup-and-recovery", rhelVersion))
	} else if noRestoreLogs || !hasRecentRestoreTest {
		check.Result = report.NewResult(report.StatusWarning,
			"No evidence of recent recovery testing found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Perform and document regular recovery testing")
		report.AddRecommendation(&check.Result, "Keep logs of recovery tests for verification")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/system_design_guide/backup-and-recovery", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Recovery process appears to be documented and tested",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkApplicationBackups validates application-level backups
func checkApplicationBackups(r *report.AsciiDocReport) {
	checkID := "backup-application"
	checkName := "Application Backups"
	checkDesc := "Validates application-level backups."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Detect installed applications that might need specialized backups
	applicationsCmd := "rpm -qa | grep -E '(mysql|mariadb|postgresql|oracle|db2|mongodb|tomcat|jboss|elasticsearch|jenkins|docker)' || echo 'No common applications detected'"
	applicationsOutput, _ := utils.RunCommand("bash", "-c", applicationsCmd)

	// Check for database backup configurations
	dbBackupCmd := "find /etc -path '*/mysql*/*' -o -path '*/pgsql*/*' -o -path '*/mongo*/*' -name '*backup*' 2>/dev/null || echo 'No database backup configurations found'"
	dbBackupOutput, _ := utils.RunCommand("bash", "-c", dbBackupCmd)

	// Check for database dump files
	dbDumpsCmd := "find / -path /proc -prune -o -path /sys -prune -o -path /dev -prune -o -name '*.sql' -o -name '*.dump' -o -name '*.bak' -type f -mtime -30 2>/dev/null | head -20 || echo 'No recent database dumps found'"
	dbDumpsOutput, _ := utils.RunCommand("bash", "-c", dbDumpsCmd)

	// Check for specific application backup tools
	appBackupToolsCmd := "which mysqldump pg_dump mongodump 2>/dev/null || echo 'No database backup tools found'"
	appBackupToolsOutput, _ := utils.RunCommand("bash", "-c", appBackupToolsCmd)

	var detail strings.Builder
	detail.WriteString("Detected Applications:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(applicationsOutput, "No common applications detected") {
		detail.WriteString("No common applications that require specialized backups detected\n")
	} else {
		detail.WriteString(applicationsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Database Backup Configurations:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(dbBackupOutput, "No database backup configurations found") {
		detail.WriteString("No database backup configurations found\n")
	} else {
		detail.WriteString(dbBackupOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Recent Database Dumps (last 30 days):\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(dbDumpsOutput, "No recent database dumps found") {
		detail.WriteString("No recent database dumps found\n")
	} else {
		detail.WriteString(dbDumpsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Application Backup Tools:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(appBackupToolsOutput, "No database backup tools found") {
		detail.WriteString("No database backup tools found\n")
	} else {
		detail.WriteString(appBackupToolsOutput)
	}
	detail.WriteString("\n----\n")

	// Identify apps that need backups
	appBackupNeeded := false
	hasAppSpecificBackup := false

	// List of critical apps that always need specialized backups
	criticalApps := []string{
		"mysql", "mariadb", "postgresql", "mongodb", "oracle", "db2",
	}

	for _, app := range criticalApps {
		if strings.Contains(applicationsOutput, app) {
			appBackupNeeded = true

			// Check if this app has a specific backup
			if (!strings.Contains(dbBackupOutput, "No database backup configurations found") &&
				strings.Contains(dbBackupOutput, app)) ||
				(!strings.Contains(dbDumpsOutput, "No recent database dumps found") &&
					strings.Contains(dbDumpsOutput, app)) ||
				(!strings.Contains(appBackupToolsOutput, "No database backup tools found") &&
					strings.Contains(appBackupToolsOutput, app+"dump")) {
				hasAppSpecificBackup = true
			}
		}
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate application backups
	if !appBackupNeeded {
		check.Result = report.NewResult(report.StatusInfo,
			"No applications requiring specialized backups detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Ensure system-level backups are in place")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/system_design_guide/backup-and-recovery", rhelVersion))
	} else if !hasAppSpecificBackup {
		check.Result = report.NewResult(report.StatusWarning,
			"Applications requiring specialized backups detected but no app-specific backups found",
			report.ResultKeyRecommended)

		// Make app-specific recommendations
		if strings.Contains(applicationsOutput, "mysql") || strings.Contains(applicationsOutput, "mariadb") {
			report.AddRecommendation(&check.Result, "Configure MySQL/MariaDB backups using mysqldump or other tools")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/deploying_mariadb_on_rhel/backing-up-and-restoring-mariadb", rhelVersion))
		}
		if strings.Contains(applicationsOutput, "postgresql") {
			report.AddRecommendation(&check.Result, "Configure PostgreSQL backups using pg_dump or other tools")
			report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_using_database_servers/assembly_configuring-postgreSQL-backup-and-restore_configuring-and-using-database-servers", rhelVersion))
		}
		if strings.Contains(applicationsOutput, "mongodb") {
			report.AddRecommendation(&check.Result, "Configure MongoDB backups using mongodump or other tools")
		}

		report.AddRecommendation(&check.Result, "Ensure application data is backed up consistently (e.g., database dumps)")
		report.AddRecommendation(&check.Result, "Set up application-specific backup schedules")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Application-specific backups appear to be configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
