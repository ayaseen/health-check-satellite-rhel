// pkg/checks/rhel/logs.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunLogsChecks performs log related checks
func RunLogsChecks(r *report.AsciiDocReport) {
	// Check system logs for critical errors
	checkSystemLogs(r)

	// Ensure log rotation and archiving are configured
	checkLogRotation(r)

	// Validate logging system (rsyslog or journald)
	checkLoggingSystem(r)
}

// checkSystemLogs checks system logs for critical errors
func checkSystemLogs(r *report.AsciiDocReport) {
	checkID := "logs-system-errors"
	checkName := "System Logs Check"
	checkDesc := "Checks system logs for critical errors."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check for critical errors in the system logs
	journalErrorsCmd := "journalctl -p 0..3 --since '1 day ago' | grep -v firewalld | grep -v 'duplicated line' | head -20"
	journalErrorsOutput, _ := utils.RunCommand("bash", "-c", journalErrorsCmd)

	// Check for kernel errors in dmesg
	dmesgErrorsCmd := "dmesg | grep -iE '(error|fail|warn|bug|oops|panic)' | head -20"
	dmesgErrorsOutput, _ := utils.RunCommand("bash", "-c", dmesgErrorsCmd)

	// Check for auth failures
	authFailuresCmd := "grep -i 'authentication failure' /var/log/secure /var/log/auth.log 2>/dev/null | tail -10"
	authFailuresOutput, _ := utils.RunCommand("bash", "-c", authFailuresCmd)

	var detail strings.Builder
	detail.WriteString("Recent Journal Errors (Priority 0-3):\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(journalErrorsOutput) == "" {
		detail.WriteString("No critical errors found in journal\n")
	} else {
		detail.WriteString(journalErrorsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Kernel Log Errors:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(dmesgErrorsOutput) == "" {
		detail.WriteString("No critical errors found in kernel logs\n")
	} else {
		detail.WriteString(dmesgErrorsOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Authentication Failures:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(authFailuresOutput) == "" {
		detail.WriteString("No recent authentication failures found\n")
	} else {
		detail.WriteString(authFailuresOutput)
	}
	detail.WriteString("\n----\n")

	// Count errors
	journalErrorCount := 0
	dmesgErrorCount := 0
	authFailureCount := 0

	if strings.TrimSpace(journalErrorsOutput) != "" {
		journalErrorCount = len(strings.Split(strings.TrimSpace(journalErrorsOutput), "\n"))
	}

	if strings.TrimSpace(dmesgErrorsOutput) != "" {
		dmesgErrorCount = len(strings.Split(strings.TrimSpace(dmesgErrorsOutput), "\n"))
	}

	if strings.TrimSpace(authFailuresOutput) != "" {
		authFailureCount = len(strings.Split(strings.TrimSpace(authFailuresOutput), "\n"))
	}

	totalErrors := journalErrorCount + dmesgErrorCount + authFailureCount

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	logsDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/logging_and_monitoring/", rhelVersion)

	// Evaluate log health
	if totalErrors > 50 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("Found %d critical errors in system logs", totalErrors),
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Review system logs carefully for potential system issues")
		report.AddRecommendation(&check.Result, "Check journal logs with 'journalctl -p 0..3'")
		report.AddRecommendation(&check.Result, "Check kernel messages with 'dmesg | grep -i error'")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sassembly_viewing-logs_logging-and-monitoring", logsDocURL))
	} else if totalErrors > 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d errors in system logs", totalErrors),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review system logs for potential issues")
		if journalErrorCount > 0 {
			report.AddRecommendation(&check.Result, "Review journal logs with 'journalctl -p 0..3'")
		}
		if dmesgErrorCount > 0 {
			report.AddRecommendation(&check.Result, "Review kernel messages with 'dmesg | grep -i error'")
		}
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sviewing-problems-with-journalctl_logging-and-monitoring", logsDocURL))
	} else if totalErrors > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d minor issues in system logs", totalErrors),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor system logs for recurring issues")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, logsDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No critical errors found in system logs",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkLogRotation ensures log rotation and archiving are configured
func checkLogRotation(r *report.AsciiDocReport) {
	checkID := "logs-rotation"
	checkName := "Log Rotation"
	checkDesc := "Ensures log rotation and archiving are configured."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check logrotate configuration
	logrotateConfCmd := "cat /etc/logrotate.conf"
	logrotateConfOutput, _ := utils.RunCommand("bash", "-c", logrotateConfCmd)

	// Check logrotate.d directory
	logrotatedCmd := "ls -l /etc/logrotate.d/"
	logrotatedOutput, _ := utils.RunCommand("bash", "-c", logrotatedCmd)

	// Check for large log files
	largeLogsCmd := "find /var/log -type f -size +100M -exec ls -lh {} \\; 2>/dev/null | sort -k5nr | head -5"
	largeLogsOutput, _ := utils.RunCommand("bash", "-c", largeLogsCmd)

	// Check logrotate status - improved to filter out normal debug messages that aren't errors
	// The original command was flagging informational "considering log" messages as errors
	logrotateStatusCmd := "logrotate -d /etc/logrotate.conf 2>&1 | grep -iE 'error|warning' | grep -v 'considering log'"
	logrotateStatusOutput, _ := utils.RunCommand("bash", "-c", logrotateStatusCmd)

	var detail strings.Builder
	detail.WriteString("Logrotate Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logrotateConfOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Logrotate.d Directory Contents:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logrotatedOutput)
	detail.WriteString("\n----\n\n")

	if strings.TrimSpace(largeLogsOutput) != "" {
		detail.WriteString("Large Log Files (>100MB):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(largeLogsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No log files larger than 100MB found\n\n")
	}

	// Check if we found actual errors in logrotate configuration
	if strings.TrimSpace(logrotateStatusOutput) != "" {
		detail.WriteString("Logrotate Configuration Errors:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(logrotateStatusOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No logrotate configuration errors detected\n\n")
	}

	// Check for basic logrotate configuration
	hasRotate := strings.Contains(logrotateConfOutput, "rotate")

	// Check for large log files
	hasLargeLogs := strings.TrimSpace(largeLogsOutput) != ""

	// Check for logrotate errors - this now only looks for actual errors
	hasLogrotateErrors := strings.TrimSpace(logrotateStatusOutput) != ""

	// Also check if compress option is enabled for better space utilization
	hasCompress := strings.Contains(logrotateConfOutput, "compress") &&
		!strings.Contains(logrotateConfOutput, "#compress")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	logsDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/logging_and_monitoring/", rhelVersion)

	// Evaluate log rotation
	issues := []string{}

	if !hasRotate {
		issues = append(issues, "Logrotate configuration may be missing or incomplete")
	}

	if hasLargeLogs {
		issues = append(issues, "Large log files detected (>100MB)")
	}

	if hasLogrotateErrors {
		issues = append(issues, "Errors found in logrotate configuration")
	}

	if !hasCompress {
		issues = append(issues, "Log compression not enabled (consider enabling for better space utilization)")
	}

	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d log rotation issues", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Review logrotate configuration in /etc/logrotate.conf and /etc/logrotate.d/")
		report.AddRecommendation(&check.Result, "Test logrotate configuration with 'logrotate -d /etc/logrotate.conf'")

		if !hasCompress {
			report.AddRecommendation(&check.Result, "Enable compression by uncommenting the 'compress' line in /etc/logrotate.conf")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sassembly_managing-logs_logging-and-monitoring", logsDocURL))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Log rotation is properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkLoggingSystem validates logging system (rsyslog or journald)
// This function now focuses on local logging system configuration
// rather than remote/centralized logging which is handled by monitoring.go
func checkLoggingSystem(r *report.AsciiDocReport) {
	checkID := "logs-system"
	checkName := "Logging System"
	checkDesc := "Validates local logging system configuration (rsyslog or journald)."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check if rsyslog is installed and running
	rsyslogStatusCmd := "systemctl status rsyslog 2>/dev/null | grep 'Active:'"
	rsyslogStatusOutput, _ := utils.RunCommand("bash", "-c", rsyslogStatusCmd)
	rsyslogActive := strings.Contains(rsyslogStatusOutput, "active (running)")

	// Check journald status
	journaldStatusCmd := "systemctl status systemd-journald 2>/dev/null | grep 'Active:'"
	journaldStatusOutput, _ := utils.RunCommand("bash", "-c", journaldStatusCmd)
	journaldActive := strings.Contains(journaldStatusOutput, "active (running)")

	// Check rsyslog configuration
	rsyslogConfCmd := "cat /etc/rsyslog.conf 2>/dev/null | grep -v '^#'"
	rsyslogConfOutput, _ := utils.RunCommand("bash", "-c", rsyslogConfCmd)

	// Check journald configuration
	journaldConfCmd := "cat /etc/systemd/journald.conf 2>/dev/null | grep -v '^#'"
	journaldConfOutput, _ := utils.RunCommand("bash", "-c", journaldConfCmd)

	// Check journal disk usage
	journalDiskCmd := "journalctl --disk-usage 2>/dev/null"
	journalDiskOutput, _ := utils.RunCommand("bash", "-c", journalDiskCmd)

	// Check log destinations in rsyslog.conf
	logDestinationsCmd := "grep -r -E '/var/log/' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#' | head -10"
	logDestinationsOutput, _ := utils.RunCommand("bash", "-c", logDestinationsCmd)

	// Check syslog facilities configured
	syslogFacilitiesCmd := "grep -E '\\.(info|notice|warn|err|crit|emerg);' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null | grep -v '^#' | head -10"
	syslogFacilitiesOutput, _ := utils.RunCommand("bash", "-c", syslogFacilitiesCmd)

	// Check for external/remote logging configuration
	remoteLoggingCmd := "grep -r '[[:space:]]*@[^[:space:]]\\|[[:space:]]*@@[^[:space:]]\\|target=\\|action.Target=\\|action=\"omfwd\"' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo 'No remote logging configured in rsyslog'"
	remoteLoggingOutput, _ := utils.RunCommand("bash", "-c", remoteLoggingCmd)
	hasRemoteLogging := !strings.Contains(remoteLoggingOutput, "No remote logging configured")

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("Rsyslog Service Active: %v\n\n", rsyslogActive))
	detail.WriteString(fmt.Sprintf("Journald Service Active: %v\n\n", journaldActive))

	detail.WriteString("\nRsyslog Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(rsyslogConfOutput) != "" {
		detail.WriteString(rsyslogConfOutput)
	} else {
		detail.WriteString("Rsyslog configuration not found or empty\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Journald Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(journaldConfOutput) != "" {
		detail.WriteString(journaldConfOutput)
	} else {
		detail.WriteString("Journald configuration not found or empty\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Journal Disk Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(journalDiskOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Configured Log Destinations:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(logDestinationsOutput) != "" {
		detail.WriteString(logDestinationsOutput)
	} else {
		detail.WriteString("No log destinations found in rsyslog configuration\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Configured Syslog Facilities:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.TrimSpace(syslogFacilitiesOutput) != "" {
		detail.WriteString(syslogFacilitiesOutput)
	} else {
		detail.WriteString("No syslog facilities found in rsyslog configuration\n")
	}
	detail.WriteString("\n----\n\n")

	// Add information about remote logging configuration
	detail.WriteString("Remote Logging Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasRemoteLogging {
		detail.WriteString(remoteLoggingOutput)
	} else {
		detail.WriteString("No remote logging configuration detected\n")
	}
	detail.WriteString("\n----\n")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	logsDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/logging_and_monitoring/", rhelVersion)

	// Check if at least one logging system is active
	if !rsyslogActive && !journaldActive {
		check.Result = report.NewResult(report.StatusWarning,
			"No logging service is active",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start at least one logging service: 'systemctl start rsyslog'")
		report.AddRecommendation(&check.Result, "Enable the service to start at boot: 'systemctl enable rsyslog'")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sconfiguring-and-managing-logging_logging-and-monitoring", logsDocURL))
	} else {
		loggingIssues := []string{}

		// Parse journal disk usage to get a numeric value
		journalSizeInMB := 0
		if strings.Contains(journalDiskOutput, "M") {
			// Extract the number before "M"
			parts := strings.Split(journalDiskOutput, "M")
			if len(parts) > 0 {
				sizeStr := strings.TrimSpace(strings.Split(parts[0], " ")[len(strings.Split(parts[0], " "))-1])
				if size, err := strconv.ParseFloat(sizeStr, 64); err == nil {
					journalSizeInMB = int(size)
				}
			}
		} else if strings.Contains(journalDiskOutput, "G") {
			// Convert GB to MB
			parts := strings.Split(journalDiskOutput, "G")
			if len(parts) > 0 {
				sizeStr := strings.TrimSpace(strings.Split(parts[0], " ")[len(strings.Split(parts[0], " "))-1])
				if size, err := strconv.ParseFloat(sizeStr, 64); err == nil {
					journalSizeInMB = int(size * 1024)
				}
			}
		}

		// Check if journal is too large
		if journalSizeInMB > 1024 { // More than 1GB
			loggingIssues = append(loggingIssues, fmt.Sprintf("Journal is using significant disk space (%d MB)", journalSizeInMB))
		}

		// Check for SystemMaxUse value in journald.conf
		if !strings.Contains(journaldConfOutput, "SystemMaxUse") && !hasRemoteLogging {
			loggingIssues = append(loggingIssues, "Journal size limit not configured (SystemMaxUse) and no remote logging configured")
		} else if !strings.Contains(journaldConfOutput, "SystemMaxUse") && hasRemoteLogging {
			// No warning needed as logs are being forwarded externally
		}

		// Check if essential log destinations are configured in rsyslog
		if !strings.Contains(logDestinationsOutput, "/var/log/messages") &&
			!strings.Contains(logDestinationsOutput, "/var/log/syslog") {
			loggingIssues = append(loggingIssues, "Standard system log file destination not configured")
		}

		// Check if secure log is configured
		if !strings.Contains(logDestinationsOutput, "/var/log/secure") &&
			!strings.Contains(logDestinationsOutput, "/var/log/auth.log") {
			loggingIssues = append(loggingIssues, "Security log file destination not configured")
		}

		if len(loggingIssues) > 0 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Found %d local logging system issues", len(loggingIssues)),
				report.ResultKeyRecommended)

			for _, issue := range loggingIssues {
				report.AddRecommendation(&check.Result, issue)
			}

			if journalSizeInMB > 1024 && !strings.Contains(journaldConfOutput, "SystemMaxUse") {
				report.AddRecommendation(&check.Result, "Configure journal size limit in /etc/systemd/journald.conf")
				report.AddRecommendation(&check.Result, "Add 'SystemMaxUse=1G' to limit journal size")
			}

			// Add reference link directly
			report.AddReferenceLink(&check.Result, fmt.Sprintf("%sassembly_working-with-systemd-journal_logging-and-monitoring", logsDocURL))
		} else {
			var status string
			if rsyslogActive && journaldActive {
				if hasRemoteLogging {
					status = "Both rsyslog and journald are active with remote logging configured"
				} else {
					status = "Both rsyslog and journald are active and properly configured"
				}
			} else if rsyslogActive {
				if hasRemoteLogging {
					status = "Rsyslog is active with remote logging configured"
				} else {
					status = "Rsyslog is active and properly configured"
				}
			} else {
				status = "Journald is active and properly configured"
			}

			check.Result = report.NewResult(report.StatusOK,
				status,
				report.ResultKeyNoChange)
		}
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
