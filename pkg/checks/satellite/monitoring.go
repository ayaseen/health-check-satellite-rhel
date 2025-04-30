// pkg/checks/satellite/monitoring.go

package satellite

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunMonitoringChecks performs Satellite monitoring checks
func RunMonitoringChecks(r *report.AsciiDocReport) {
	// Check logging configuration
	checkLoggingConfiguration(r)

	// Check for centralized log collection
	checkCentralizedLogging(r)

	// Check for error patterns in logs
	checkLogErrorPatterns(r)
}

// RunMonitoringIntegrationChecks performs Satellite monitoring integration checks
func RunMonitoringIntegrationChecks(r *report.AsciiDocReport) {
	// Check monitoring integration (Prometheus, etc.)
	checkMonitoringIntegration(r)

	// Check alerting configuration
	checkAlertingConfiguration(r)
}

// checkLoggingConfiguration checks Satellite's logging settings
func checkLoggingConfiguration(r *report.AsciiDocReport) {
	checkID := "satellite-logging-config"
	checkName := "Logging Configuration"
	checkDesc := "Checks Satellite's logging configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check Satellite log settings
	logSettingsCmd := "hammer settings list --search 'name ~ log'"
	logSettingsOutput, err := utils.RunCommand("bash", "-c", logSettingsCmd)

	var detail strings.Builder
	detail.WriteString("Logging Configuration Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving logging settings:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))
	} else {
		detail.WriteString("Satellite Logging Settings:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(logSettingsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check log levels
	logLevelCmd := "grep -r 'log_level\\|logging:' /etc/foreman/ /etc/foreman-proxy/ /etc/httpd/conf.d/ 2>/dev/null"
	logLevelOutput, _ := utils.RunCommand("bash", "-c", logLevelCmd)

	detail.WriteString("Log Level Configuration:\n\n")
	if logLevelOutput == "" {
		detail.WriteString("No specific log level configuration found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(logLevelOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check log file existence and permissions
	logFilesCmd := "find /var/log/foreman /var/log/httpd /var/log/candlepin -type f -name '*.log' | xargs ls -la 2>/dev/null"
	logFilesOutput, _ := utils.RunCommand("bash", "-c", logFilesCmd)

	detail.WriteString("Log Files:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logFilesOutput)
	detail.WriteString("\n----\n\n")

	// Check log rotation configuration - Improved to detect more rotation evidence
	logrotateCmd := "grep -r foreman /etc/logrotate.d/ 2>/dev/null || echo 'No configuration found'"
	logrotateOutput, _ := utils.RunCommand("bash", "-c", logrotateCmd)

	detail.WriteString("Log Rotation Configuration:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(logrotateOutput)
	detail.WriteString("\n----\n\n")

	// Also check for actual rotated log files as evidence of rotation
	rotatedLogsCmd := "ls -la /var/log/foreman/*-2* 2>/dev/null || echo 'No rotated logs found'"
	rotatedLogsOutput, _ := utils.RunCommand("bash", "-c", rotatedLogsCmd)

	detail.WriteString("Evidence of Log Rotation:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rotatedLogsOutput)
	detail.WriteString("\n----\n\n")

	// Check log storage capacity
	logStorageCmd := "df -h /var/log"
	logStorageOutput, _ := utils.RunCommand("bash", "-c", logStorageCmd)

	detail.WriteString("Log Storage Capacity:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logStorageOutput)
	detail.WriteString("\n----\n\n")

	// Check log file growth
	logSizeCmd := "find /var/log/foreman -name '*.log' -type f -exec du -h {} \\; | sort -hr | head -5"
	logSizeOutput, _ := utils.RunCommand("bash", "-c", logSizeCmd)

	detail.WriteString("Largest Log Files:\n\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logSizeOutput)
	detail.WriteString("\n----\n\n")

	// Extract log level configuration
	productionLogLevel := "unknown"
	logLevelFound := false

	if strings.Contains(logLevelOutput, "log_level") {
		re := regexp.MustCompile(`log_level\s*[:=]\s*(\w+)`)
		match := re.FindStringSubmatch(logLevelOutput)
		if len(match) > 1 {
			productionLogLevel = match[1]
			logLevelFound = true
		}
	}

	// Extract log rotation period by checking both configuration and evidence
	rotationPeriod := "unknown"
	rotationConfigFound := false

	// First check in logrotate config
	if strings.Contains(logrotateOutput, "rotate") {
		re := regexp.MustCompile(`rotate\s+(\d+)`)
		match := re.FindStringSubmatch(logrotateOutput)
		if len(match) > 1 {
			rotationPeriod = match[1]
			rotationConfigFound = true
		}
	}

	// If not found in config, check for presence of rotated logs
	if !rotationConfigFound && !strings.Contains(rotatedLogsOutput, "No rotated logs found") {
		rotationConfigFound = true
		// If we find rotated logs but couldn't determine period, set to "Enabled (period unknown)"
		rotationPeriod = "Enabled (period unknown)"
	}

	// Extract log storage space
	logSpaceAvailable := "Unknown"
	if len(logStorageOutput) > 0 {
		lines := strings.Split(logStorageOutput, "\n")
		if len(lines) > 1 {
			fields := strings.Fields(lines[1])
			if len(fields) > 3 {
				logSpaceAvailable = fields[3]
			}
		}
	}

	// Create a summary table
	detail.WriteString("Logging Configuration Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Setting|Value\n")

	if logLevelFound {
		detail.WriteString(fmt.Sprintf("|Production Log Level|%s\n", productionLogLevel))
	} else {
		detail.WriteString("|Production Log Level|Not found\n")
	}

	if rotationConfigFound {
		detail.WriteString(fmt.Sprintf("|Log Rotation Period|%s\n", rotationPeriod))
	} else {
		detail.WriteString("|Log Rotation Period|Not found\n")
	}

	detail.WriteString(fmt.Sprintf("|Log Storage Available|%s\n", logSpaceAvailable))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if !logLevelFound {
		check.Result = report.NewResult(report.StatusWarning,
			"Log level configuration not found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure appropriate log levels")
		report.AddRecommendation(&check.Result, "Set production.log level to info or warn for normal operation")
	} else if productionLogLevel == "debug" {
		check.Result = report.NewResult(report.StatusWarning,
			"Production log level set to debug",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Change log level from debug to info or warn")
		report.AddRecommendation(&check.Result, "Debug level generates excessive logs and can impact performance")
	} else if !rotationConfigFound {
		check.Result = report.NewResult(report.StatusWarning,
			"Log rotation configuration not found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure log rotation to prevent disk space issues")
	} else {
		// If numerical rotation period found, evaluate it
		rotationDays, err := strconv.Atoi(rotationPeriod)
		if err == nil && rotationDays < 7 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Log rotation period (%s days) may be too short", rotationPeriod),
				report.ResultKeyAdvisory)
			report.AddRecommendation(&check.Result, "Consider increasing log rotation period for better troubleshooting")
		} else if err == nil && rotationDays > 30 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("Log rotation period (%s days) may be too long", rotationPeriod),
				report.ResultKeyAdvisory)
			report.AddRecommendation(&check.Result, "Long rotation periods may lead to excessive disk usage")
		} else {
			check.Result = report.NewResult(report.StatusOK,
				"Logging configuration appears appropriate",
				report.ResultKeyNoChange)
		}
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/logging_and_reporting_problems_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkCentralizedLogging checks for centralized log collection
func checkCentralizedLogging(r *report.AsciiDocReport) {
	checkID := "satellite-centralized-logging"
	checkName := "Centralized Logging"
	checkDesc := "Checks for centralized log collection configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check for rsyslog forwarding configuration - specifically look for uncommented forwarding to external systems
	rsyslogCmd := "grep -v '^#' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -E '(@|target=|action.*type=.*omfwd)' || echo 'No external rsyslog forwarding found'"
	rsyslogOutput, _ := utils.RunCommand("bash", "-c", rsyslogCmd)

	var detail strings.Builder
	detail.WriteString("Centralized Logging Analysis:\n\n")

	detail.WriteString("Rsyslog Forwarding Configuration (uncommented):\n\n")
	if strings.Contains(rsyslogOutput, "No external rsyslog forwarding found") {
		detail.WriteString("No external rsyslog forwarding configuration found\n\n")

		// Also check for commented forwarding configurations
		commentedRsyslogCmd := "grep '^#' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null | grep -E '(@|target=|action.*type=.*omfwd)' || echo 'None'"
		commentedRsyslogOutput, _ := utils.RunCommand("bash", "-c", commentedRsyslogCmd)

		if strings.TrimSpace(commentedRsyslogOutput) != "None" {
			detail.WriteString("Commented Rsyslog Forwarding (disabled):\n\n")
			detail.WriteString("[source, text]\n----\n")
			detail.WriteString(commentedRsyslogOutput)
			detail.WriteString("\n----\n\n")
		}
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(rsyslogOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for log forwarding agents - external forwarding only
	agentsCmd := "ps -ef | grep -E 'filebeat|fluentd|logstash|splunk|fluentbit|td-agent|vector|promtail|logagent|nxlog' | grep -v grep || echo 'None'"
	agentsOutput, _ := utils.RunCommand("bash", "-c", agentsCmd)

	detail.WriteString("External Log Forwarding Agents:\n\n")
	if strings.TrimSpace(agentsOutput) == "None" {
		detail.WriteString("No external log forwarding agents detected\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(agentsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for agent configuration files
	configCmd := "find /etc -path '*/filebeat/*' -o -path '*/fluentd/*' -o -path '*/logstash/*' -o -name 'splunk*.conf' -o -path '*/td-agent/*' -o -path '*/vector/*' -o -path '*/promtail/*' -o -path '*/nxlog/*' 2>/dev/null || echo 'None'"
	configOutput, _ := utils.RunCommand("bash", "-c", configCmd)

	detail.WriteString("External Log Agent Configuration Files:\n\n")
	if strings.TrimSpace(configOutput) == "None" {
		detail.WriteString("No external log agent configuration files found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(configOutput)
		detail.WriteString("\n----\n\n")

		// Get contents of found config files to check for external forwarding targets
		if strings.TrimSpace(configOutput) != "None" {
			// Sample the first config file
			configFiles := strings.Split(configOutput, "\n")
			if len(configFiles) > 0 && strings.TrimSpace(configFiles[0]) != "None" {
				sampleConfigCmd := fmt.Sprintf("grep -E '(output|host|destination|target|syslog|address|url)' %s 2>/dev/null | grep -v '127.0.0.1\\|localhost' | head -10 || echo 'None'", configFiles[0])
				sampleConfigOutput, _ := utils.RunCommand("bash", "-c", sampleConfigCmd)

				if strings.TrimSpace(sampleConfigOutput) != "None" {
					detail.WriteString("Sample External Configuration Targets:\n\n")
					detail.WriteString("[source, text]\n----\n")
					detail.WriteString(sampleConfigOutput)
					detail.WriteString("\n----\n\n")
				}
			}
		}
	}

	// Check systemd journal forwarding settings
	journalCmd := "grep -r 'ForwardTo' /etc/systemd/journald.conf* 2>/dev/null || echo 'None'"
	journalOutput, _ := utils.RunCommand("bash", "-c", journalCmd)

	detail.WriteString("Systemd Journal Forwarding:\n\n")
	if strings.TrimSpace(journalOutput) == "None" {
		detail.WriteString("No journal forwarding configuration found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(journalOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for network connections to external logging destinations (exclude localhost connections)
	loggingPortsCmd := "ss -tunap | grep -E ':(514|601|6514|5140|5170|9200|9300|5044|5170|24224|24220|10514|1468)' | grep -v '127.0.0.1\\|localhost' || echo 'None'"
	loggingPortsOutput, _ := utils.RunCommand("bash", "-c", loggingPortsCmd)

	detail.WriteString("External Logging Connections:\n\n")
	if strings.TrimSpace(loggingPortsOutput) == "None" {
		detail.WriteString("No connections to external logging systems detected\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(loggingPortsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check installed logging packages
	logPackagesCmd := "rpm -qa | grep -E 'filebeat|fluentd|logstash|splunk|td-agent|fluentbit|vector|promtail|logagent|nxlog|rsyslog' || echo 'None'"
	logPackagesOutput, _ := utils.RunCommand("bash", "-c", logPackagesCmd)

	detail.WriteString("Installed Logging Packages:\n\n")
	if strings.TrimSpace(logPackagesOutput) == "None" {
		detail.WriteString("No logging packages detected\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(logPackagesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for outbound connections from logging processes to non-localhost destinations
	outboundCmd := "ss -pant | grep -E '(rsyslog|syslog-ng|filebeat|fluentd|logstash|splunk|td-agent|fluentbit|vector|promtail|logagent|nxlog)' | grep -v '127.0.0.1\\|localhost' || echo 'None'"
	outboundOutput, _ := utils.RunCommand("bash", "-c", outboundCmd)

	if strings.TrimSpace(outboundOutput) != "None" {
		detail.WriteString("Outbound External Connections from Logging Processes:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(outboundOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No outbound external connections from logging processes detected\n\n")
	}

	// Determine if centralized logging is configured using multiple indicators
	// Focus on actual external logging, not local forwarding
	hasCentralizedLogging := false
	localLoggingOnly := false

	// Primary indicators - strong evidence of external centralized logging
	hasExternalRsyslogForwarding := !strings.Contains(rsyslogOutput, "No external rsyslog forwarding found")
	hasExternalLogAgents := strings.TrimSpace(agentsOutput) != "None"
	hasExternalAgentConfigs := strings.TrimSpace(configOutput) != "None"
	hasExternalLoggingConnections := strings.TrimSpace(loggingPortsOutput) != "None"
	hasExternalOutboundConnections := strings.TrimSpace(outboundOutput) != "None"

	// Check for journal forwarding to syslog (local forwarding)
	hasJournalForwardingSyslog := strings.Contains(journalOutput, "ForwardToSyslog=yes")

	// Determine if only local logging is configured
	if !hasExternalRsyslogForwarding &&
		!hasExternalLogAgents &&
		!hasExternalAgentConfigs &&
		!hasExternalLoggingConnections &&
		!hasExternalOutboundConnections {
		// Only local logging setup detected
		if hasJournalForwardingSyslog {
			localLoggingOnly = true
		}
	}

	// Determine if external centralized logging is configured
	if hasExternalRsyslogForwarding ||
		hasExternalLogAgents ||
		hasExternalAgentConfigs ||
		hasExternalLoggingConnections ||
		hasExternalOutboundConnections {
		hasCentralizedLogging = true
	}

	// Identify the specific logging solution in use
	var loggingSolution string

	if hasExternalRsyslogForwarding {
		loggingSolution = "Rsyslog forwarding to external system"
	} else if strings.Contains(strings.ToLower(agentsOutput), "filebeat") ||
		strings.Contains(strings.ToLower(configOutput), "filebeat") {
		loggingSolution = "Filebeat to external system"
	} else if strings.Contains(strings.ToLower(agentsOutput), "fluentd") ||
		strings.Contains(strings.ToLower(configOutput), "fluentd") ||
		strings.Contains(strings.ToLower(agentsOutput), "td-agent") {
		loggingSolution = "Fluentd/td-agent to external system"
	} else if strings.Contains(strings.ToLower(agentsOutput), "splunk") ||
		strings.Contains(strings.ToLower(configOutput), "splunk") {
		loggingSolution = "Splunk Forwarder to external system"
	} else if hasExternalLoggingConnections || hasExternalOutboundConnections {
		loggingSolution = "Network-based log forwarding to external system"
	} else if localLoggingOnly {
		loggingSolution = "Local logging only (journald to rsyslog)"
	} else {
		loggingSolution = "No centralized logging detected"
	}

	// Create a summary table
	detail.WriteString("Centralized Logging Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Component|Status\n")
	detail.WriteString(fmt.Sprintf("|External Rsyslog Forwarding|%s\n", boolToYesNo(hasExternalRsyslogForwarding)))
	detail.WriteString(fmt.Sprintf("|External Log Forwarding Agents|%s\n", boolToYesNo(hasExternalLogAgents)))
	detail.WriteString(fmt.Sprintf("|External Agent Configuration Files|%s\n", boolToYesNo(hasExternalAgentConfigs)))
	detail.WriteString(fmt.Sprintf("|Journal to Syslog Forwarding|%s\n", boolToYesNo(hasJournalForwardingSyslog)))
	detail.WriteString(fmt.Sprintf("|External Logging Connections|%s\n", boolToYesNo(hasExternalLoggingConnections || hasExternalOutboundConnections)))
	detail.WriteString(fmt.Sprintf("|External Centralized Logging|%s\n", boolToYesNo(hasCentralizedLogging)))
	detail.WriteString(fmt.Sprintf("|Logging Configuration|%s\n", loggingSolution))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if !hasCentralizedLogging && !localLoggingOnly {
		check.Result = report.NewResult(report.StatusWarning,
			"No logging configuration detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure local logging at minimum")
		report.AddRecommendation(&check.Result, "Consider setting up centralized log collection")
		report.AddRecommendation(&check.Result, "Reference: https://access.redhat.com/solutions/3006821 - Implementing centralized logging for Satellite")
	} else if !hasCentralizedLogging && localLoggingOnly {
		check.Result = report.NewResult(report.StatusWarning,
			"Only local logging configured (no external centralized logging)",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider implementing external centralized logging")
		report.AddRecommendation(&check.Result, "Configure rsyslog forwarding or use a dedicated logging agent")
		report.AddRecommendation(&check.Result, "Centralized logging helps with troubleshooting across systems and compliance")
	} else if hasCentralizedLogging {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("External centralized logging configured via %s", loggingSolution),
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Logging configuration status could not be determined",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify logging configuration manually")
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/logging_and_reporting_problems_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/3006821")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkLogErrorPatterns checks for error patterns in logs
func checkLogErrorPatterns(r *report.AsciiDocReport) {
	checkID := "satellite-log-errors"
	checkName := "Log Error Patterns"
	checkDesc := "Checks for error patterns in Satellite logs."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check for pattern counts rather than showing full errors
	foremanCountCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/foreman/production.log | wc -l || echo '0'"
	foremanCountOutput, _ := utils.RunCommand("bash", "-c", foremanCountCmd)
	foremanErrorCount := strings.TrimSpace(foremanCountOutput)

	// Get only the most recent errors - limited to 10 lines
	foremanCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/foreman/production.log | tail -10"
	foremanOutput, _ := utils.RunCommand("bash", "-c", foremanCmd)

	var detail strings.Builder
	detail.WriteString("Log Error Pattern Analysis:\n\n")

	// Show error count and just a sample of recent errors
	detail.WriteString("Foreman Production Log Errors:\n\n")
	detail.WriteString(fmt.Sprintf("Total errors found: %s\n\n", foremanErrorCount))
	detail.WriteString("Recent error samples (last 10):\n\n")

	if foremanOutput == "" {
		detail.WriteString("No significant errors found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(foremanOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for errors in Candlepin logs - count and limited sample
	candlepinCountCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/candlepin/candlepin.log 2>/dev/null | wc -l || echo '0'"
	candlepinCountOutput, _ := utils.RunCommand("bash", "-c", candlepinCountCmd)
	candlepinErrorCount := strings.TrimSpace(candlepinCountOutput)

	// Sample of recent errors - limited to 5 lines
	candlepinCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/candlepin/candlepin.log 2>/dev/null | tail -5"
	candlepinOutput, _ := utils.RunCommand("bash", "-c", candlepinCmd)

	detail.WriteString("Candlepin Log Errors:\n\n")
	detail.WriteString(fmt.Sprintf("Total errors found: %s\n\n", candlepinErrorCount))

	if candlepinOutput == "" {
		detail.WriteString("No significant errors found\n\n")
	} else {
		detail.WriteString("Recent error samples (last 5):\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(candlepinOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for errors in Pulp logs - count and limited sample
	pulpCountCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/pulp/pulp*.log 2>/dev/null | wc -l || echo '0'"
	pulpCountOutput, _ := utils.RunCommand("bash", "-c", pulpCountCmd)
	pulpErrorCount := strings.TrimSpace(pulpCountOutput)

	// Sample of recent errors - limited to 5 lines
	pulpCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/pulp/pulp*.log 2>/dev/null | tail -5"
	pulpOutput, _ := utils.RunCommand("bash", "-c", pulpCmd)

	detail.WriteString("Pulp Log Errors:\n\n")
	detail.WriteString(fmt.Sprintf("Total errors found: %s\n\n", pulpErrorCount))

	if pulpOutput == "" {
		detail.WriteString("No significant errors found\n\n")
	} else {
		detail.WriteString("Recent error samples (last 5):\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(pulpOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for errors in Apache logs - count and limited sample
	apacheCountCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/httpd/error_log 2>/dev/null | wc -l || echo '0'"
	apacheCountOutput, _ := utils.RunCommand("bash", "-c", apacheCountCmd)
	apacheErrorCount := strings.TrimSpace(apacheCountOutput)

	// Sample of recent errors - limited to 5 lines
	apacheCmd := "grep -i 'error\\|exception\\|failed\\|fatal' /var/log/httpd/error_log 2>/dev/null | tail -5"
	apacheOutput, _ := utils.RunCommand("bash", "-c", apacheCmd)

	detail.WriteString("Apache Error Log:\n\n")
	detail.WriteString(fmt.Sprintf("Total errors found: %s\n\n", apacheErrorCount))

	if apacheOutput == "" {
		detail.WriteString("No significant errors found\n\n")
	} else {
		detail.WriteString("Recent error samples (last 5):\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(apacheOutput)
		detail.WriteString("\n----\n\n")
	}

	// Count error occurrences by type - using regex patterns for more accuracy
	foremanErrors := countErrorsByTypePattern(foremanOutput)
	candlepinErrors := countErrorsByTypePattern(candlepinOutput)
	pulpErrors := countErrorsByTypePattern(pulpOutput)
	apacheErrors := countErrorsByTypePattern(apacheOutput)

	// Convert string counts to integers for better assessment
	foremanCount, _ := strconv.Atoi(foremanErrorCount)
	candlepinCount, _ := strconv.Atoi(candlepinErrorCount)
	pulpCount, _ := strconv.Atoi(pulpErrorCount)
	apacheCount, _ := strconv.Atoi(apacheErrorCount)

	// Create a summary table
	detail.WriteString("Error Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1,1,1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Component|Total Errors|Fatal/Critical|Exception|General Error\n")
	detail.WriteString(fmt.Sprintf("|Foreman Production|%d|%d|%d|%d\n",
		foremanCount, foremanErrors["fatal"], foremanErrors["exception"], foremanErrors["error"]))
	detail.WriteString(fmt.Sprintf("|Candlepin|%d|%d|%d|%d\n",
		candlepinCount, candlepinErrors["fatal"], candlepinErrors["exception"], candlepinErrors["error"]))
	detail.WriteString(fmt.Sprintf("|Pulp|%d|%d|%d|%d\n",
		pulpCount, pulpErrors["fatal"], pulpErrors["exception"], pulpErrors["error"]))
	detail.WriteString(fmt.Sprintf("|Apache|%d|%d|%d|%d\n",
		apacheCount, apacheErrors["fatal"], apacheErrors["exception"], apacheErrors["error"]))
	detail.WriteString("|===\n\n")

	// Calculate total critical errors
	totalFatal := foremanErrors["fatal"] + candlepinErrors["fatal"] + pulpErrors["fatal"] + apacheErrors["fatal"]
	totalErrors := foremanCount + candlepinCount + pulpCount + apacheCount
	totalExceptions := foremanErrors["exception"] + candlepinErrors["exception"] + pulpErrors["exception"] + apacheErrors["exception"]

	// Evaluate results
	if totalFatal > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("Found %d fatal errors in logs", totalFatal),
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Investigate fatal errors immediately")
		report.AddRecommendation(&check.Result, "Check application and service status")
	} else if totalExceptions > 10 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found high number of exceptions (%d) in logs", totalExceptions),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate recurring exceptions")
		report.AddRecommendation(&check.Result, "Consider service restarts if appropriate")
	} else if totalErrors > 50 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found high number of errors (%d) in logs", totalErrors),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review error logs and address recurring issues")
	} else if totalErrors > 0 || totalExceptions > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d errors and %d exceptions in logs", totalErrors, totalExceptions),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor logs for increasing error rates")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No significant error patterns detected in logs",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/logging_and_reporting_problems_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// countErrorsByTypePattern counts the occurrences of different error types in log output using regex
func countErrorsByTypePattern(logOutput string) map[string]int {
	result := map[string]int{
		"error":     0,
		"exception": 0,
		"failed":    0,
		"fatal":     0,
	}

	fatalRegex := regexp.MustCompile(`(?i)(fatal|critical|emergency|alert|crit)`)
	exceptionRegex := regexp.MustCompile(`(?i)(exception|stack trace|java\.lang|traceback|segfault)`)
	errorRegex := regexp.MustCompile(`(?i)(error|err:)`)
	failedRegex := regexp.MustCompile(`(?i)(failed|failure|fail:)`)

	for _, line := range strings.Split(logOutput, "\n") {
		if line == "" {
			continue
		}

		if fatalRegex.MatchString(line) {
			result["fatal"]++
		} else if exceptionRegex.MatchString(line) {
			result["exception"]++
		} else if errorRegex.MatchString(line) {
			result["error"]++
		} else if failedRegex.MatchString(line) {
			result["failed"]++
		}
	}

	return result
}

// formatErrorCounts formats error counts for display
func formatErrorCounts(counts map[string]int) string {
	parts := []string{}

	if counts["fatal"] > 0 {
		parts = append(parts, fmt.Sprintf("%d fatal", counts["fatal"]))
	}

	if counts["exception"] > 0 {
		parts = append(parts, fmt.Sprintf("%d exceptions", counts["exception"]))
	}

	if counts["error"] > 0 {
		parts = append(parts, fmt.Sprintf("%d errors", counts["error"]))
	}

	if counts["failed"] > 0 {
		parts = append(parts, fmt.Sprintf("%d failures", counts["failed"]))
	}

	if len(parts) == 0 {
		return "None"
	}

	return strings.Join(parts, ", ")
}

// checkMonitoringIntegration checks monitoring integration (Prometheus, etc.)
func checkMonitoringIntegration(r *report.AsciiDocReport) {
	checkID := "satellite-monitoring-integration"
	checkName := "Monitoring Integration"
	checkDesc := "Checks Satellite metrics and monitoring integration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check for Prometheus integration
	prometheusCmd := "grep -r 'metrics\\|prometheus\\|telemetry' /etc/foreman/ /etc/foreman-proxy/ 2>/dev/null"
	prometheusOutput, _ := utils.RunCommand("bash", "-c", prometheusCmd)

	var detail strings.Builder
	detail.WriteString("Monitoring Integration Analysis:\n\n")

	detail.WriteString("Prometheus Integration Configuration:\n\n")
	if prometheusOutput == "" {
		detail.WriteString("No Prometheus configuration found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(prometheusOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for node_exporter
	nodeExporterCmd := "systemctl status node_exporter || ps -ef | grep node_exporter | grep -v grep"
	nodeExporterOutput, _ := utils.RunCommand("bash", "-c", nodeExporterCmd)

	detail.WriteString("Node Exporter Status:\n\n")
	if nodeExporterOutput == "" {
		detail.WriteString("Node exporter not detected\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(nodeExporterOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for Grafana
	grafanaCmd := "systemctl status grafana-server || ps -ef | grep grafana | grep -v grep"
	grafanaOutput, _ := utils.RunCommand("bash", "-c", grafanaCmd)

	detail.WriteString("Grafana Status:\n\n")
	if grafanaOutput == "" {
		detail.WriteString("Grafana not detected\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(grafanaOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check Telemetry settings in Satellite
	telemetryCmd := "hammer settings list --search 'name ~ telemetry'"
	telemetryOutput, _ := utils.RunCommand("bash", "-c", telemetryCmd)

	detail.WriteString("Satellite Telemetry Settings:\n\n")
	if telemetryOutput == "" {
		detail.WriteString("No telemetry settings found\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(telemetryOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for monitoring packages
	monitoringPkgsCmd := "rpm -qa | grep -E 'prometheus|grafana|zabbix|nagios|check_mk'"
	monitoringPkgsOutput, _ := utils.RunCommand("bash", "-c", monitoringPkgsCmd)

	detail.WriteString("Monitoring Packages:\n\n")
	if monitoringPkgsOutput == "" {
		detail.WriteString("No monitoring packages found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(monitoringPkgsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for monitoring agent configuration
	agentConfigCmd := "find /etc -name 'prometheus*.yml' -o -name 'zabbix_agent*.conf' -o -name 'nagios*.cfg' 2>/dev/null"
	agentConfigOutput, _ := utils.RunCommand("bash", "-c", agentConfigCmd)

	detail.WriteString("Monitoring Agent Configuration Files:\n\n")
	if agentConfigOutput == "" {
		detail.WriteString("No monitoring agent configuration files found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(agentConfigOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check host count with Insights
	insightsHostsCmd := "hammer host list --search 'has_has_insights = true' --per-page 1 | grep Total || echo 'No hosts with Insights'"
	insightsHostsOutput, _ := utils.RunCommand("bash", "-c", insightsHostsCmd)

	detail.WriteString("Hosts with Insights:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(insightsHostsOutput)
	detail.WriteString("\n----\n\n")

	// Determine Insights status
	hasMonitoring := prometheusOutput != "" ||
		nodeExporterOutput != "" ||
		grafanaOutput != "" ||
		strings.Contains(telemetryOutput, "true") ||
		monitoringPkgsOutput != "" ||
		agentConfigOutput != ""

	// Create a summary table
	detail.WriteString("Monitoring Integration Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Component|Status\n")
	detail.WriteString(fmt.Sprintf("|Prometheus Integration|%s\n", boolToYesNo(prometheusOutput != "")))
	detail.WriteString(fmt.Sprintf("|Node Exporter|%s\n", boolToYesNo(nodeExporterOutput != "")))
	detail.WriteString(fmt.Sprintf("|Grafana|%s\n", boolToYesNo(grafanaOutput != "")))
	detail.WriteString(fmt.Sprintf("|Telemetry Settings|%s\n", boolToYesNo(strings.Contains(telemetryOutput, "true"))))
	detail.WriteString(fmt.Sprintf("|Monitoring Packages|%s\n", boolToYesNo(monitoringPkgsOutput != "")))
	detail.WriteString(fmt.Sprintf("|Monitoring Configuration|%s\n", boolToYesNo(agentConfigOutput != "")))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if !hasMonitoring {
		check.Result = report.NewResult(report.StatusWarning,
			"No monitoring integration detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Implement monitoring integration for Satellite")
		report.AddRecommendation(&check.Result, "Consider Prometheus/Grafana or other monitoring solutions")
		report.AddRecommendation(&check.Result, "Enable Satellite telemetry for better monitoring")
	} else if !strings.Contains(nodeExporterOutput, "active (running)") && nodeExporterOutput != "" {
		check.Result = report.NewResult(report.StatusWarning,
			"Node exporter is installed but may not be running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start and enable node_exporter service")
		report.AddRecommendation(&check.Result, "Run: systemctl start node_exporter && systemctl enable node_exporter")
	} else if hasMonitoring {
		check.Result = report.NewResult(report.StatusOK,
			"Monitoring integration detected",
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Monitoring status could not be determined",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify monitoring integration manually")
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/monitoring_resources_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkAlertingConfiguration checks alerting configuration
func checkAlertingConfiguration(r *report.AsciiDocReport) {
	checkID := "satellite-alerting"
	checkName := "Alerting Configuration"
	checkDesc := "Checks for alerting configuration for Satellite."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check for various alerting configurations - not limited to Prometheus
	alertingCmd := "find /etc -path '*/alert*' -o -name '*alert*.yml' -o -name '*alert*.rules' -o -name '*alert*.conf' -o -path '*/nagios*/conf.d' -o -path '*/zabbix*/alert*' -o -path '*/zabbix*/trigger*' -o -path '*/icinga*/conf.d' 2>/dev/null || echo 'None'"
	alertingOutput, _ := utils.RunCommand("bash", "-c", alertingCmd)

	var detail strings.Builder
	detail.WriteString("Alerting Configuration Analysis:\n\n")

	detail.WriteString("Alert Configuration Files:\n\n")
	if strings.TrimSpace(alertingOutput) == "" || strings.TrimSpace(alertingOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(alertingOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for any alerting services - expanded beyond just alertmanager
	alertServicesCmd := "systemctl list-units --type=service | grep -E '(alert|nagios|zabbix|icinga|grafana|prometheus|monit|sensu|graylog)' | grep -v grep || echo 'None'"
	alertServicesOutput, _ := utils.RunCommand("bash", "-c", alertServicesCmd)

	detail.WriteString("Alerting Services Status:\n\n")
	if strings.TrimSpace(alertServicesOutput) == "" || strings.TrimSpace(alertServicesOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(alertServicesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for any running alerting processes regardless of service status
	alertProcessesCmd := "ps -ef | grep -E '(alertmanager|nagios|zabbix|icinga|grafana|prometheus|monit|sensu|graylog)' | grep -v grep || echo 'None'"
	alertProcessesOutput, _ := utils.RunCommand("bash", "-c", alertProcessesCmd)

	if strings.TrimSpace(alertProcessesOutput) != "None" {
		detail.WriteString("Alerting Processes Running:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(alertProcessesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for email notification configuration in any monitoring system
	emailCmd := "grep -r -l --include='*.conf' --include='*.yml' --include='*.yaml' --include='*.cfg' '(smtp|email|mail)' /etc 2>/dev/null | grep -E '(alert|monitoring|nagios|zabbix|icinga|grafana|prometheus|monit|sensu|graylog)' || echo 'None'"
	emailOutput, _ := utils.RunCommand("bash", "-c", emailCmd)

	detail.WriteString("Email Notification Configuration:\n\n")
	if strings.TrimSpace(emailOutput) == "" || strings.TrimSpace(emailOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(emailOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for other notification channels
	notificationCmd := "grep -r -l --include='*.conf' --include='*.yml' --include='*.yaml' --include='*.cfg' '(slack|webhook|pagerduty|opsgenie|teams|telegram|discord)' /etc 2>/dev/null | grep -E '(alert|monitoring|nagios|zabbix|icinga|grafana|prometheus|monit|sensu|graylog)' || echo 'None'"
	notificationOutput, _ := utils.RunCommand("bash", "-c", notificationCmd)

	detail.WriteString("Other Notification Channels:\n\n")
	if strings.TrimSpace(notificationOutput) == "" || strings.TrimSpace(notificationOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(notificationOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for specific Satellite-related alerting rules - broadened to look in more places
	rulesCmd := "find /etc -type f -exec grep -l '(satellite|foreman|candlepin|pulp|katello|httpd|pgsql|mongodb)' {} \\; 2>/dev/null | grep -E '(alert|monitoring|nagios|zabbix|icinga|grafana|prometheus|monit|sensu|graylog)' || echo 'None'"
	rulesOutput, _ := utils.RunCommand("bash", "-c", rulesCmd)

	detail.WriteString("Satellite-specific Alert Rules:\n\n")
	if strings.TrimSpace(rulesOutput) == "" || strings.TrimSpace(rulesOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(rulesOutput)
		detail.WriteString("\n----\n\n")

		// Get content of first rule file
		if strings.TrimSpace(rulesOutput) != "None" {
			firstRuleFile := strings.Split(rulesOutput, "\n")[0]
			if firstRuleFile != "" && firstRuleFile != "None" {
				firstRuleCmd := fmt.Sprintf("cat %s 2>/dev/null | head -20 || echo 'None'", firstRuleFile)
				firstRuleOutput, _ := utils.RunCommand("bash", "-c", firstRuleCmd)

				detail.WriteString("Sample Alert Rules Content:\n\n")
				if strings.TrimSpace(firstRuleOutput) == "" || strings.TrimSpace(firstRuleOutput) == "None" {
					detail.WriteString("None\n\n")
				} else {
					detail.WriteString("[source, yaml]\n----\n")
					detail.WriteString(firstRuleOutput)
					detail.WriteString("\n----\n\n")
				}
			}
		}
	}

	// Check for monitoring tools installed (broader check)
	monitoringToolsCmd := "rpm -qa | grep -E '(prometheus|alertmanager|nagios|zabbix|icinga|grafana|monit|sensu|graylog)' || echo 'None'"
	monitoringToolsOutput, _ := utils.RunCommand("bash", "-c", monitoringToolsCmd)

	detail.WriteString("Monitoring/Alerting Tools Installed:\n\n")
	if strings.TrimSpace(monitoringToolsOutput) == "" || strings.TrimSpace(monitoringToolsOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(monitoringToolsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for active listening ports related to monitoring/alerting
	monitoringPortsCmd := "ss -tlnp | grep -E ':(9090|9093|9100|3000|8080|9091|9094|5666|10050|10051|5667|8086)' || echo 'None'"
	monitoringPortsOutput, _ := utils.RunCommand("bash", "-c", monitoringPortsCmd)

	detail.WriteString("Monitoring/Alerting Ports in Use:\n\n")
	if strings.TrimSpace(monitoringPortsOutput) == "" || strings.TrimSpace(monitoringPortsOutput) == "None" {
		detail.WriteString("None\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(monitoringPortsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Determine alerting setup using a wider range of indicators
	hasAlertingConfig := strings.TrimSpace(alertingOutput) != "" && strings.TrimSpace(alertingOutput) != "None"
	hasAlertingServices := strings.TrimSpace(alertServicesOutput) != "" && strings.TrimSpace(alertServicesOutput) != "None"
	hasAlertingProcesses := strings.TrimSpace(alertProcessesOutput) != "" && strings.TrimSpace(alertProcessesOutput) != "None"
	hasEmailNotification := strings.TrimSpace(emailOutput) != "" && strings.TrimSpace(emailOutput) != "None"
	hasOtherNotification := strings.TrimSpace(notificationOutput) != "" && strings.TrimSpace(notificationOutput) != "None"
	hasSatelliteRules := strings.TrimSpace(rulesOutput) != "" && strings.TrimSpace(rulesOutput) != "None"
	hasMonitoringTools := strings.TrimSpace(monitoringToolsOutput) != "" && strings.TrimSpace(monitoringToolsOutput) != "None"
	hasMonitoringPorts := strings.TrimSpace(monitoringPortsOutput) != "" && strings.TrimSpace(monitoringPortsOutput) != "None"

	// Try to identify the alerting system being used
	alertingSystem := "None detected"
	if strings.Contains(strings.ToLower(monitoringToolsOutput), "prometheus") ||
		strings.Contains(strings.ToLower(alertServicesOutput), "prometheus") {
		alertingSystem = "Prometheus/Alertmanager"
	} else if strings.Contains(strings.ToLower(monitoringToolsOutput), "zabbix") ||
		strings.Contains(strings.ToLower(alertServicesOutput), "zabbix") {
		alertingSystem = "Zabbix"
	} else if strings.Contains(strings.ToLower(monitoringToolsOutput), "nagios") ||
		strings.Contains(strings.ToLower(alertServicesOutput), "nagios") {
		alertingSystem = "Nagios"
	} else if strings.Contains(strings.ToLower(monitoringToolsOutput), "icinga") ||
		strings.Contains(strings.ToLower(alertServicesOutput), "icinga") {
		alertingSystem = "Icinga"
	} else if strings.Contains(strings.ToLower(monitoringToolsOutput), "monit") ||
		strings.Contains(strings.ToLower(alertServicesOutput), "monit") {
		alertingSystem = "Monit"
	} else if strings.Contains(strings.ToLower(monitoringToolsOutput), "grafana") ||
		strings.Contains(strings.ToLower(alertServicesOutput), "grafana") {
		alertingSystem = "Grafana"
	} else if hasMonitoringPorts || hasAlertingConfig {
		alertingSystem = "Custom/External monitoring system"
	}

	// Create a summary table
	detail.WriteString("Alerting Configuration Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Component|Status\n")
	detail.WriteString(fmt.Sprintf("|Alert Configuration Files|%s\n", boolToYesNo(hasAlertingConfig)))
	detail.WriteString(fmt.Sprintf("|Alerting Services Running|%s\n", boolToYesNo(hasAlertingServices)))
	detail.WriteString(fmt.Sprintf("|Email Notifications|%s\n", boolToYesNo(hasEmailNotification)))
	detail.WriteString(fmt.Sprintf("|Other Notification Channels|%s\n", boolToYesNo(hasOtherNotification)))
	detail.WriteString(fmt.Sprintf("|Satellite-specific Rules|%s\n", boolToYesNo(hasSatelliteRules)))
	detail.WriteString(fmt.Sprintf("|Detected Alerting System|%s\n", alertingSystem))
	detail.WriteString("|===\n\n")

	// Determine the overall alerting status
	hasAlerting := (hasAlertingConfig || hasAlertingServices || hasAlertingProcesses || hasMonitoringTools || hasMonitoringPorts)
	hasNotifications := (hasEmailNotification || hasOtherNotification)

	// Evaluate results - more dynamic based on what we find
	if !hasAlerting {
		check.Result = report.NewResult(report.StatusWarning,
			"No alerting configuration detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Implement alerting for critical Satellite components")
		report.AddRecommendation(&check.Result, "Configure alerts for disk usage, service failures, and task queues")
		report.AddRecommendation(&check.Result, "Set up notification channels (email, Slack, etc.)")
	} else if hasMonitoringTools && !(hasAlertingServices || hasAlertingProcesses) {
		// Tools installed but not running
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Alerting tools installed (%s) but services may not be running", alertingSystem),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, fmt.Sprintf("Ensure %s services are running", alertingSystem))
		report.AddRecommendation(&check.Result, "Check and start relevant alerting services")
	} else if hasAlerting && !hasNotifications {
		check.Result = report.NewResult(report.StatusWarning,
			"Alert notification channels not configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure notification channels for alerts")
		report.AddRecommendation(&check.Result, "Set up email, Slack, or other notification method")
	} else if hasAlerting && !hasSatelliteRules {
		check.Result = report.NewResult(report.StatusWarning,
			"No Satellite-specific alert rules found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Create alert rules specific to Satellite components")
		report.AddRecommendation(&check.Result, "Monitor Foreman, Pulp, Candlepin, and database services")
	} else if hasAlerting && hasNotifications && hasSatelliteRules {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Alerting configuration detected (%s)", alertingSystem),
			report.ResultKeyNoChange)
	} else {
		// Partial configuration
		check.Result = report.NewResult(report.StatusWarning,
			"Partial alerting configuration detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Complete the alerting setup for comprehensive monitoring")
		if !hasNotifications {
			report.AddRecommendation(&check.Result, "Configure notification channels")
		}
		if !hasSatelliteRules {
			report.AddRecommendation(&check.Result, "Add Satellite-specific monitoring rules")
		}
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/monitoring_resources_admin",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
