// pkg/checks/rhel/monitoring.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunMonitoringChecks performs monitoring related checks
func RunMonitoringChecks(r *report.AsciiDocReport) {
	// Validate centralized log forwarding
	checkCentralizedLogging(r)

	// Check alerting rules for cluster and system failures
	checkAlertingRules(r)

	// Check monitoring agent configuration
	checkMonitoringAgents(r)
}

// checkCentralizedLogging validates centralized log forwarding
func checkCentralizedLogging(r *report.AsciiDocReport) {
	checkID := "monitoring-logs"
	checkName := "Centralized Logging"
	checkDesc := "Validates centralized log forwarding."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check for rsyslog configuration - improved search patterns for remote logging
	rsyslogConfCmd := "grep -r '[[:space:]]*@[^[:space:]]\\|[[:space:]]*@@[^[:space:]]\\|target=\\|action.Target=\\|action=\"omfwd\"' /etc/rsyslog.conf /etc/rsyslog.d/ 2>/dev/null || echo 'No remote logging configured in rsyslog'"
	rsyslogConfOutput, _ := utils.RunCommand("bash", "-c", rsyslogConfCmd)
	hasRsyslogForwarding := !strings.Contains(rsyslogConfOutput, "No remote logging configured")

	// Check for journald forwarding - improved to check actual configuration values
	journaldConfCmd := "grep -E 'ForwardTo(Syslog|Console|Wall|KMsg)' /etc/systemd/journald.conf 2>/dev/null | grep -v '^#' || echo 'No journald forwarding configured'"
	journaldConfOutput, _ := utils.RunCommand("bash", "-c", journaldConfCmd)
	hasJournaldForwarding := !strings.Contains(journaldConfOutput, "No journald forwarding configured")

	// Check for third-party logging agents
	otherAgentsCmd := "rpm -qa | grep -E '(filebeat|fluentd|fluentbit|logstash|splunk|elastic|syslog-ng|vector|promtail|telegraf|graylog|logagent)' || echo 'No logging agents detected'"
	otherAgentsOutput, _ := utils.RunCommand("bash", "-c", otherAgentsCmd)
	hasLoggingAgents := !strings.Contains(otherAgentsOutput, "No logging agents detected")

	// Check if rsyslog or other logging agents are running with improved service detection
	loggingStatusCmd := "systemctl status rsyslog syslog-ng filebeat fluentd td-agent splunk-forwarder fluent-bit vector promtail telegraf 2>/dev/null | grep 'Active:' || echo 'No logging services found'"
	loggingStatusOutput, _ := utils.RunCommand("bash", "-c", loggingStatusCmd)
	hasActiveLoggingService := strings.Contains(loggingStatusOutput, "active (running)")

	// Check filebeat configuration if installed - more thorough check
	filebeatConfCmd := "if rpm -q filebeat &>/dev/null; then grep -r '\\(output\\|elasticsearch\\|logstash\\|kafka\\|redis\\|hosts:\\)' /etc/filebeat /etc/filebeat/**/* 2>/dev/null || echo 'No filebeat output configuration found'; else echo 'Filebeat not installed'; fi"
	filebeatConfOutput, _ := utils.RunCommand("bash", "-c", filebeatConfCmd)
	hasFilebeatOutput := !strings.Contains(filebeatConfOutput, "No filebeat output configuration found") &&
		!strings.Contains(filebeatConfOutput, "Filebeat not installed") &&
		(strings.Contains(filebeatConfOutput, "hosts:") ||
			strings.Contains(filebeatConfOutput, "elasticsearch") ||
			strings.Contains(filebeatConfOutput, "logstash") ||
			strings.Contains(filebeatConfOutput, "kafka") ||
			strings.Contains(filebeatConfOutput, "redis"))

	// Check for fluentd configuration if installed
	fluentdConfCmd := "if rpm -q fluentd td-agent &>/dev/null; then grep -r '\\(<match\\|@type forward\\|@type elasticsearch\\|@type kafka\\)' /etc/fluentd /etc/td-agent /opt/td-agent 2>/dev/null || echo 'No fluentd forwarding configured'; else echo 'Fluentd not installed'; fi"
	fluentdConfOutput, _ := utils.RunCommand("bash", "-c", fluentdConfCmd)
	hasFluentdForwarding := !strings.Contains(fluentdConfOutput, "No fluentd forwarding configured") &&
		!strings.Contains(fluentdConfOutput, "Fluentd not installed") &&
		(strings.Contains(fluentdConfOutput, "@type forward") ||
			strings.Contains(fluentdConfOutput, "@type elasticsearch") ||
			strings.Contains(fluentdConfOutput, "@type kafka"))

	// Check for network connections to common logging ports - improved with netstat fallback
	logConnectionsCmd := "{ ss -tuln || netstat -tuln; } 2>/dev/null | grep -E ':(514|601|6514|5140|5170|9200|9300|5044|5140|24224|24220|10514)' || echo 'No logging connections detected'"
	logConnectionsOutput, _ := utils.RunCommand("bash", "-c", logConnectionsCmd)
	hasLogConnections := !strings.Contains(logConnectionsOutput, "No logging connections detected")

	// Check for outbound connections to logging servers
	outboundLogCmd := "{ ss -tn state established || netstat -tn; } 2>/dev/null | grep -E ':(514|601|6514|5140|5170|9200|9300|5044|5140|24224|24220|10514)' || echo 'No outbound logging connections detected'"
	outboundLogOutput, _ := utils.RunCommand("bash", "-c", outboundLogCmd)
	hasOutboundLogConnections := !strings.Contains(outboundLogOutput, "No outbound logging connections detected")

	var detail strings.Builder
	detail.WriteString("Rsyslog Remote Logging Configuration:\n")
	if hasRsyslogForwarding {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(rsyslogConfOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No remote logging configured in rsyslog\n\n")
	}

	detail.WriteString("\nJournald Forwarding Configuration:\n")
	if hasJournaldForwarding {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(journaldConfOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No journald forwarding configured\n\n")
	}

	detail.WriteString("\nLogging Agents Installed:\n")
	if hasLoggingAgents {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(otherAgentsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No specialized logging agents detected\n\n")
	}

	detail.WriteString("\nLogging Services Status:\n")
	if hasActiveLoggingService {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(loggingStatusOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No active logging services detected\n\n")
	}

	if hasFilebeatOutput {
		detail.WriteString("\nFilebeat Output Configuration:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(filebeatConfOutput)
		detail.WriteString("\n----\n")
	}

	if hasFluentdForwarding {
		detail.WriteString("\nFluentd Forwarding Configuration:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(fluentdConfOutput)
		detail.WriteString("\n----\n")
	}

	detail.WriteString("\nLogging Network Connections:\n")
	if hasLogConnections {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(logConnectionsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No logging-related network connections detected\n\n")
	}

	if hasOutboundLogConnections {
		detail.WriteString("\nOutbound Logging Connections:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(outboundLogOutput)
		detail.WriteString("\n----\n")
	}

	// Determine if centralized logging is configured - improved logic with weighted indicators
	hasCentralizedLogging := false

	// Primary indicators - any of these strongly suggests centralized logging
	primaryIndicators := hasRsyslogForwarding ||
		hasFilebeatOutput ||
		hasFluentdForwarding ||
		hasOutboundLogConnections

	// Secondary indicators - these suggest possible centralized logging
	secondaryIndicators := hasJournaldForwarding ||
		hasLogConnections ||
		(hasLoggingAgents && hasActiveLoggingService)

	hasCentralizedLogging = primaryIndicators || secondaryIndicators

	// Record the detected centralized logging solution for reporting
	var loggingSolution string
	if hasRsyslogForwarding {
		loggingSolution = "RSyslog remote forwarding"
	} else if hasFilebeatOutput {
		loggingSolution = "Filebeat"
	} else if hasFluentdForwarding {
		loggingSolution = "Fluentd/TD-Agent"
	} else if hasJournaldForwarding {
		loggingSolution = "Journald forwarding"
	} else if hasLoggingAgents && hasActiveLoggingService {
		loggingSolution = "Third-party logging agent"
	} else if hasLogConnections || hasOutboundLogConnections {
		loggingSolution = "Network-based log forwarding"
	} else {
		loggingSolution = "None detected"
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	logDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/index", rhelVersion)

	// Evaluate centralized logging
	if !hasActiveLoggingService {
		check.Result = report.NewResult(report.StatusWarning,
			"No active logging services detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start and enable rsyslog: 'systemctl enable --now rsyslog'")
		report.AddRecommendation(&check.Result, "Or configure another logging solution for centralized logging")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, logDocURL)
	} else if !hasCentralizedLogging {
		check.Result = report.NewResult(report.StatusWarning,
			"Logging services running but centralized logging not configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure remote log forwarding in rsyslog or another agent")
		report.AddRecommendation(&check.Result, "Example rsyslog config: '*.* @logserver:514'")
		report.AddRecommendation(&check.Result, "Centralized logging is essential for effective monitoring")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sconfiguring-and-managing-logging_logging-and-monitoring", logDocURL))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Centralized logging appears to be configured via "+loggingSolution),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkAlertingRules checks alerting rules for cluster and system failures
func checkAlertingRules(r *report.AsciiDocReport) {
	checkID := "monitoring-alerts"
	checkName := "Alerting Rules"
	checkDesc := "Checks alerting rules for cluster and system failures."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check for monitoring systems with alerting
	monitoringSystemsCmd := "rpm -qa | grep -E '(nagios|zabbix|prometheus|grafana|collectd|icinga)' || echo 'No common monitoring systems detected'"
	monitoringSystemsOutput, _ := utils.RunCommand("bash", "-c", monitoringSystemsCmd)
	hasMonitoringSystems := !strings.Contains(monitoringSystemsOutput, "No common monitoring systems detected")

	// Check for alerting configurations
	alertingConfigCmd := "find /etc -path '*/nagios/*' -o -path '*/zabbix/*' -o -path '*/prometheus/*' -o -path '*/alertmanager/*' -o -path '*/icinga/*' | grep -E '(alert|notif)' 2>/dev/null || echo 'No alerting configurations found'"
	alertingConfigOutput, _ := utils.RunCommand("bash", "-c", alertingConfigCmd)
	hasAlertingConfigs := !strings.Contains(alertingConfigOutput, "No alerting configurations found")

	// Check if monitoring agents are running
	monitoringAgentsCmd := "systemctl status nagios zabbix-agent node_exporter collectd icinga2 2>/dev/null | grep 'Active:' || echo 'No monitoring agents found'"
	monitoringAgentsOutput, _ := utils.RunCommand("bash", "-c", monitoringAgentsCmd)
	hasActiveMonitoringAgents := strings.Contains(monitoringAgentsOutput, "active (running)")

	// Check for alert management connections
	alertConnectionsCmd := "ss -tuln | grep -E ':(9093|5666|10050|10051|5665|8080)' || echo 'No alert manager connections detected'"
	alertConnectionsOutput, _ := utils.RunCommand("bash", "-c", alertConnectionsCmd)
	hasAlertConnections := !strings.Contains(alertConnectionsOutput, "No alert manager connections detected")

	// Check for email alert configuration
	emailAlertCmd := "grep -r 'mail\\|email\\|smtp' /etc/nagios* /etc/zabbix* /etc/prometheus* /etc/icinga* /etc/alertmanager* 2>/dev/null || echo 'No email alerting configurations found'"
	emailAlertOutput, _ := utils.RunCommand("bash", "-c", emailAlertCmd)
	hasEmailAlerts := !strings.Contains(emailAlertOutput, "No email alerting configurations found")

	// Check if this is a cluster node and if there are cluster-specific alert configs
	isClusterNodeCmd := "rpm -q pacemaker 2>/dev/null || echo 'Not a cluster node'"
	isClusterNodeOutput, _ := utils.RunCommand("bash", "-c", isClusterNodeCmd)
	isClusterNode := !strings.Contains(isClusterNodeOutput, "Not a cluster node")

	var clusterAlertOutput string
	hasClusterAlerts := false

	if isClusterNode {
		clusterAlertCmd := "find /etc -path '*/nagios/*' -o -path '*/zabbix/*' -o -path '*/prometheus/*' -o -path '*/icinga/*' | xargs grep -l 'cluster\\|pacemaker\\|corosync' 2>/dev/null || echo 'No cluster-specific monitoring configurations found'"
		clusterAlertOutput, _ = utils.RunCommand("bash", "-c", clusterAlertCmd)
		hasClusterAlerts = !strings.Contains(clusterAlertOutput, "No cluster-specific monitoring configurations found")
	}

	var detail strings.Builder
	detail.WriteString("Monitoring Systems Installed:\n")
	if hasMonitoringSystems {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(monitoringSystemsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No common monitoring systems detected\n\n")
	}

	detail.WriteString("\nAlerting Configurations:\n")
	if hasAlertingConfigs {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(alertingConfigOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No alerting configurations found\n\n")
	}

	detail.WriteString("\nMonitoring Agents Status:\n")
	if hasActiveMonitoringAgents {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(monitoringAgentsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No active monitoring agents detected\n\n")
	}

	detail.WriteString("\nAlert Manager Connections:\n")
	if hasAlertConnections {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(alertConnectionsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No alert manager connections detected\n\n")
	}

	if hasEmailAlerts {
		detail.WriteString("\nEmail Alerting Configuration:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(emailAlertOutput)
		detail.WriteString("\n----\n")
	}

	if isClusterNode {
		detail.WriteString("\nCluster Monitoring Configuration:\n")
		if hasClusterAlerts {
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(clusterAlertOutput)
			detail.WriteString("\n----\n")
		} else {
			detail.WriteString("No cluster-specific monitoring configurations found\n\n")
		}
	}

	// Determine if alerting is configured
	hasAlerting := hasAlertingConfigs || hasEmailAlerts || hasAlertConnections

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	monitoringDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/index", rhelVersion)
	clusterDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/index", rhelVersion)

	// Evaluate alerting rules
	if !hasMonitoringSystems && !hasActiveMonitoringAgents {
		check.Result = report.NewResult(report.StatusWarning,
			"No monitoring system or agents detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install and configure a monitoring system (e.g., Nagios, Zabbix, Prometheus)")
		report.AddRecommendation(&check.Result, "Deploy monitoring agents on all systems")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, monitoringDocURL)
	} else if !hasAlerting {
		check.Result = report.NewResult(report.StatusWarning,
			"Monitoring in place but no alerting configurations detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure alerting rules for critical system events")
		report.AddRecommendation(&check.Result, "Set up alerts for CPU, memory, disk space, and service availability")
		report.AddRecommendation(&check.Result, "Configure notification channels (email, messaging apps, etc.)")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%smonitoring-performance-using-performance-co-pilot_logging-and-monitoring", monitoringDocURL))
	} else if isClusterNode && !hasClusterAlerts {
		check.Result = report.NewResult(report.StatusWarning,
			"Cluster node without specific cluster monitoring alerts",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure specific monitoring for cluster resources")
		report.AddRecommendation(&check.Result, "Monitor Pacemaker and Corosync services")
		report.AddRecommendation(&check.Result, "Set up alerts for split-brain scenarios and resource failures")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, clusterDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Alerting rules appear to be configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkMonitoringAgents checks monitoring agent configuration
func checkMonitoringAgents(r *report.AsciiDocReport) {
	checkID := "monitoring-agents"
	checkName := "Monitoring Agents"
	checkDesc := "Confirms monitoring agents are active."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryServices)

	// Check for monitoring agents installed
	monitoringAgentsCmd := "rpm -qa | grep -E '(nagios-plugins|nrpe|zabbix-agent|node_exporter|collectd|icinga2-agent)' || echo 'No monitoring agents detected'"
	monitoringAgentsOutput, _ := utils.RunCommand("bash", "-c", monitoringAgentsCmd)
	hasMonitoringAgents := !strings.Contains(monitoringAgentsOutput, "No monitoring agents detected")

	// Check if monitoring agents are running
	agentStatusCmd := "systemctl status nrpe zabbix-agent node_exporter collectd icinga2 2>/dev/null | grep 'Active:' || echo 'No monitoring agent services found'"
	agentStatusOutput, _ := utils.RunCommand("bash", "-c", agentStatusCmd)
	hasActiveAgents := strings.Contains(agentStatusOutput, "active (running)")

	// Check for monitoring ports open
	monitoringPortsCmd := "ss -tuln | grep -E ':(5666|10050|9100|9090|9093|5665)' || echo 'No monitoring ports detected'"
	monitoringPortsOutput, _ := utils.RunCommand("bash", "-c", monitoringPortsCmd)
	hasMonitoringPorts := !strings.Contains(monitoringPortsOutput, "No monitoring ports detected")

	// Check agent configurations
	agentConfigCmd := "find /etc -path '*/collectd/*' -o -path '*/node_exporter/*' -o -path '*/zabbix/*' -o -path '*/nagios/*' -o -name 'nrpe.cfg' -o -path '*/icinga2/*' 2>/dev/null || echo 'No monitoring agent configurations found'"
	agentConfigOutput, _ := utils.RunCommand("bash", "-c", agentConfigCmd)
	hasAgentConfigs := !strings.Contains(agentConfigOutput, "No monitoring agent configurations found")

	// Check for agent logs to see if they're working properly
	agentLogsCmd := "grep -i -E '(error|fail|warn)' /var/log/zabbix-agent/* /var/log/collectd.log /var/log/nagios/* /var/log/icinga2/* 2>/dev/null | tail -10 || echo 'No agent log errors found or logs not available'"
	agentLogsOutput, _ := utils.RunCommand("bash", "-c", agentLogsCmd)
	hasAgentErrors := !strings.Contains(agentLogsOutput, "No agent log errors found") &&
		strings.TrimSpace(agentLogsOutput) != ""

	// Check for firewall rules allowing monitoring connections
	firewallRulesCmd := "firewall-cmd --list-all 2>/dev/null | grep -E '(zabbix|nrpe|nagios|monitoring|node_exporter|prometheus|icinga|5666|10050|9100)' || iptables -L -n | grep -E '(zabbix|nrpe|nagios|monitoring|node_exporter|prometheus|icinga|5666|10050|9100)' || echo 'No monitoring firewall rules detected'"
	firewallRulesOutput, _ := utils.RunCommand("bash", "-c", firewallRulesCmd)
	hasFirewallRules := !strings.Contains(firewallRulesOutput, "No monitoring firewall rules detected")

	var detail strings.Builder
	detail.WriteString("Monitoring Agents Installed:\n")
	if hasMonitoringAgents {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(monitoringAgentsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No monitoring agents detected\n\n")
	}

	detail.WriteString("\nMonitoring Agent Services:\n")
	if hasActiveAgents {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(agentStatusOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No monitoring agent services found\n\n")
	}

	detail.WriteString("\nMonitoring Ports Open:\n")
	if hasMonitoringPorts {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(monitoringPortsOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No monitoring ports detected\n\n")
	}

	detail.WriteString("\nMonitoring Agent Configurations:\n")
	if hasAgentConfigs {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(agentConfigOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No monitoring agent configurations found\n\n")
	}

	if hasAgentErrors {
		detail.WriteString("\nMonitoring Agent Log Errors:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(agentLogsOutput)
		detail.WriteString("\n----\n")
	}

	detail.WriteString("\nFirewall Rules for Monitoring:\n")
	if hasFirewallRules {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(firewallRulesOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No monitoring firewall rules detected\n\n")
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	monitoringDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/monitoring_and_managing_system_status_and_performance/index", rhelVersion)
	firewallDocURL := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/index", rhelVersion)

	// Evaluate monitoring agents
	if !hasMonitoringAgents {
		check.Result = report.NewResult(report.StatusWarning,
			"No monitoring agents detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install a monitoring agent (e.g., Zabbix Agent, Node Exporter, NRPE)")
		report.AddRecommendation(&check.Result, "Configure the agent to connect to your monitoring server")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%smonitoring-performance-using-performance-co-pilot_logging-and-monitoring", monitoringDocURL))
	} else if !hasActiveAgents {
		check.Result = report.NewResult(report.StatusWarning,
			"Monitoring agents installed but not running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start and enable monitoring agent services")
		report.AddRecommendation(&check.Result, "Example: 'systemctl enable --now zabbix-agent'")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, monitoringDocURL)
	} else if hasAgentErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Monitoring agents running but errors detected in logs",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review agent logs and fix configuration issues")
		report.AddRecommendation(&check.Result, "Check connectivity to monitoring server")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("%sconfiguring-and-managing-logging_logging-and-monitoring", monitoringDocURL))
	} else if !hasFirewallRules && hasMonitoringPorts {
		check.Result = report.NewResult(report.StatusWarning,
			"Monitoring ports open but no specific firewall rules detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Add firewall rules to allow connections from monitoring servers only")
		report.AddRecommendation(&check.Result, "Example: 'firewall-cmd --permanent --add-rich-rule=\"rule family=ipv4 source address=monitoring-server-ip port port=10050 protocol=tcp accept\"'")
		// Add reference link directly
		report.AddReferenceLink(&check.Result, firewallDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Monitoring agents appear to be properly configured and active",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
