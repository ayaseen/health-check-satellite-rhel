// pkg/checks/rhel/cluster.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunClusterChecks performs cluster integration and readiness checks
func RunClusterChecks(r *report.AsciiDocReport) {
	// Verify Pacemaker/Corosync versions and compatibility
	checkClusterSoftware(r)

	// Check node name resolution and hostname consistency
	checkClusterNameResolution(r)

	// Validate fencing agents and test them
	checkFencingAgents(r)

	// Review Pacemaker constraints and timeouts
	checkClusterConstraints(r)

	// Ensure cluster auto-starts on reboot
	checkClusterAutostart(r)

	// Test fencing and avoid split-brain conditions
	checkSplitBrainPrevention(r)
}

// checkClusterSoftware verifies Pacemaker/Corosync versions and compatibility
func checkClusterSoftware(r *report.AsciiDocReport) {
	checkID := "cluster-software"
	checkName := "Cluster Software"
	checkDesc := "Verifies Pacemaker/Corosync versions and compatibility."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if Pacemaker is installed
	pacemakerCmd := "rpm -q pacemaker corosync pcs 2>/dev/null || echo 'Cluster packages not installed'"
	pacemakerOutput, _ := utils.RunCommand("bash", "-c", pacemakerCmd)
	hasClusterPackages := !strings.Contains(pacemakerOutput, "not installed")

	if !hasClusterPackages {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster software detected",
			report.ResultKeyNotApplicable)
		r.AddCheck(check)
		return
	}

	// Get versions of key components
	versionsCmd := "rpm -q pacemaker corosync pcs resource-agents fence-agents-all --queryformat '%{NAME}-%{VERSION}-%{RELEASE}\n'"
	versionsOutput, _ := utils.RunCommand("bash", "-c", versionsCmd)

	// Check if services are running
	serviceStatusCmd := "systemctl status pacemaker corosync pcsd 2>/dev/null | grep 'Active:'"
	serviceStatusOutput, _ := utils.RunCommand("bash", "-c", serviceStatusCmd)
	servicesRunning := strings.Contains(serviceStatusOutput, "active (running)")

	// Check cluster status
	clusterStatusCmd := "pcs status 2>/dev/null || echo 'Cluster not running'"
	clusterStatusOutput, _ := utils.RunCommand("bash", "-c", clusterStatusCmd)
	clusterRunning := !strings.Contains(clusterStatusOutput, "Cluster not running")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("Cluster Packages:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pacemakerOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Component Versions:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(versionsOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Service Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(serviceStatusOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Cluster Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(clusterStatusOutput)
	detail.WriteString("\n----\n")

	// Evaluate cluster software
	if !servicesRunning {
		check.Result = report.NewResult(report.StatusWarning,
			"Cluster software installed but services are not running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start cluster services with 'systemctl start pacemaker corosync pcsd'")
		report.AddRecommendation(&check.Result, "Enable services with 'systemctl enable pacemaker corosync pcsd'")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-controlling-cluster-services-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !clusterRunning {
		check.Result = report.NewResult(report.StatusWarning,
			"Cluster services running but cluster is not active",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check cluster configuration with 'pcs config'")
		report.AddRecommendation(&check.Result, "Start the cluster with 'pcs cluster start --all'")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_troubleshooting-problems-with-high-availability-clustershigh-availability-clusters", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Cluster software is installed and running",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkClusterNameResolution checks node name resolution and hostname consistency
func checkClusterNameResolution(r *report.AsciiDocReport) {
	checkID := "cluster-names"
	checkName := "Cluster Name Resolution"
	checkDesc := "Checks node name resolution and hostname consistency."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if cluster is configured
	corosyncConfCmd := "test -f /etc/corosync/corosync.conf && cat /etc/corosync/corosync.conf || echo 'Corosync not configured'"
	corosyncConfOutput, _ := utils.RunCommand("bash", "-c", corosyncConfCmd)
	hasCorosyncConf := !strings.Contains(corosyncConfOutput, "not configured")

	if !hasCorosyncConf {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster configuration found",
			report.ResultKeyNotApplicable)
		r.AddCheck(check)
		return
	}

	// Extract node names from corosync.conf
	var nodeNames []string
	for _, line := range strings.Split(corosyncConfOutput, "\n") {
		if strings.Contains(line, "name:") {
			parts := strings.SplitN(line, ":", 2)
			if len(parts) > 1 {
				nodeName := strings.TrimSpace(parts[1])
				// Remove any quotes or trailing symbols
				nodeName = strings.Trim(nodeName, " \t,\"'")
				if nodeName != "" {
					nodeNames = append(nodeNames, nodeName)
				}
			}
		}
	}

	// Test name resolution for each node
	var nameResolutionIssues []string
	for _, node := range nodeNames {
		if strings.TrimSpace(node) == "" || node == "127.0.0.1" || node == "::1" {
			continue
		}

		// Try to resolve node name
		lookupCmd := fmt.Sprintf("getent hosts %s || echo 'Cannot resolve %s'", node, node)
		lookupOutput, _ := utils.RunCommand("bash", "-c", lookupCmd)

		if strings.Contains(lookupOutput, "Cannot resolve") {
			nameResolutionIssues = append(nameResolutionIssues, fmt.Sprintf("Node %s cannot be resolved", node))
		}
	}

	// Check system hostname
	hostnameCmd := "hostname"
	hostnameOutput, _ := utils.RunCommand("bash", "-c", hostnameCmd)
	hostname := strings.TrimSpace(hostnameOutput)

	// Check if hostname is in the cluster nodes
	hostnameInCluster := false
	for _, node := range nodeNames {
		if node == hostname {
			hostnameInCluster = true
			break
		}
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("Cluster Nodes from Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	for _, node := range nodeNames {
		detail.WriteString("- " + node + "\n")
	}
	detail.WriteString("----\n\n")

	detail.WriteString("System Hostname:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hostname)
	detail.WriteString("----\n\n")

	if len(nameResolutionIssues) > 0 {
		detail.WriteString("Name Resolution Issues:\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, issue := range nameResolutionIssues {
			detail.WriteString(issue + "\n")
		}
		detail.WriteString("\n----\n")
	}

	// Evaluate name resolution
	if len(nameResolutionIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d cluster name resolution issues", len(nameResolutionIssues)),
			report.ResultKeyRecommended)

		for _, issue := range nameResolutionIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Ensure all node names can be resolved through DNS or /etc/hosts")
		report.AddRecommendation(&check.Result, "Consistent name resolution is critical for cluster stability")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_cluster-network-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !hostnameInCluster {
		check.Result = report.NewResult(report.StatusWarning,
			"System hostname doesn't match any cluster node names",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the system hostname matches the name in corosync.conf")
		report.AddRecommendation(&check.Result, "Node names should be consistent in all cluster configuration")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_cluster-network-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All cluster node names resolve correctly",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFencingAgents validates fencing agents and their configuration
func checkFencingAgents(r *report.AsciiDocReport) {
	checkID := "cluster-fencing"
	checkName := "Fencing Agents"
	checkDesc := "Validates fencing agents and their configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if cluster is configured
	pacemakerCmd := "rpm -q pacemaker 2>/dev/null || echo 'Pacemaker not installed'"
	pacemakerOutput, _ := utils.RunCommand("bash", "-c", pacemakerCmd)
	hasPacemaker := !strings.Contains(pacemakerOutput, "not installed")

	if !hasPacemaker {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster software detected",
			report.ResultKeyNotApplicable)
		r.AddCheck(check)
		return
	}

	// Check for configured STONITH resources
	stonithCmd := "pcs stonith show 2>/dev/null || echo 'No fencing devices configured'"
	stonithOutput, _ := utils.RunCommand("bash", "-c", stonithCmd)
	hasStonith := !strings.Contains(stonithOutput, "No fencing devices configured")

	// Check if STONITH is enabled
	stonithEnabledCmd := "pcs property show stonith-enabled 2>/dev/null || echo 'stonith-enabled: true'"
	stonithEnabledOutput, _ := utils.RunCommand("bash", "-c", stonithEnabledCmd)
	stonithEnabled := !strings.Contains(stonithEnabledOutput, "stonith-enabled: false")

	// Get fence agents list
	fenceAgentsCmd := "ls -1 /usr/sbin/fence_* 2>/dev/null || echo 'No fence agents found'"
	fenceAgentsOutput, _ := utils.RunCommand("bash", "-c", fenceAgentsCmd)
	hasFenceAgents := !strings.Contains(fenceAgentsOutput, "No fence agents found")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("Fencing Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasStonith {
		detail.WriteString(stonithOutput)
	} else {
		detail.WriteString("No fencing devices configured\n")
	}
	detail.WriteString("----\n\n")

	detail.WriteString("STONITH Enabled Setting:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(stonithEnabledOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Available Fence Agents:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasFenceAgents {
		// Show a condensed list
		agents := strings.Split(fenceAgentsOutput, "\n")
		if len(agents) > 10 {
			detail.WriteString("(Sample of available agents)\n")
			for i := 0; i < 10; i++ {
				if agents[i] != "" {
					detail.WriteString("- " + strings.TrimPrefix(agents[i], "/usr/sbin/") + "\n")
				}
			}
			detail.WriteString(fmt.Sprintf("... and %d more\n", len(agents)-10))
		} else {
			for _, agent := range agents {
				if agent != "" {
					detail.WriteString("- " + strings.TrimPrefix(agent, "/usr/sbin/") + "\n")
				}
			}
		}
	} else {
		detail.WriteString("No fence agents found\n")
	}
	detail.WriteString("\n----\n")

	// Evaluate fencing configuration
	if !stonithEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"STONITH is disabled in the cluster",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable STONITH with 'pcs property set stonith-enabled=true'")
		report.AddRecommendation(&check.Result, "STONITH is essential for cluster data integrity")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-fencing-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !hasStonith {
		check.Result = report.NewResult(report.StatusWarning,
			"STONITH is enabled but no fencing devices are configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure fencing devices with 'pcs stonith create'")
		report.AddRecommendation(&check.Result, "Each node must have a fencing device configured")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-fencing-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Fencing is properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkClusterConstraints reviews Pacemaker constraints and timeouts
func checkClusterConstraints(r *report.AsciiDocReport) {
	checkID := "cluster-constraints"
	checkName := "Cluster Constraints"
	checkDesc := "Reviews Pacemaker constraints and timeouts."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if cluster is configured
	pacemakerCmd := "rpm -q pacemaker 2>/dev/null || echo 'Pacemaker not installed'"
	pacemakerOutput, _ := utils.RunCommand("bash", "-c", pacemakerCmd)
	hasPacemaker := !strings.Contains(pacemakerOutput, "not installed")

	if !hasPacemaker {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster software detected",
			report.ResultKeyNotApplicable)
		r.AddCheck(check)
		return
	}

	// Check for constraints
	constraintsCmd := "pcs constraint list 2>/dev/null || echo 'No constraints configured'"
	constraintsOutput, _ := utils.RunCommand("bash", "-c", constraintsCmd)
	hasConstraints := !strings.Contains(constraintsOutput, "No constraints configured")

	// Check resource defaults and operations
	resourceDefaultsCmd := "pcs resource defaults 2>/dev/null || echo 'No resource defaults'"
	resourceDefaultsOutput, _ := utils.RunCommand("bash", "-c", resourceDefaultsCmd)

	// Check resource operations
	resourceOpsCmd := "pcs resource op defaults 2>/dev/null || echo 'No operation defaults'"
	resourceOpsOutput, _ := utils.RunCommand("bash", "-c", resourceOpsCmd)

	// Check resources configuration
	resourcesCmd := "pcs resource show 2>/dev/null || echo 'No resources configured'"
	resourcesOutput, _ := utils.RunCommand("bash", "-c", resourcesCmd)
	hasResources := !strings.Contains(resourcesOutput, "No resources configured")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("Cluster Constraints:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasConstraints {
		detail.WriteString(constraintsOutput)
	} else {
		detail.WriteString("No constraints configured\n")
	}
	detail.WriteString("----\n\n")

	detail.WriteString("Resource Defaults:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(resourceDefaultsOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Operation Defaults:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(resourceOpsOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Configured Resources:\n")
	detail.WriteString("[source, bash]\n----\n")
	if hasResources {
		detail.WriteString(resourcesOutput)
	} else {
		detail.WriteString("No resources configured\n")
	}
	detail.WriteString("\n----\n")

	// Check for common issues
	issues := []string{}

	// Check if timeout values are defined in defaults
	hasTimeoutDefaults := strings.Contains(resourceDefaultsOutput, "timeout") ||
		strings.Contains(resourceOpsOutput, "timeout")

	// Check for migration-threshold
	hasMigrationThreshold := strings.Contains(resourceDefaultsOutput, "migration-threshold")

	// Check for colocation and ordering constraints when multiple resources exist
	needsConstraints := strings.Count(resourcesOutput, "Resource:") > 1 && !hasConstraints

	if hasResources && !hasTimeoutDefaults {
		issues = append(issues, "No timeout values defined in resource or operation defaults")
	}

	if hasResources && !hasMigrationThreshold {
		issues = append(issues, "No migration-threshold defined for resources")
	}

	if needsConstraints {
		issues = append(issues, "Multiple resources exist but no constraints defined")
	}

	// Evaluate constraints and timeouts
	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d issues with cluster constraints and timeouts", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !hasTimeoutDefaults {
			report.AddRecommendation(&check.Result, "Define operation timeout defaults: 'pcs resource op defaults timeout=60s'")
		}

		if !hasMigrationThreshold {
			report.AddRecommendation(&check.Result, "Define migration threshold: 'pcs resource defaults migration-threshold=5'")
		}

		if needsConstraints {
			report.AddRecommendation(&check.Result, "Define order and colocation constraints for related resources")
		}

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-resource-constraints-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !hasResources {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster resources configured to check constraints",
			report.ResultKeyAdvisory)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Cluster constraints and timeouts are properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkClusterAutostart ensures cluster auto-starts on reboot
func checkClusterAutostart(r *report.AsciiDocReport) {
	checkID := "cluster-autostart"
	checkName := "Cluster Autostart"
	checkDesc := "Ensures cluster auto-starts on reboot."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if cluster is configured
	pacemakerCmd := "rpm -q pacemaker 2>/dev/null || echo 'Pacemaker not installed'"
	pacemakerOutput, _ := utils.RunCommand("bash", "-c", pacemakerCmd)
	hasPacemaker := !strings.Contains(pacemakerOutput, "not installed")

	if !hasPacemaker {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster software detected",
			report.ResultKeyNotApplicable)
		r.AddCheck(check)
		return
	}

	// Check if services are enabled to start on boot
	servicesEnabledCmd := "systemctl is-enabled pacemaker corosync pcsd 2>/dev/null || echo 'error'"
	servicesEnabledOutput, _ := utils.RunCommand("bash", "-c", servicesEnabledCmd)
	allServicesEnabled := !strings.Contains(servicesEnabledOutput, "disabled") &&
		!strings.Contains(servicesEnabledOutput, "error")

	// Get cluster global config
	clusterConfigCmd := "pcs cluster status 2>/dev/null || echo 'Cluster not configured'"
	clusterConfigOutput, _ := utils.RunCommand("bash", "-c", clusterConfigCmd)
	clusterConfigured := !strings.Contains(clusterConfigOutput, "Cluster not configured")

	// Check cluster properties for auto_start
	clusterPropsCmd := "pcs property list 2>/dev/null | grep -E '(auto_start|start_on_boot)' || echo 'No auto-start properties found'"
	clusterPropsOutput, _ := utils.RunCommand("bash", "-c", clusterPropsCmd)
	hasAutoStartProperty := !strings.Contains(clusterPropsOutput, "No auto-start properties found")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("Services Enabled Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(servicesEnabledOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Cluster Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(clusterConfigOutput)
	detail.WriteString("----\n\n")

	if hasAutoStartProperty {
		detail.WriteString("Auto-start Properties:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(clusterPropsOutput)
		detail.WriteString("\n----\n")
	}

	// Evaluate cluster autostart
	if !clusterConfigured {
		check.Result = report.NewResult(report.StatusWarning,
			"Cluster software installed but cluster is not configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure the cluster with 'pcs cluster setup'")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_creating-high-availability-cluster-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !allServicesEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Cluster services are not enabled to start on boot",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable cluster services: 'systemctl enable pacemaker corosync pcsd'")
		report.AddRecommendation(&check.Result, "This is necessary for the cluster to start automatically after reboot")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-controlling-cluster-services-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if hasAutoStartProperty && strings.Contains(clusterPropsOutput, "false") {
		check.Result = report.NewResult(report.StatusWarning,
			"Cluster has auto-start disabled in properties",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable cluster auto-start: 'pcs property set start_on_boot=true'")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-cluster-properties-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Cluster is configured to auto-start on reboot",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSplitBrainPrevention tests fencing and split-brain prevention mechanisms
func checkSplitBrainPrevention(r *report.AsciiDocReport) {
	checkID := "cluster-split-brain"
	checkName := "Split-Brain Prevention"
	checkDesc := "Tests fencing and split-brain prevention mechanisms."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryPerformance)

	// Check if cluster is configured
	pacemakerCmd := "rpm -q pacemaker 2>/dev/null || echo 'Pacemaker not installed'"
	pacemakerOutput, _ := utils.RunCommand("bash", "-c", pacemakerCmd)
	hasPacemaker := !strings.Contains(pacemakerOutput, "not installed")

	if !hasPacemaker {
		check.Result = report.NewResult(report.StatusInfo,
			"No cluster software detected",
			report.ResultKeyNotApplicable)
		r.AddCheck(check)
		return
	}

	// Check corosync configuration
	corosyncConfCmd := "cat /etc/corosync/corosync.conf 2>/dev/null || echo 'Corosync not configured'"
	corosyncConfOutput, _ := utils.RunCommand("bash", "-c", corosyncConfCmd)
	hasCorosyncConf := !strings.Contains(corosyncConfOutput, "not configured")

	// Check quorum configuration
	quorumCmd := "grep -A 5 'quorum' /etc/corosync/corosync.conf 2>/dev/null || echo 'No quorum configuration found'"
	quorumOutput, _ := utils.RunCommand("bash", "-c", quorumCmd)
	hasQuorumConfig := !strings.Contains(quorumOutput, "No quorum configuration found")

	// Check for two_node configuration in two-node clusters
	nodeCountCmd := "grep 'node {' /etc/corosync/corosync.conf 2>/dev/null | wc -l"
	nodeCountOutput, _ := utils.RunCommand("bash", "-c", nodeCountCmd)
	nodeCount := 0
	fmt.Sscanf(strings.TrimSpace(nodeCountOutput), "%d", &nodeCount)

	// Check if this is a two-node cluster with proper configuration
	isTwoNodeCluster := nodeCount == 2
	hasTwoNodeConfig := strings.Contains(quorumOutput, "two_node: 1")

	// Check for STONITH enabled
	stonithEnabledCmd := "pcs property show stonith-enabled 2>/dev/null || echo 'stonith-enabled: true'"
	stonithEnabledOutput, _ := utils.RunCommand("bash", "-c", stonithEnabledCmd)
	stonithEnabled := !strings.Contains(stonithEnabledOutput, "stonith-enabled: false")

	// Check for proper fencing configuration
	fencingConfigured := false
	if stonithEnabled {
		// Check for configured STONITH resources
		stonithCmd := "pcs stonith show 2>/dev/null || echo 'No fencing devices configured'"
		stonithOutput, _ := utils.RunCommand("bash", "-c", stonithCmd)
		fencingConfigured = !strings.Contains(stonithOutput, "No fencing devices configured")
	}

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	var detail strings.Builder
	detail.WriteString("Corosync Quorum Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(quorumOutput)
	detail.WriteString("----\n\n")

	detail.WriteString("Cluster Node Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Cluster Node Count: %d\n", nodeCount))
	if isTwoNodeCluster {
		detail.WriteString(fmt.Sprintf("Two-node configuration: %v\n", hasTwoNodeConfig))
	}
	detail.WriteString("----\n\n")

	detail.WriteString("Fencing Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("STONITH Enabled: %v\n", stonithEnabled))
	detail.WriteString(fmt.Sprintf("Fencing Configured: %v\n", fencingConfigured))
	detail.WriteString("\n----\n")

	// Evaluate split-brain prevention
	if !hasCorosyncConf {
		check.Result = report.NewResult(report.StatusWarning,
			"Corosync is not configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure the cluster with 'pcs cluster setup'")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_creating-high-availability-cluster-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if isTwoNodeCluster && !hasTwoNodeConfig {
		check.Result = report.NewResult(report.StatusWarning,
			"Two-node cluster without proper two_node configuration",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure two_node: 1 in the quorum section of corosync.conf")
		report.AddRecommendation(&check.Result, "This is important for proper quorum handling in two-node clusters")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-quorum-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !hasQuorumConfig {
		check.Result = report.NewResult(report.StatusWarning,
			"No quorum configuration found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure proper quorum settings in corosync.conf")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-quorum-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !stonithEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"STONITH is disabled, leaving the cluster vulnerable to split-brain",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable STONITH with 'pcs property set stonith-enabled=true'")
		report.AddRecommendation(&check.Result, "STONITH is essential for cluster data integrity")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-fencing-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if !fencingConfigured {
		check.Result = report.NewResult(report.StatusWarning,
			"STONITH is enabled but no fencing devices are configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure fencing devices with 'pcs stonith create'")
		report.AddRecommendation(&check.Result, "Without fencing, split-brain cannot be automatically resolved")

		// Add reference link directly
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_configuring-fencing-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Split-brain prevention is properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
