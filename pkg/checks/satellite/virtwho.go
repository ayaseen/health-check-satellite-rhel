// pkg/checks/satellite/virtwho.go

package satellite

import (
	"fmt"
	"regexp"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunVirtWhoChecks performs virt-who related checks for Satellite
func RunVirtWhoChecks(r *report.AsciiDocReport) {
	// Check virt-who configurations
	checkVirtWhoConfiguration(r)

	// Check virt-who service and status
	checkVirtWhoService(r)

	// Check virtual machine subscription status
	checkVMSubscriptionStatus(r)
}

// checkVirtWhoConfiguration checks if virt-who is properly configured
func checkVirtWhoConfiguration(r *report.AsciiDocReport) {
	checkID := "satellite-virtwho-config"
	checkName := "Virt-Who Configuration"
	checkDesc := "Checks if virt-who is properly configured for virtual machine subscription management."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check for virt-who configuration files
	configFilesCmd := "find /etc/virt-who.d -name '*.conf' 2>/dev/null || echo 'No virt-who configuration files found'"
	configFilesOutput, _ := utils.RunCommand("bash", "-c", configFilesCmd)

	var detail strings.Builder
	detail.WriteString("Virt-Who Configuration Analysis:\n\n")

	detail.WriteString("Virt-Who Configuration Files:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(configFilesOutput)
	detail.WriteString("\n----\n\n")

	// Check virt-who configurations in Satellite
	virtWhoConfigsCmd := "hammer virt-who-config list 2>/dev/null || echo 'No virt-who configurations found or hammer command failed'"
	virtWhoConfigsOutput, _ := utils.RunCommand("bash", "-c", virtWhoConfigsCmd)

	detail.WriteString("Virt-Who Configurations in Satellite:\n")
	detail.WriteString("[source, bash]\n----\n")
	// Limit output size if very large
	if len(virtWhoConfigsOutput) > 1500 {
		detail.WriteString(virtWhoConfigsOutput[:1500] + "\n... [output truncated] ...\n")
	} else {
		detail.WriteString(virtWhoConfigsOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check if the system is a virtual machine and identify hypervisor type
	isVirtualCmd := "virt-what 2>/dev/null || echo 'virt-what not available'"
	isVirtualOutput, _ := utils.RunCommand("bash", "-c", isVirtualCmd)

	// Alternative check if virt-what isn't available
	if isVirtualOutput == "virt-what not available" {
		isVirtualCmd = "grep -E 'vendor|hypervisor|vmware|xen|kvm|vbox' /proc/cpuinfo 2>/dev/null || dmesg | grep -i 'hypervisor' || dmidecode | grep -i 'vmware\\|xen\\|kvm\\|virtualbox'"
		isVirtualOutput, _ = utils.RunCommand("bash", "-c", isVirtualCmd)
	}

	detail.WriteString("Virtualization Detection:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(isVirtualOutput)
	detail.WriteString("\n----\n\n")

	// Determine if running as a virtual machine
	isVM := isVirtualOutput != "" &&
		isVirtualOutput != "virt-what not available" &&
		!strings.Contains(isVirtualOutput, "No virtualization detected")

	// Try to determine hypervisor type
	hypervisorType := "Unknown"
	if isVM {
		if strings.Contains(strings.ToLower(isVirtualOutput), "vmware") {
			hypervisorType = "VMware"
		} else if strings.Contains(strings.ToLower(isVirtualOutput), "kvm") {
			hypervisorType = "KVM"
		} else if strings.Contains(strings.ToLower(isVirtualOutput), "xen") {
			hypervisorType = "Xen"
		} else if strings.Contains(strings.ToLower(isVirtualOutput), "virtualbox") || strings.Contains(strings.ToLower(isVirtualOutput), "vbox") {
			hypervisorType = "VirtualBox"
		} else if strings.Contains(strings.ToLower(isVirtualOutput), "hyper-v") {
			hypervisorType = "Hyper-V"
		}
	}

	// Check for hypervisors that require virt-who
	hypervisorsCmd := "hammer host list --fields name,architecture,operatingsystem,virtual --search 'virtual = hypervisor' 2>/dev/null || echo 'No hypervisors found'"
	hypervisorsOutput, _ := utils.RunCommand("bash", "-c", hypervisorsCmd)

	detail.WriteString("Detected Hypervisors:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hypervisorsOutput)
	detail.WriteString("\n----\n\n")

	// Check if there are any subscriptions that require virt-who
	requiresVirtWhoCmd := "hammer subscription list --fields name,requires_virt_who --search 'requires_virt_who = true' 2>/dev/null || echo 'No subscriptions require virt-who'"
	requiresVirtWhoOutput, _ := utils.RunCommand("bash", "-c", requiresVirtWhoCmd)

	detail.WriteString("Subscriptions Requiring Virt-Who:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(requiresVirtWhoOutput)
	detail.WriteString("\n----\n\n")

	// Check for host-based subscriptions
	hostBasedSubsCmd := "hammer subscription list --fields name,type,quantity --search 'type ~ \"Hypervisor\"' 2>/dev/null || echo 'No host-based subscriptions found'"
	hostBasedSubsOutput, _ := utils.RunCommand("bash", "-c", hostBasedSubsCmd)

	detail.WriteString("Host-Based Subscriptions:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hostBasedSubsOutput)
	detail.WriteString("\n----\n\n")

	// Detect if SCA (Simple Content Access) is enabled
	scaEnabledCmd := "subscription-manager status | grep -i 'Simple Content Access' || echo 'SCA not detected'"
	scaEnabledOutput, _ := utils.RunCommand("bash", "-c", scaEnabledCmd)

	detail.WriteString("Simple Content Access Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(scaEnabledOutput)
	detail.WriteString("\n----\n")

	// Analyze configuration status
	hasConfigFiles := !strings.Contains(configFilesOutput, "No virt-who configuration files found")
	hasSatelliteConfigs := !strings.Contains(virtWhoConfigsOutput, "No virt-who configurations found")
	hasHypervisors := !strings.Contains(hypervisorsOutput, "No hypervisors found")
	requiresVirtWho := !strings.Contains(requiresVirtWhoOutput, "No subscriptions require virt-who")
	hasHostBasedSubs := !strings.Contains(hostBasedSubsOutput, "No host-based subscriptions found")
	scaEnabled := strings.Contains(scaEnabledOutput, "Simple Content Access") &&
		!strings.Contains(scaEnabledOutput, "SCA not detected")

	// Count config files
	configFileCount := 0
	if hasConfigFiles {
		configFileCount = len(strings.Split(strings.TrimSpace(configFilesOutput), "\n"))
	}

	// Add a summary section about virtualization status
	detail.WriteString("\nVirtualization Summary:\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Characteristic|Value\n")
	detail.WriteString(fmt.Sprintf("|System is a Virtual Machine|%s\n", boolToYesNo(isVM)))
	if isVM {
		detail.WriteString(fmt.Sprintf("|Hypervisor Type|%s\n", hypervisorType))
	}
	detail.WriteString(fmt.Sprintf("|Simple Content Access Enabled|%s\n", boolToYesNo(scaEnabled)))
	detail.WriteString(fmt.Sprintf("|Virt-Who Configuration Present|%s\n", boolToYesNo(hasConfigFiles || hasSatelliteConfigs)))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if requiresVirtWho && (!hasConfigFiles && !hasSatelliteConfigs) {
		check.Result = report.NewResult(report.StatusWarning,
			"Virt-who configuration missing but required for subscriptions",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure virt-who to use host-based subscriptions")
		report.AddRecommendation(&check.Result, "Create virt-who configurations in Satellite for your hypervisors")
	} else if hasHypervisors && hasHostBasedSubs && (!hasConfigFiles && !hasSatelliteConfigs) {
		check.Result = report.NewResult(report.StatusWarning,
			"Host-based subscriptions being used without virt-who configuration",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure virt-who to report hypervisor and VM relationships")
		report.AddRecommendation(&check.Result, "Create virt-who configurations using Satellite web UI or hammer CLI")
	} else if isVM && (!hasConfigFiles && !hasSatelliteConfigs) && !scaEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("System appears to be a %s VM but no virt-who configuration found", hypervisorType),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure virt-who to properly track virtualization reporting")
		report.AddRecommendation(&check.Result, "Or enable Simple Content Access if available")
	} else if scaEnabled {
		if isVM && (!hasConfigFiles && !hasSatelliteConfigs) {
			check.Result = report.NewResult(report.StatusOK,
				"Simple Content Access is enabled; virt-who not strictly required",
				report.ResultKeyNoChange)
			report.AddRecommendation(&check.Result, "Consider configuring virt-who for better inventory reporting only")
		} else {
			check.Result = report.NewResult(report.StatusOK,
				"Simple Content Access is enabled; virt-who not strictly required",
				report.ResultKeyNoChange)
		}
	} else if hasConfigFiles || hasSatelliteConfigs {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Virt-who configured with %d configuration files", configFileCount),
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Virt-who not configured, may be required if using virtual machines",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider configuring virt-who if you have virtual machines")
		report.AddRecommendation(&check.Result, "Or enable Simple Content Access as an alternative")
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/configuring_virtual_machine_subscriptions",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_virt-who/")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkVirtWhoService checks if virt-who service is running properly
func checkVirtWhoService(r *report.AsciiDocReport) {
	checkID := "satellite-virtwho-service"
	checkName := "Virt-Who Service Status"
	checkDesc := "Checks if virt-who service is installed and running properly."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check if virt-who is installed
	installedCmd := "rpm -q virt-who || echo 'virt-who package not installed'"
	installedOutput, _ := utils.RunCommand("bash", "-c", installedCmd)

	var detail strings.Builder
	detail.WriteString("Virt-Who Service Analysis:\n\n")

	detail.WriteString("Virt-Who Package:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(installedOutput)
	detail.WriteString("\n----\n\n")

	// Check for virt-who configuration files to determine if service should be running
	configFilesCmd := "find /etc/virt-who.d -name '*.conf' 2>/dev/null || echo 'No virt-who configuration files found'"
	configFilesOutput, _ := utils.RunCommand("bash", "-c", configFilesCmd)
	hasConfigFiles := !strings.Contains(configFilesOutput, "No virt-who configuration files found")

	// Check virt-who service status
	serviceStatusCmd := "systemctl status virt-who 2>&1 || echo 'virt-who service not found'"
	serviceStatusOutput, _ := utils.RunCommand("bash", "-c", serviceStatusCmd)

	detail.WriteString("Virt-Who Service Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	// Limit service status output to keep report manageable
	serviceStatusLines := strings.Split(serviceStatusOutput, "\n")
	if len(serviceStatusLines) > 15 {
		for i := 0; i < 15; i++ {
			detail.WriteString(serviceStatusLines[i] + "\n")
		}
		detail.WriteString("... [output truncated] ...\n")
	} else {
		detail.WriteString(serviceStatusOutput)
	}
	detail.WriteString("\n----\n\n")

	// Check virt-who version
	versionCmd := "virt-who --version 2>/dev/null || echo 'Cannot determine virt-who version'"
	versionOutput, _ := utils.RunCommand("bash", "-c", versionCmd)

	detail.WriteString("Virt-Who Version:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(versionOutput)
	detail.WriteString("\n----\n\n")

	// Check recent virt-who logs
	logsCmd := "journalctl -u virt-who --since '1 day ago' --no-pager 2>/dev/null | tail -30 || echo 'No virt-who logs found'"
	logsOutput, _ := utils.RunCommand("bash", "-c", logsCmd)

	detail.WriteString("Recent Virt-Who Logs:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(logsOutput)
	detail.WriteString("\n----\n\n")

	// Check if service is reporting correctly to Satellite
	reportingCmd := "grep -i 'Report for config' /var/log/virt-who/virt-who.log 2>/dev/null | tail -10 || echo 'No reporting information found'"
	reportingOutput, _ := utils.RunCommand("bash", "-c", reportingCmd)

	detail.WriteString("Virt-Who Reporting Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(reportingOutput)
	detail.WriteString("\n----\n")

	// Check subscription-manager configuration for virt-who
	rhsmConfigCmd := "cat /etc/rhsm/rhsm.conf | grep -E 'hostname|insecure|proxy' | grep -v '^#'"
	rhsmConfigOutput, _ := utils.RunCommand("bash", "-c", rhsmConfigCmd)

	detail.WriteString("\nRHSM Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rhsmConfigOutput)
	detail.WriteString("\n----\n\n")

	// Detect if SCA (Simple Content Access) is enabled
	scaEnabledCmd := "subscription-manager status | grep -i 'Simple Content Access' || echo 'SCA not detected'"
	scaEnabledOutput, _ := utils.RunCommand("bash", "-c", scaEnabledCmd)
	scaEnabled := strings.Contains(scaEnabledOutput, "Simple Content Access") &&
		!strings.Contains(scaEnabledOutput, "SCA not detected")

	// Analyze service status
	isInstalled := !strings.Contains(installedOutput, "not installed")
	isRunning := strings.Contains(serviceStatusOutput, "Active: active (running)")
	hasRecentReports := !strings.Contains(reportingOutput, "No reporting information")
	hasErrors := strings.Contains(logsOutput, "Error") || strings.Contains(logsOutput, "ERROR")

	// Add analysis summary
	detail.WriteString("Virt-Who Status Summary:\n")
	detail.WriteString("[cols=\"1,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Status\n")
	detail.WriteString(fmt.Sprintf("|Virt-Who Installed|%s\n", boolToYesNo(isInstalled)))
	detail.WriteString(fmt.Sprintf("|Configuration Files Present|%s\n", boolToYesNo(hasConfigFiles)))
	detail.WriteString(fmt.Sprintf("|Service Running|%s\n", boolToYesNo(isRunning)))
	detail.WriteString(fmt.Sprintf("|Recent Reports Found|%s\n", boolToYesNo(hasRecentReports)))
	detail.WriteString(fmt.Sprintf("|Errors in Logs|%s\n", boolToYesNo(hasErrors)))
	detail.WriteString(fmt.Sprintf("|Simple Content Access Enabled|%s\n", boolToYesNo(scaEnabled)))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if !hasConfigFiles {
		// No configuration, so service status is not applicable
		check.Result = report.NewResult(report.StatusOK,
			"No virt-who configuration found; service check not applicable",
			report.ResultKeyNotApplicable)
	} else if !isInstalled {
		check.Result = report.NewResult(report.StatusWarning,
			"Virt-who configuration exists but package is not installed",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Install virt-who package: yum install virt-who")
		report.AddRecommendation(&check.Result, "Configure virt-who to report hypervisor information")
	} else if !isRunning {
		check.Result = report.NewResult(report.StatusWarning,
			"Virt-who service is installed but not running",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start virt-who service: systemctl start virt-who")
		report.AddRecommendation(&check.Result, "Enable virt-who service: systemctl enable virt-who")
	} else if hasErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Virt-who service is running but has errors in logs",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review virt-who logs for error details")
		report.AddRecommendation(&check.Result, "Check virt-who configuration files in /etc/virt-who.d/")
	} else if !hasRecentReports {
		check.Result = report.NewResult(report.StatusWarning,
			"Virt-who service is running but not reporting recently",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check that virt-who has appropriate access to hypervisors")
		report.AddRecommendation(&check.Result, "Verify hypervisor connection parameters in config files")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Virt-who service is installed and running properly",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/configuring_virtual_machine_subscriptions",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1607993") // Virt-who troubleshooting

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkVMSubscriptionStatus checks the subscription status of virtual machines
func checkVMSubscriptionStatus(r *report.AsciiDocReport) {
	checkID := "satellite-vm-subscription"
	checkName := "Virtual Machine Subscription Status"
	checkDesc := "Checks if virtual machines are properly subscribed through virt-who."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get virtual machines without valid subscriptions
	vmNoSubsCmd := "hammer host list --fields name,subscription_status --search 'virtual = true AND subscription_status ~ invalid' --per-page 20 2>/dev/null || echo 'No virtual machines with invalid subscriptions found'"
	vmNoSubsOutput, _ := utils.RunCommand("bash", "-c", vmNoSubsCmd)

	var detail strings.Builder
	detail.WriteString("Virtual Machine Subscription Analysis:\n\n")

	detail.WriteString("VMs with Invalid Subscriptions:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(vmNoSubsOutput)
	detail.WriteString("\n----\n\n")

	// Get count of virtual machines
	vmCountCmd := "hammer host list --fields name,subscription_status,virtual --search 'virtual = true' --per-page 1 2>/dev/null | grep 'Total:' || echo 'Total: 0'"
	vmCountOutput, _ := utils.RunCommand("bash", "-c", vmCountCmd)

	detail.WriteString("Total Virtual Machines:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(vmCountOutput)
	detail.WriteString("\n----\n\n")

	// Get hypervisors with VMs
	hypervisorVMsCmd := "hammer host list --fields name,virtual,subscription_status --search 'virtual = hypervisor' --per-page 10 2>/dev/null || echo 'No hypervisors found'"
	hypervisorVMsOutput, _ := utils.RunCommand("bash", "-c", hypervisorVMsCmd)

	detail.WriteString("Hypervisors:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hypervisorVMsOutput)
	detail.WriteString("\n----\n\n")

	// Get virt-who reported mappings
	reportedMappingsCmd := "hammer host list --fields name,virtual,subscription_status --search 'virtual = true AND reporter != null' --per-page 10 2>/dev/null || echo 'No virt-who reported hosts found'"
	reportedMappingsOutput, _ := utils.RunCommand("bash", "-c", reportedMappingsCmd)

	detail.WriteString("Virt-Who Reported Virtual Machines:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(reportedMappingsOutput)
	detail.WriteString("\n----\n\n")

	// Check for temporary subscriptions (7-day grace period)
	tempSubsCmd := "hammer subscription list --fields name,end_date --search 'name ~ temp' 2>/dev/null || echo 'No temporary subscriptions found'"
	tempSubsOutput, _ := utils.RunCommand("bash", "-c", tempSubsCmd)

	detail.WriteString("Temporary Subscriptions:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(tempSubsOutput)
	detail.WriteString("\n----\n")

	// Analyze subscription status
	hasVMsWithoutSubs := !strings.Contains(vmNoSubsOutput, "No virtual machines with invalid subscriptions found")
	hasMappings := !strings.Contains(reportedMappingsOutput, "No virt-who reported hosts found")
	hasHypervisors := !strings.Contains(hypervisorVMsOutput, "No hypervisors found")
	hasTempSubs := !strings.Contains(tempSubsOutput, "No temporary subscriptions found")

	// Add hypervisor information to results if available
	if hasHypervisors {
		detail.WriteString("\nHypervisors detected in environment that may require virt-who reporting.\n")
	}

	// Extract VM count
	vmCount := 0
	re := regexp.MustCompile(`Total:\s+(\d+)`)
	if match := re.FindStringSubmatch(vmCountOutput); len(match) > 1 {
		fmt.Sscanf(match[1], "%d", &vmCount)
	}

	// Evaluate results
	if hasVMsWithoutSubs && vmCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Some virtual machines have invalid subscription status",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify virt-who is running and reporting correctly")
		report.AddRecommendation(&check.Result, "Check that auto-attach is enabled in activation keys for virtual machines")
		report.AddRecommendation(&check.Result, "Ensure host-based subscriptions are available for hypervisors")
	} else if hasTempSubs {
		check.Result = report.NewResult(report.StatusWarning,
			"Temporary subscriptions detected for virtual machines",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Temporary subscriptions will expire in 7 days")
		report.AddRecommendation(&check.Result, "Ensure virt-who is reporting correctly to convert temporary to permanent subscriptions")
	} else if !hasMappings && vmCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Virtual machines exist but none are reported by virt-who",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check virt-who configuration and service status")
		report.AddRecommendation(&check.Result, "Verify hypervisor credentials and connectivity")
	} else if vmCount == 0 {
		check.Result = report.NewResult(report.StatusOK,
			"No virtual machines detected in Satellite inventory",
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Virtual machines appear to be properly subscribed",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/configuring_virtual_machine_subscriptions",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/subscription_central/2021/html/getting_started_with_simple_content_access")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
