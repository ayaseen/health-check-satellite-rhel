// pkg/checks/rhel/ha_networking.go

package rhel

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunHANetworkingChecks performs HA networking readiness checks
func RunHANetworkingChecks(r *report.AsciiDocReport) {
	// Confirm multicast is enabled for Corosync
	checkMulticast(r)

	// Validate fencing interface reachability
	checkFencingNetworking(r)
}

// checkMulticast confirms multicast is enabled for Corosync
func checkMulticast(r *report.AsciiDocReport) {
	checkID := "ha-multicast"
	checkName := "Multicast Configuration"
	checkDesc := "Confirms multicast is enabled for Corosync."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Check if this is a cluster member
	isClusterMemberCmd := "rpm -q pacemaker corosync 2>/dev/null || echo 'Clustering packages not installed'"
	isClusterMemberOutput, _ := utils.RunCommand("bash", "-c", isClusterMemberCmd)
	isClusterMember := !strings.Contains(isClusterMemberOutput, "not installed")

	if !isClusterMember {
		check.Result = report.NewResult(report.StatusInfo,
			"System is not a cluster member",
			report.ResultKeyNotApplicable)
		report.AddRecommendation(&check.Result, "This check is only applicable for cluster nodes")
		r.AddCheck(check)
		return
	}

	// Check corosync configuration
	corosyncConfCmd := "cat /etc/corosync/corosync.conf 2>/dev/null || echo 'Corosync configuration not found'"
	corosyncConfOutput, _ := utils.RunCommand("bash", "-c", corosyncConfCmd)

	// Determine if multicast or unicast is being used
	usesMulticast := strings.Contains(corosyncConfOutput, "mcastaddr")
	usesUnicast := strings.Contains(corosyncConfOutput, "hostname") || strings.Contains(corosyncConfOutput, "ring")

	// Check if multicast is enabled in the kernel
	multicastEnabledCmd := "cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null || echo 'unknown'"
	multicastEnabledOutput, _ := utils.RunCommand("bash", "-c", multicastEnabledCmd)
	multicastEnabled := strings.TrimSpace(multicastEnabledOutput) == "0"

	// Test multicast using omping if available
	ompingInstalledCmd := "which omping 2>/dev/null || echo 'omping not available'"
	ompingInstalledOutput, _ := utils.RunCommand("bash", "-c", ompingInstalledCmd)
	ompingAvailable := !strings.Contains(ompingInstalledOutput, "not available")

	var ompingOutput string
	var multicastWorking bool

	if ompingAvailable && usesMulticast {
		// Extract multicast address from corosync.conf
		mcastAddr := "239.255.1.1" // Default if not found
		for _, line := range strings.Split(corosyncConfOutput, "\n") {
			if strings.Contains(line, "mcastaddr:") {
				parts := strings.Split(line, ":")
				if len(parts) > 1 {
					mcastAddrCandidate := strings.TrimSpace(parts[1])
					// Remove any trailing commas or quotes
					mcastAddrCandidate = strings.Trim(mcastAddrCandidate, " \t,\"'")
					if mcastAddrCandidate != "" {
						mcastAddr = mcastAddrCandidate
					}
				}
			}
		}

		// Try to get the cluster network interface
		clusterInterfaceCmd := "ip route get " + mcastAddr + " 2>/dev/null | awk '{print $5}' || echo 'unknown'"
		clusterInterfaceOutput, _ := utils.RunCommand("bash", "-c", clusterInterfaceCmd)
		clusterInterface := strings.TrimSpace(clusterInterfaceOutput)

		if clusterInterface == "unknown" {
			// Try to find the interface from corosync.conf
			for _, line := range strings.Split(corosyncConfOutput, "\n") {
				if strings.Contains(line, "bindnetaddr:") {
					bindNetAddr := strings.TrimSpace(strings.Split(line, ":")[1])
					bindNetAddr = strings.Trim(bindNetAddr, " \t,\"'")

					// Try to find the interface with this network
					ifaceForNetCmd := "ip route | grep " + bindNetAddr + " | awk '{print $3}' || echo 'unknown'"
					ifaceForNetOutput, _ := utils.RunCommand("bash", "-c", ifaceForNetCmd)
					possibleIface := strings.TrimSpace(ifaceForNetOutput)

					if possibleIface != "unknown" {
						clusterInterface = possibleIface
						break
					}
				}
			}
		}

		// If we still don't have an interface, use the first non-loopback interface
		if clusterInterface == "unknown" {
			firstInterfaceCmd := "ip -o link show | grep -v 'lo:' | head -1 | awk -F': ' '{print $2}' || echo 'eth0'"
			firstInterfaceOutput, _ := utils.RunCommand("bash", "-c", firstInterfaceCmd)
			clusterInterface = strings.TrimSpace(firstInterfaceOutput)
		}

		// Run omping test
		ompingCmd := fmt.Sprintf("timeout 3 omping -c 3 -i %s %s 2>&1 || echo 'Multicast test failed'",
			clusterInterface, mcastAddr)
		ompingOutput, _ = utils.RunCommand("bash", "-c", ompingCmd)
		multicastWorking = !strings.Contains(ompingOutput, "failed") && strings.Contains(ompingOutput, "multicast")
	}

	// Check firewall rules for multicast traffic
	firewallMulticastCmd := "iptables -L -n | grep -i multicast || firewall-cmd --list-all | grep -i multicast || echo 'No multicast firewall rules found'"
	firewallMulticastOutput, _ := utils.RunCommand("bash", "-c", firewallMulticastCmd)
	hasMulticastFirewallRules := !strings.Contains(firewallMulticastOutput, "No multicast firewall rules found")

	var detail strings.Builder
	detail.WriteString("Cluster Package Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(isClusterMemberOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Corosync Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	if !strings.Contains(corosyncConfOutput, "not found") {
		// Show relevant portions of the config
		for _, line := range strings.Split(corosyncConfOutput, "\n") {
			if strings.Contains(line, "transport:") ||
				strings.Contains(line, "mcastaddr:") ||
				strings.Contains(line, "mcastport:") ||
				strings.Contains(line, "bindnetaddr:") ||
				strings.Contains(line, "hostname:") ||
				strings.Contains(line, "ring") {
				detail.WriteString(line + "\n")
			}
		}
	} else {
		detail.WriteString(corosyncConfOutput)
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Multicast Kernel Setting:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("icmp_echo_ignore_broadcasts = %s (0 means multicast enabled)\n", strings.TrimSpace(multicastEnabledOutput)))
	detail.WriteString("\n----\n")

	if ompingAvailable && usesMulticast {
		detail.WriteString("\nMulticast Test Results:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(ompingOutput)
		detail.WriteString("\n----\n\n")
	}

	detail.WriteString("Firewall Multicast Rules:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(firewallMulticastOutput)
	detail.WriteString("\n----\n")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate multicast configuration
	if !usesMulticast && !usesUnicast {
		check.Result = report.NewResult(report.StatusWarning,
			"Corosync transport method not clearly defined",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure Corosync transport method (multicast or unicast)")
		report.AddRecommendation(&check.Result, "Recommended: Add 'transport: udpu' for unicast in corosync.conf")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_creating-cluster-configuring-managing-high-availability-clusters", rhelVersion))
	} else if usesMulticast && !multicastEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Multicast is used by Corosync but may be disabled in kernel",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Enable multicast in kernel: 'echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts'")
		report.AddRecommendation(&check.Result, "Make the change persistent: 'echo \"net.ipv4.icmp_echo_ignore_broadcasts = 0\" >> /etc/sysctl.conf'")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/configuring-system-network-parameters_configuring-and-managing-networking", rhelVersion))
	} else if usesMulticast && ompingAvailable && !multicastWorking {
		check.Result = report.NewResult(report.StatusWarning,
			"Multicast test failed, cluster communication may be impacted",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check network configuration for multicast support")
		report.AddRecommendation(&check.Result, "Verify switch configuration allows multicast traffic")
		report.AddRecommendation(&check.Result, "Consider switching to unicast (transport: udpu) if multicast cannot be fixed")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/troubleshooting-cluster-components-configuring-and-managing-high-availability-clusters", rhelVersion))
	} else if usesMulticast && !hasMulticastFirewallRules {
		check.Result = report.NewResult(report.StatusWarning,
			"No specific firewall rules for multicast detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Add firewall rules for multicast traffic")
		report.AddRecommendation(&check.Result, "For firewalld: 'firewall-cmd --permanent --add-rich-rule=\"rule family=ipv4 destination address=239.255.0.0/16 protocol=udp accept\"'")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_creating-cluster-configuring-managing-high-availability-clusters#high-availability-firewall-configuring-managing-high-availability-clusters", rhelVersion))
	} else if usesMulticast {
		check.Result = report.NewResult(report.StatusOK,
			"Multicast is properly configured for Corosync",
			report.ResultKeyNoChange)
	} else if usesUnicast {
		check.Result = report.NewResult(report.StatusOK,
			"Unicast transport is configured for Corosync",
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not determine Corosync transport configuration",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify Corosync configuration is properly set up")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_creating-cluster-configuring-managing-high-availability-clusters", rhelVersion))
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFencingNetworking validates fencing interface reachability
func checkFencingNetworking(r *report.AsciiDocReport) {
	checkID := "ha-fencing-network"
	checkName := "Fencing Network"
	checkDesc := "Validates fencing interface reachability."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Check if this is a cluster member
	isClusterMemberCmd := "rpm -q pacemaker 2>/dev/null || echo 'Clustering packages not installed'"
	isClusterMemberOutput, _ := utils.RunCommand("bash", "-c", isClusterMemberCmd)
	isClusterMember := !strings.Contains(isClusterMemberOutput, "not installed")

	if !isClusterMember {
		check.Result = report.NewResult(report.StatusInfo,
			"System is not a cluster member",
			report.ResultKeyNotApplicable)
		report.AddRecommendation(&check.Result, "This check is only applicable for cluster nodes")
		r.AddCheck(check)
		return
	}

	// Check for fencing devices configuration
	fencingDevicesCmd := "pcs stonith show 2>/dev/null || echo 'No fencing devices configured'"
	fencingDevicesOutput, _ := utils.RunCommand("bash", "-c", fencingDevicesCmd)
	hasFencingDevices := !strings.Contains(fencingDevicesOutput, "No fencing devices configured")

	// Extract fencing device IPs or hostnames
	var fencingTargets []string
	if hasFencingDevices {
		// Try to extract IPs from stonith device configuration
		for _, line := range strings.Split(fencingDevicesOutput, "\n") {
			if strings.Contains(line, "ipaddr=") || strings.Contains(line, "ip=") ||
				strings.Contains(line, "hostname=") || strings.Contains(line, "host=") {
				parts := strings.Split(line, "=")
				if len(parts) > 1 {
					fencingTargets = append(fencingTargets, strings.TrimSpace(parts[1]))
				}
			}
		}
	}

	// If we couldn't extract targets from the config, check if there are other nodes in the cluster
	if len(fencingTargets) == 0 {
		clusterNodesCmd := "pcs status nodes 2>/dev/null | grep -v 'Standby' | grep 'Online' || echo 'No nodes found'"
		clusterNodesOutput, _ := utils.RunCommand("bash", "-c", clusterNodesCmd)

		if !strings.Contains(clusterNodesOutput, "No nodes found") {
			// Extract node names
			for _, line := range strings.Split(clusterNodesOutput, "\n") {
				if strings.Contains(line, "Online:") {
					parts := strings.Split(line, ":")
					if len(parts) > 1 {
						nodeList := strings.Split(parts[1], " ")
						for _, node := range nodeList {
							node = strings.TrimSpace(node)
							if node != "" {
								fencingTargets = append(fencingTargets, node)
							}
						}
					}
				}
			}
		}
	}

	// Test connectivity to fencing targets
	var fencingReachability strings.Builder
	unreachableTargets := []string{}

	var detail strings.Builder
	detail.WriteString("Cluster Package Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(isClusterMemberOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Fencing Devices Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fencingDevicesOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Fencing Targets:\n")
	detail.WriteString("[source, bash]\n----\n")
	if len(fencingTargets) > 0 {
		for _, target := range fencingTargets {
			detail.WriteString(fmt.Sprintf("- %s\n", target))
		}
	} else {
		detail.WriteString("No fencing targets identified\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Fencing Reachability Tests:\n")
	detail.WriteString("[source, bash]\n----\n")
	if len(fencingTargets) > 0 {
		for _, target := range fencingTargets {
			pingCmd := fmt.Sprintf("ping -c 1 -W 2 %s 2>&1 || echo 'Ping failed'", target)
			pingOutput, _ := utils.RunCommand("bash", "-c", pingCmd)

			fencingReachability.WriteString(fmt.Sprintf("Target %s: ", target))
			if strings.Contains(pingOutput, "Ping failed") {
				fencingReachability.WriteString("UNREACHABLE\n")
				unreachableTargets = append(unreachableTargets, target)
			} else {
				fencingReachability.WriteString("Reachable\n")
			}
		}
		detail.WriteString(fencingReachability.String())
	} else {
		detail.WriteString("No fencing targets to test\n")
	}
	detail.WriteString("\n----\n\n")

	// Check if fencing devices are on a separate network interface
	separateInterface := false

	if len(fencingTargets) > 0 {
		// Check network interfaces used for routing to fencing targets
		clusterInterfaceCmd := "ip -o a | grep -v 'lo' | head -1 | awk '{print $2}'"
		clusterInterfaceOutput, _ := utils.RunCommand("bash", "-c", clusterInterfaceCmd)
		clusterInterface := strings.TrimSpace(clusterInterfaceOutput)

		for _, target := range fencingTargets {
			// Get the interface used to reach each target
			outInterfaceCmd := fmt.Sprintf("ip route get %s 2>/dev/null | grep -o 'dev [^ ]*' | awk '{print $2}'", target)
			outInterfaceOutput, _ := utils.RunCommand("bash", "-c", outInterfaceCmd)
			outInterface := strings.TrimSpace(outInterfaceOutput)

			if outInterface != "" && outInterface != clusterInterface {
				separateInterface = true
				break
			}
		}
	}

	detail.WriteString(fmt.Sprintf("Fencing devices use separate network interface: %v\n", separateInterface))

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()

	// Evaluate fencing networking
	if !hasFencingDevices {
		check.Result = report.NewResult(report.StatusWarning,
			"No fencing devices configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure fencing devices for the cluster")
		report.AddRecommendation(&check.Result, "Use 'pcs stonith create' to configure fencing")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_fencing-configuring-managing-high-availability-clusters", rhelVersion))
	} else if len(fencingTargets) == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"Fencing devices configured but couldn't identify targets",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify fencing device configuration is correct")
		report.AddRecommendation(&check.Result, "Ensure fencing device parameters are properly set")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_fencing-configuring-managing-high-availability-clusters", rhelVersion))
	} else if len(unreachableTargets) > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("%d fencing targets are unreachable", len(unreachableTargets)),
			report.ResultKeyRequired)

		for _, target := range unreachableTargets {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Fix connectivity to fencing target: %s", target))
		}

		report.AddRecommendation(&check.Result, "Check network configuration and firewall rules")
		report.AddRecommendation(&check.Result, "Ensure fencing devices are powered on and connected to the network")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_troubleshooting-configuring-high-availability-clusters#fence-troubleshooting-configuring-high-availability-clusters", rhelVersion))
	} else if !separateInterface {
		check.Result = report.NewResult(report.StatusWarning,
			"Fencing devices use same network interface as cluster traffic",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Consider using separate network interfaces for fencing")
		report.AddRecommendation(&check.Result, "This provides additional redundancy in case of network failures")

		// Add RHEL documentation reference directly as a link
		report.AddReferenceLink(&check.Result, fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/%s/html/configuring_and_managing_high_availability_clusters/assembly_creating-cluster-configuring-managing-high-availability-clusters", rhelVersion))
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Fencing network is properly configured and reachable",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
