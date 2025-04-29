// pkg/checks/rhel/network.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunNetworkChecks performs network related checks
func RunNetworkChecks(r *report.AsciiDocReport) {
	// Check IP addressing, subnet, gateway, and DNS
	checkNetworkConfig(r)

	// Check bonding or teaming configuration
	checkBondingTeaming(r)

	// Check hostname resolution
	checkHostnameResolution(r)

	// Check MTU and jumbo frame configuration
	checkMTUConfig(r)

	// Check firewall rules
	checkFirewallRules(r)

	// Check TCP/IP stack hardening
	checkTCPIPStackHardening(r)
}

// checkNetworkConfig validates IP addressing, subnet, gateway, and DNS
func checkNetworkConfig(r *report.AsciiDocReport) {
	checkID := "network-config"
	checkName := "Network Configuration"
	checkDesc := "Validates IP addressing, subnet, gateway, and DNS."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get IP configuration
	ipCmd := "ip addr show"
	ipOutput, err := utils.RunCommand("bash", "-c", ipCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine IP configuration", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'ip' command is available.")
		r.AddCheck(check)
		return
	}

	// Get routing information
	routeCmd := "ip route show"
	routeOutput, _ := utils.RunCommand("bash", "-c", routeCmd)

	// Get DNS configuration
	resolvConfCmd := "cat /etc/resolv.conf"
	resolvConfOutput, _ := utils.RunCommand("bash", "-c", resolvConfCmd)

	// Get network interfaces information
	ifconfigCmd := "ifconfig -a 2>/dev/null || echo 'ifconfig not available'"
	ifconfigOutput, _ := utils.RunCommand("bash", "-c", ifconfigCmd)

	// Check if NetworkManager is used
	nmcliCmd := "nmcli device status 2>/dev/null || echo 'nmcli not available'"
	nmcliOutput, _ := utils.RunCommand("bash", "-c", nmcliCmd)

	var detail strings.Builder
	detail.WriteString("IP Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ipOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nRouting Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(routeOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nDNS Configuration:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(resolvConfOutput)
	detail.WriteString("\n----\n")

	if !strings.Contains(ifconfigOutput, "not available") {
		detail.WriteString("\n\nNetwork Interfaces (ifconfig):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(ifconfigOutput)
		detail.WriteString("\n----\n")
	}

	if !strings.Contains(nmcliOutput, "not available") {
		detail.WriteString("\n\nNetworkManager Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(nmcliOutput)
		detail.WriteString("\n----\n")
	}

	// Extract IP configurations
	interfaces := []string{}
	ipAddresses := []string{}

	currentInterface := ""
	for _, line := range strings.Split(ipOutput, "\n") {
		if strings.Contains(line, ": ") && !strings.HasPrefix(line, " ") {
			parts := strings.Split(line, ": ")
			if len(parts) > 1 {
				currentInterface = parts[1]
				interfaces = append(interfaces, currentInterface)
			}
		} else if strings.Contains(line, "inet ") && currentInterface != "" {
			ipAddresses = append(ipAddresses, fmt.Sprintf("%s: %s", currentInterface, strings.TrimSpace(line)))
		}
	}

	// Check for default gateway
	hasDefaultRoute := false
	for _, line := range strings.Split(routeOutput, "\n") {
		if strings.HasPrefix(line, "default") {
			hasDefaultRoute = true
			break
		}
	}

	// Check for DNS servers
	dnsServers := []string{}
	for _, line := range strings.Split(resolvConfOutput, "\n") {
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) > 1 {
				dnsServers = append(dnsServers, parts[1])
			}
		}
	}

	// Check for issues
	networkIssues := []string{}

	if !hasDefaultRoute {
		networkIssues = append(networkIssues, "No default gateway configured")
	}

	if len(dnsServers) == 0 {
		networkIssues = append(networkIssues, "No DNS servers configured")
	}

	// Check if any interfaces have IP addresses (excluding loopback)
	hasNonLoopbackIPs := false
	for _, ip := range ipAddresses {
		if !strings.Contains(ip, "lo:") && !strings.Contains(ip, "127.0.0.1") {
			hasNonLoopbackIPs = true
			break
		}
	}

	if !hasNonLoopbackIPs {
		networkIssues = append(networkIssues, "No non-loopback IP addresses configured")
	}

	// Evaluate network configuration
	if len(networkIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d network configuration issues", len(networkIssues)),
			report.ResultKeyRecommended)

		for _, issue := range networkIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !hasDefaultRoute {
			report.AddRecommendation(&check.Result, "Configure a default gateway using 'ip route add default via GATEWAY_IP'")
		}

		if len(dnsServers) == 0 {
			report.AddRecommendation(&check.Result, "Configure DNS servers in /etc/resolv.conf")
		}

		// Add Red Hat documentation reference
		rhelVersion := utils.GetRedHatVersion()
		docURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/", rhelVersion)
		report.AddReferenceLink(&check.Result, docURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Network configuration appears to be correct",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkBondingTeaming checks bonding or teaming configuration
func checkBondingTeaming(r *report.AsciiDocReport) {
	checkID := "network-bonding"
	checkName := "Network Bonding/Teaming"
	checkDesc := "Checks bonding or teaming configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get RHEL version for documentation references
	rhelVersion := utils.GetRedHatVersion()

	// Use same URL format for both RHEL 8 and 9
	docURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/", rhelVersion)

	// Check for bonding modules
	bondingModulesCmd := "lsmod | grep bonding"
	bondingModulesOutput, _ := utils.RunCommand("bash", "-c", bondingModulesCmd)

	// Check for bonding interfaces
	bondingInterfacesCmd := "ls -l /sys/class/net/*/bonding 2>/dev/null || echo 'No bonding interfaces found'"
	bondingInterfacesOutput, _ := utils.RunCommand("bash", "-c", bondingInterfacesCmd)

	// Check for network teaming
	teamingCmd := "teamdctl status 2>/dev/null || echo 'Teaming not configured'"
	teamingOutput, _ := utils.RunCommand("bash", "-c", teamingCmd)

	// Get bonding details if available
	bondingDetailsCmd := "cat /proc/net/bonding/* 2>/dev/null || echo 'No bonding details available'"
	bondingDetailsOutput, _ := utils.RunCommand("bash", "-c", bondingDetailsCmd)

	// Check if NetworkManager has any teams defined
	nmTeamsCmd := "nmcli connection show 2>/dev/null | grep -E 'team|bond'"
	nmTeamsOutput, _ := utils.RunCommand("bash", "-c", nmTeamsCmd)

	// Count available network interfaces (excluding loopback)
	nicCountCmd := "ip -o link show | grep -v 'LOOPBACK' | wc -l"
	nicCountOutput, _ := utils.RunCommand("bash", "-c", nicCountCmd)
	nicCount := 0
	if count, err := strconv.Atoi(strings.TrimSpace(nicCountOutput)); err == nil {
		nicCount = count
	}

	// Get list of network interfaces for additional context
	interfacesCmd := "ip -o link show | grep -v 'LOOPBACK' | awk -F': ' '{print $2}'"
	interfacesOutput, _ := utils.RunCommand("bash", "-c", interfacesCmd)

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("Detected RHEL Version: %s\n\n", rhelVersion))

	if bondingModulesOutput != "" {
		detail.WriteString("Bonding Module Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(bondingModulesOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("Bonding Module Status: Not loaded\n")
	}

	detail.WriteString("\nBonding Interfaces:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(bondingInterfacesOutput)
	detail.WriteString("\n----\n")

	if !strings.Contains(teamingOutput, "not configured") {
		detail.WriteString("\n\nNetwork Teaming Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(teamingOutput)
		detail.WriteString("\n----\n")
	}

	if !strings.Contains(bondingDetailsOutput, "No bonding details available") {
		detail.WriteString("\n\nBonding Configuration Details:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(bondingDetailsOutput)
		detail.WriteString("\n----\n")
	}

	if nmTeamsOutput != "" {
		detail.WriteString("\n\nNetworkManager Team/Bond Connections:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(nmTeamsOutput)
		detail.WriteString("\n----\n")
	}

	// Add network interface count information
	detail.WriteString("\n\nNetwork Interface Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Total Network Interfaces: %d\n", nicCount))
	detail.WriteString("Available Interfaces:\n")
	detail.WriteString(interfacesOutput)
	detail.WriteString("\n----\n")

	// Determine if bonding or teaming is configured
	hasBonding := strings.Contains(bondingInterfacesOutput, "bonding") ||
		bondingModulesOutput != "" ||
		!strings.Contains(bondingDetailsOutput, "No bonding details available")

	hasTeaming := !strings.Contains(teamingOutput, "not configured") &&
		!strings.Contains(teamingOutput, "No such file or directory")

	hasNmBondOrTeam := nmTeamsOutput != ""

	// Check if there's an actual bonding configuration in place
	actualBondingFound := hasBonding || hasTeaming || hasNmBondOrTeam

	// Check for issues
	bondingIssues := []string{}

	if actualBondingFound {
		// Extract bonding modes if available
		bondingMode := "unknown"
		bondingModeIssue := true

		for _, line := range strings.Split(bondingDetailsOutput, "\n") {
			if strings.Contains(line, "Bonding Mode:") {
				bondingMode = strings.TrimSpace(strings.Split(line, ":")[1])

				// Check if mode is active-backup (mode 1) or 802.3ad (mode 4)
				if strings.Contains(bondingMode, "active-backup") ||
					strings.Contains(bondingMode, "fault tolerance") ||
					strings.Contains(bondingMode, "IEEE 802.3ad") {
					bondingModeIssue = false
				}
			}
		}

		if hasBonding && bondingModeIssue {
			bondingIssues = append(bondingIssues, fmt.Sprintf("Bonding using mode: %s might not be optimal", bondingMode))
		}
	}

	// Evaluate bonding/teaming configuration
	if nicCount <= 1 {
		// If there's only one NIC, bonding is not applicable regardless of other indicators
		check.Result = report.NewResult(report.StatusInfo,
			"Network bonding is not applicable with only one network interface",
			report.ResultKeyNotApplicable)

		// Only add recommendation if they actually need to add NICs for HA
		if actualBondingFound {
			report.AddRecommendation(&check.Result, "Bonding/teaming requires at least two network interfaces")
			report.AddRecommendation(&check.Result, "Add additional network interfaces to enable bonding/teaming")
		}
	} else if actualBondingFound {
		// Only report bonding/teaming if there are at least 2 NICs and actual bonding config is detected
		configType := "Network bonding"
		if hasTeaming {
			configType = "Network teaming"
		} else if hasNmBondOrTeam {
			configType = "NetworkManager bonding/teaming"
		}

		if len(bondingIssues) > 0 {
			check.Result = report.NewResult(report.StatusWarning,
				fmt.Sprintf("%s is configured but has potential issues", configType),
				report.ResultKeyRecommended)

			for _, issue := range bondingIssues {
				report.AddRecommendation(&check.Result, issue)
			}

			report.AddRecommendation(&check.Result, "For high availability, consider using mode 1 (active-backup)")
			report.AddRecommendation(&check.Result, "For performance and HA, consider using mode 4 (802.3ad)")
			report.AddReferenceLink(&check.Result, docURL)
		} else {
			check.Result = report.NewResult(report.StatusOK,
				fmt.Sprintf("%s is properly configured", configType),
				report.ResultKeyNoChange)
		}
	} else {
		// Multiple NICs but no bonding configured
		check.Result = report.NewResult(report.StatusInfo,
			fmt.Sprintf("No network bonding or teaming is configured (found %d network interfaces)", nicCount),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider implementing network bonding or teaming for improved redundancy and performance")
		report.AddRecommendation(&check.Result, "For high availability, use mode 1 (active-backup)")
		report.AddRecommendation(&check.Result, "For performance and HA, consider using mode 4 (802.3ad) if your network infrastructure supports it")
		report.AddReferenceLink(&check.Result, docURL)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkHostnameResolution ensures hostname resolution works correctly
func checkHostnameResolution(r *report.AsciiDocReport) {
	checkID := "hostname-resolution"
	checkName := "Hostname Resolution"
	checkDesc := "Ensures hostname resolution works correctly."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get hostname
	hostnameCmd := "hostname"
	hostnameOutput, err := utils.RunCommand("bash", "-c", hostnameCmd)
	hostname := strings.TrimSpace(hostnameOutput)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine hostname", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'hostname' command is available.")
		r.AddCheck(check)
		return
	}

	// Get fully qualified domain name
	fqdnCmd := "hostname -f 2>/dev/null || echo $HOSTNAME"
	fqdnOutput, _ := utils.RunCommand("bash", "-c", fqdnCmd)
	fqdn := strings.TrimSpace(fqdnOutput)

	// Test hostname resolution
	lookupCmd := fmt.Sprintf("getent hosts %s", hostname)
	lookupOutput, lookupErr := utils.RunCommand("bash", "-c", lookupCmd)

	// Test FQDN resolution
	fqdnLookupCmd := fmt.Sprintf("getent hosts %s", fqdn)
	fqdnLookupOutput, fqdnLookupErr := utils.RunCommand("bash", "-c", fqdnLookupCmd)

	// Check hosts file
	hostsFileCmd := "cat /etc/hosts"
	hostsFileOutput, _ := utils.RunCommand("bash", "-c", hostsFileCmd)

	// Check DNS resolution
	dnsCmd := "cat /etc/resolv.conf"
	dnsOutput, _ := utils.RunCommand("bash", "-c", dnsCmd)

	var detail strings.Builder
	detail.WriteString("Hostname Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(fmt.Sprintf("Hostname: %s\n", hostname))
	detail.WriteString(fmt.Sprintf("FQDN: %s\n", fqdn))
	detail.WriteString("\n----\n")

	detail.WriteString("\nHostname Resolution Lookup:\n")
	detail.WriteString("[source, bash]\n----\n")
	if lookupErr == nil {
		detail.WriteString(lookupOutput)
	} else {
		detail.WriteString("Failed to resolve hostname\n")
	}
	detail.WriteString("\n----\n")

	detail.WriteString("\nFQDN Resolution Lookup:\n")
	detail.WriteString("[source, bash]\n----\n")
	if fqdnLookupErr == nil {
		detail.WriteString(fqdnLookupOutput)
	} else {
		detail.WriteString("Failed to resolve FQDN\n")
	}
	detail.WriteString("\n----\n")

	detail.WriteString("\n/etc/hosts File:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(hostsFileOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n/etc/resolv.conf File:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(dnsOutput)
	detail.WriteString("\n----\n")

	// Check for resolution issues
	resolutionIssues := []string{}

	if lookupErr != nil && fqdnLookupErr != nil {
		resolutionIssues = append(resolutionIssues, "Neither hostname nor FQDN resolves")
	} else if lookupErr != nil {
		resolutionIssues = append(resolutionIssues, "Hostname does not resolve, but FQDN does")
	} else if fqdnLookupErr != nil && fqdn != hostname {
		resolutionIssues = append(resolutionIssues, "FQDN does not resolve, but hostname does")
	}

	// Check if hostname is in /etc/hosts
	hostnameInHosts := strings.Contains(hostsFileOutput, hostname)
	if !hostnameInHosts && (lookupErr != nil || fqdnLookupErr != nil) {
		resolutionIssues = append(resolutionIssues, "Hostname not found in /etc/hosts")
	}

	// Evaluate hostname resolution
	if len(resolutionIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d hostname resolution issues", len(resolutionIssues)),
			report.ResultKeyRecommended)

		for _, issue := range resolutionIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		if !hostnameInHosts {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Add hostname to /etc/hosts: '127.0.0.1 %s %s'", hostname, fqdn))
		}

		report.AddRecommendation(&check.Result, "Ensure DNS or local hostname resolution is properly configured")

		// Red Hat version-specific hostname configuration docs
		rhelVersion := utils.GetRedHatVersion()
		docURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/", rhelVersion)
		report.AddReferenceLink(&check.Result, docURL)
		report.AddRecommendation(&check.Result, "Use 'hostnamectl' command to set your system hostname permanently")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Hostname resolution is working correctly",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkMTUConfig checks MTU and jumbo frame configuration
func checkMTUConfig(r *report.AsciiDocReport) {
	checkID := "network-mtu"
	checkName := "MTU Configuration"
	checkDesc := "Reviews MTU and jumbo frame configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get RHEL version for documentation
	rhelVersion := utils.GetRedHatVersion()

	// Build documentation URL for MTU configuration
	docURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/", rhelVersion)

	// Get interface MTU values
	mtuCmd := "ip link show | grep -E 'mtu|state'"
	mtuOutput, err := utils.RunCommand("bash", "-c", mtuCmd)

	if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine interface MTU values", report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure the 'ip' command is available.")
		r.AddCheck(check)
		return
	}

	// Check interface configuration files
	ifcfgFilesCmd := "ls -l /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null || echo 'No ifcfg files found'"
	ifcfgFilesOutput, _ := utils.RunCommand("bash", "-c", ifcfgFilesCmd)

	// Get MTU from ifcfg files
	ifcfgMtuCmd := "grep -i MTU /etc/sysconfig/network-scripts/ifcfg-* 2>/dev/null || echo 'No MTU settings found in ifcfg files'"
	ifcfgMtuOutput, _ := utils.RunCommand("bash", "-c", ifcfgMtuCmd)

	// Get NetworkManager connection details if available
	nmMtuCmd := "nmcli -g connection.id,802-3-ethernet.mtu connection show 2>/dev/null || echo 'NetworkManager not available'"
	nmMtuOutput, _ := utils.RunCommand("bash", "-c", nmMtuCmd)

	var detail strings.Builder
	detail.WriteString("Interface MTU Values:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(mtuOutput)
	detail.WriteString("\n----\n")

	detail.WriteString("\n\nNetwork Configuration Files:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ifcfgFilesOutput)
	detail.WriteString("\n----\n")

	if !strings.Contains(ifcfgMtuOutput, "No MTU settings") {
		detail.WriteString("\n\nMTU Settings in Network Scripts:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(ifcfgMtuOutput)
		detail.WriteString("\n----\n")
	}

	if !strings.Contains(nmMtuOutput, "not available") {
		detail.WriteString("\n\nNetworkManager MTU Settings:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(nmMtuOutput)
		detail.WriteString("\n----\n")
	}

	// Check if any interface has jumbo frames enabled
	jumboFramesEnabled := false
	mtuConsistent := true
	interfaceMtus := map[string]int{}
	physicalInterfacesWithJumbo := []string{}

	// Parse MTU values from ip link output
	currentIface := ""
	for _, line := range strings.Split(mtuOutput, "\n") {
		if strings.Contains(line, ": ") && !strings.HasPrefix(line, " ") {
			parts := strings.Split(line, ": ")
			if len(parts) > 1 {
				currentIface = strings.TrimSpace(parts[1])
			}
		}

		if strings.Contains(line, "mtu") && currentIface != "" {
			// Skip loopback interface
			if currentIface == "lo" || strings.Contains(line, "LOOPBACK") {
				continue
			}

			mtuParts := strings.Split(line, "mtu ")
			if len(mtuParts) > 1 {
				// Extract MTU value (may be followed by other parameters)
				mtuValStr := strings.Split(mtuParts[1], " ")[0]
				mtuVal, err := strconv.Atoi(mtuValStr)
				if err == nil {
					interfaceMtus[currentIface] = mtuVal

					if mtuVal > 1500 {
						jumboFramesEnabled = true
						physicalInterfacesWithJumbo = append(physicalInterfacesWithJumbo, currentIface)
					}
				}
			}
		}
	}

	// Check for MTU consistency (only for non-loopback interfaces)
	prevMtu := 0
	for _, mtu := range interfaceMtus {
		if prevMtu == 0 {
			prevMtu = mtu
		} else if mtu != prevMtu && mtu != 1500 && prevMtu != 1500 {
			// Inconsistent MTU values (excluding standard 1500)
			mtuConsistent = false
			break
		}
	}

	// List physical interfaces with jumbo frames
	if len(physicalInterfacesWithJumbo) > 0 {
		detail.WriteString("\n\nPhysical Interfaces with Jumbo Frames:\n")
		detail.WriteString("[source, bash]\n----\n")
		for _, iface := range physicalInterfacesWithJumbo {
			detail.WriteString(fmt.Sprintf("%s: MTU %d\n", iface, interfaceMtus[iface]))
		}
		detail.WriteString("\n----\n")
	}

	// Check for multicast firewall rules
	firewallMulticastCmd := "iptables -L -n | grep -i multicast || firewall-cmd --list-all | grep -i multicast || echo 'No multicast firewall rules found'"
	firewallMulticastOutput, _ := utils.RunCommand("bash", "-c", firewallMulticastCmd)

	detail.WriteString("\n\nFirewall Multicast Rules:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(firewallMulticastOutput)
	detail.WriteString("\n----\n")

	// Check for issues
	mtuIssues := []string{}

	if jumboFramesEnabled && !mtuConsistent {
		mtuIssues = append(mtuIssues, "Jumbo frames enabled but MTU values are inconsistent across interfaces")
	}

	if jumboFramesEnabled && strings.Contains(ifcfgMtuOutput, "No MTU settings") &&
		strings.Contains(nmMtuOutput, "not available") {
		mtuIssues = append(mtuIssues, "Jumbo frames enabled but not configured in network scripts or NetworkManager")
	}

	// Evaluate MTU configuration
	if len(mtuIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d MTU configuration issues", len(mtuIssues)),
			report.ResultKeyRecommended)

		for _, issue := range mtuIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Ensure consistent MTU values across all network devices")
		report.AddRecommendation(&check.Result, "Add MTU settings to interface configuration files for persistence")
		report.AddReferenceLink(&check.Result, docURL)
	} else if jumboFramesEnabled {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("Jumbo frames are properly configured on %d interfaces", len(physicalInterfacesWithJumbo)),
			report.ResultKeyNoChange)
	} else {
		check.Result = report.NewResult(report.StatusInfo,
			"Standard MTU (1500) is used on all interfaces",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkFirewallRules confirms firewall rules are consistent with expectations
func checkFirewallRules(r *report.AsciiDocReport) {
	checkID := "firewall-rules"
	checkName := "Firewall Rules"
	checkDesc := "Confirms firewall rules are consistent with expectations."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get RHEL version for documentation
	rhelVersion := utils.GetRedHatVersion()

	// Build documentation URL for firewall configuration
	docURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/configuring_and_managing_networking/", rhelVersion)

	// Get firewalld status
	firewalldCmd := "systemctl is-active firewalld"
	firewalldOutput, _ := utils.RunCommand("bash", "-c", firewalldCmd)
	firewalldActive := strings.TrimSpace(firewalldOutput) == "active"

	// Check if iptables service is running
	iptablesCmd := "systemctl is-active iptables"
	iptablesOutput, _ := utils.RunCommand("bash", "-c", iptablesCmd)
	iptablesActive := strings.TrimSpace(iptablesOutput) == "active"

	// Get firewalld status
	firewallStatusCmd := "firewall-cmd --list-all 2>/dev/null || echo 'firewall-cmd not available'"
	firewallStatusOutput, _ := utils.RunCommand("bash", "-c", firewallStatusCmd)

	// Get iptables rules
	iptablesRulesCmd := "iptables -L -n -v 2>/dev/null || echo 'iptables command not available'"
	iptablesRulesOutput, _ := utils.RunCommand("bash", "-c", iptablesRulesCmd)

	// Check for open ports
	openPortsCmd := "ss -tuln | grep LISTEN"
	openPortsOutput, _ := utils.RunCommand("bash", "-c", openPortsCmd)

	// Check for multicast firewall rules
	firewallMulticastCmd := "iptables -L -n | grep -i multicast || firewall-cmd --list-all | grep -i multicast || echo 'No multicast firewall rules found'"
	firewallMulticastOutput, _ := utils.RunCommand("bash", "-c", firewallMulticastCmd)

	var detail strings.Builder
	detail.WriteString(fmt.Sprintf("FirewallD Active: %v\n", firewalldActive))
	detail.WriteString(fmt.Sprintf("IPTables Service Active: %v\n", iptablesActive))

	if !strings.Contains(firewallStatusOutput, "not available") {
		detail.WriteString("\nFirewallD Configuration:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(firewallStatusOutput)
		detail.WriteString("\n----\n")
	}

	if !strings.Contains(iptablesRulesOutput, "not available") {
		detail.WriteString("\nIPTables Rules:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(iptablesRulesOutput)
		detail.WriteString("\n----\n")
	}

	detail.WriteString("\nOpen Ports:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(openPortsOutput)
	detail.WriteString("\n----\n")

	// Still including the multicast rules information in the report
	detail.WriteString("\nMulticast Firewall Rules:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(firewallMulticastOutput)
	detail.WriteString("\n----\n")

	// Determine if any firewall is running
	firewallRunning := firewalldActive || iptablesActive

	// Check if SSH is allowed
	sshAllowed := false
	if strings.Contains(firewallStatusOutput, "ssh") ||
		strings.Contains(firewallStatusOutput, "22") ||
		strings.Contains(iptablesRulesOutput, "ssh") ||
		strings.Contains(iptablesRulesOutput, "22") ||
		strings.Contains(openPortsOutput, ":22") {
		sshAllowed = true
	}

	// Check if firewall rules exist at all
	hasFirewallRules := false
	if !strings.Contains(firewallStatusOutput, "not available") &&
		(strings.Contains(firewallStatusOutput, "services:") ||
			strings.Contains(firewallStatusOutput, "ports:")) {
		hasFirewallRules = true
	}

	if !strings.Contains(iptablesRulesOutput, "not available") &&
		!strings.Contains(iptablesRulesOutput, "Chain INPUT (policy ACCEPT") {
		hasFirewallRules = true
	}

	// Evaluate firewall rules
	if !firewallRunning {
		check.Result = report.NewResult(report.StatusWarning,
			"No firewall service is active",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Start and enable firewalld: 'systemctl enable --now firewalld'")
		report.AddRecommendation(&check.Result, "Configure appropriate firewall rules for your services")
		report.AddReferenceLink(&check.Result, docURL)
	} else if !hasFirewallRules {
		check.Result = report.NewResult(report.StatusWarning,
			"Firewall is running but no rules are configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure firewall rules for your services")
		report.AddRecommendation(&check.Result, "For firewalld: 'firewall-cmd --permanent --add-service=<service>'")
		report.AddReferenceLink(&check.Result, docURL)
	} else if !sshAllowed {
		check.Result = report.NewResult(report.StatusWarning,
			"SSH access may not be allowed through the firewall",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure SSH access is allowed: 'firewall-cmd --permanent --add-service=ssh'")
		report.AddRecommendation(&check.Result, "Reload firewall rules: 'firewall-cmd --reload'")
		report.AddReferenceLink(&check.Result, docURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Firewall is active with appropriate rules",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkTCPIPStackHardening validates TCP/IP stack security settings
func checkTCPIPStackHardening(r *report.AsciiDocReport) {
	checkID := "network-tcp-ip-hardening"
	checkName := "TCP/IP Stack Hardening"
	checkDesc := "Checks TCP/IP stack security parameters."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryNetworking)

	// Get RHEL version for documentation
	rhelVersion := utils.GetRedHatVersion()

	// Build documentation URL
	docURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/", rhelVersion)

	// Define critical sysctl settings to check
	criticalSettings := map[string]string{
		"net.ipv4.tcp_syncookies":                   "1",
		"net.ipv4.conf.all.rp_filter":               "1",
		"net.ipv4.conf.default.rp_filter":           "1",
		"net.ipv4.icmp_echo_ignore_broadcasts":      "1",
		"net.ipv4.conf.all.accept_redirects":        "0",
		"net.ipv4.conf.default.accept_redirects":    "0",
		"net.ipv4.conf.all.secure_redirects":        "0",
		"net.ipv4.conf.default.secure_redirects":    "0",
		"net.ipv4.conf.all.accept_source_route":     "0",
		"net.ipv4.conf.default.accept_source_route": "0",
		"net.ipv4.ip_forward":                       "0", // Should be 0 unless system is a router/NAT
	}

	// Get current sysctl settings
	sysctlCmd := "sysctl -a 2>/dev/null | grep -E '" + strings.Join(getKeys(criticalSettings), "|") + "'"
	sysctlOutput, err := utils.RunCommand("bash", "-c", sysctlCmd)

	var detail strings.Builder
	detail.WriteString("TCP/IP Stack Security Settings:\n")

	if err != nil {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString("Failed to retrieve sysctl settings: " + err.Error())
		detail.WriteString("\n----\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Failed to determine TCP/IP stack security settings",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Ensure sysctl command is available")
		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sysctlOutput)
	detail.WriteString("\n----\n\n")

	// Parse current sysctl values
	currentSettings := make(map[string]string)
	for _, line := range strings.Split(sysctlOutput, "\n") {
		if line == "" {
			continue
		}
		parts := strings.SplitN(line, "=", 2)
		if len(parts) == 2 {
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(parts[1])
			currentSettings[key] = value
		}
	}

	// Check for persistence in sysctl.conf
	sysctlConfCmd := "grep -E '" + strings.Join(getKeys(criticalSettings), "|") + "' /etc/sysctl.conf /etc/sysctl.d/*.conf 2>/dev/null || echo 'No persistent settings found'"
	sysctlConfOutput, _ := utils.RunCommand("bash", "-c", sysctlConfCmd)

	detail.WriteString("Persistent TCP/IP Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(sysctlConfOutput)
	detail.WriteString("\n----\n\n")

	// Check for IPv6 status
	ipv6Cmd := "sysctl -a 2>/dev/null | grep -E 'net.ipv6.conf.all.disable_ipv6' || echo 'IPv6 settings not found'"
	ipv6Output, _ := utils.RunCommand("bash", "-c", ipv6Cmd)

	detail.WriteString("IPv6 Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(ipv6Output)
	detail.WriteString("\n----\n")

	// Check if system might be a router/NAT (e.g., has IP forwarding enabled)
	isRouter := false
	if val, ok := currentSettings["net.ipv4.ip_forward"]; ok && val == "1" {
		isRouter = true

		// If it's a router, we need to check additional NAT/masquerade settings
		natCmd := "iptables -t nat -L -n -v 2>/dev/null | grep -i masq || echo 'No NAT configuration found'"
		natOutput, _ := utils.RunCommand("bash", "-c", natCmd)

		detail.WriteString("\nNAT/Masquerading Configuration:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(natOutput)
		detail.WriteString("\n----\n")
	}

	// Create summary table of settings
	detail.WriteString("\n{set:cellbgcolor!}\n")
	detail.WriteString("TCP/IP Security Setting Summary:\n")
	detail.WriteString("|===\n")
	detail.WriteString("|Parameter|Current Value|Expected Value|Status\n\n")

	missingSettings := []string{}
	incorrectSettings := []string{}

	for param, expectedValue := range criticalSettings {
		// Skip ip_forward check if this is a router
		if param == "net.ipv4.ip_forward" && isRouter {
			detail.WriteString(fmt.Sprintf("|%s|1|1 (Router/NAT detected)|OK\n", param))
			continue
		}

		currentValue, found := currentSettings[param]
		if !found {
			detail.WriteString(fmt.Sprintf("|%s|Not set|%s|Missing\n", param, expectedValue))
			missingSettings = append(missingSettings, param)
		} else if currentValue != expectedValue {
			detail.WriteString(fmt.Sprintf("|%s|%s|%s|Incorrect\n", param, currentValue, expectedValue))
			incorrectSettings = append(incorrectSettings, param)
		} else {
			detail.WriteString(fmt.Sprintf("|%s|%s|%s|OK\n", param, currentValue, expectedValue))
		}
	}

	detail.WriteString("|===\n")

	// Evaluate TCP/IP stack security
	if len(incorrectSettings) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d incorrect TCP/IP security settings", len(incorrectSettings)),
			report.ResultKeyRecommended)

		report.AddRecommendation(&check.Result, "Update the following sysctl parameters to recommended values:")

		for _, param := range incorrectSettings {
			if isRouter && param == "net.ipv4.ip_forward" {
				continue // Skip recommendation for ip_forward if router
			}
			expValue := criticalSettings[param]
			report.AddRecommendation(&check.Result, fmt.Sprintf("Set %s = %s", param, expValue))
		}

		report.AddRecommendation(&check.Result, "Apply settings with: 'sysctl -p' and make them persistent in /etc/sysctl.conf")
		report.AddReferenceLink(&check.Result, docURL)
	} else if len(missingSettings) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d missing TCP/IP security settings", len(missingSettings)),
			report.ResultKeyRecommended)

		report.AddRecommendation(&check.Result, "Configure the following sysctl parameters:")

		for _, param := range missingSettings {
			if isRouter && param == "net.ipv4.ip_forward" {
				continue // Skip recommendation for ip_forward if router
			}
			expValue := criticalSettings[param]
			report.AddRecommendation(&check.Result, fmt.Sprintf("Set %s = %s", param, expValue))
		}

		report.AddRecommendation(&check.Result, "Apply settings with: 'sysctl -p' and make them persistent in /etc/sysctl.conf")
		report.AddReferenceLink(&check.Result, docURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"TCP/IP stack security settings are properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// Helper function to get keys from map
func getKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		// Escape dots for grep
		escaped := strings.ReplaceAll(k, ".", "\\.")
		keys = append(keys, escaped)
	}
	return keys
}
