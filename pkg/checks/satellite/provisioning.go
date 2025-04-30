// pkg/checks/satellite/provisioning.go

package satellite

import (
	"fmt"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunProvisioningChecks performs Satellite provisioning checks
func RunProvisioningChecks(r *report.AsciiDocReport) {
	// Check provisioning templates and settings
	checkProvisioningTemplates(r)

	// Check compute resources
	checkComputeResources(r)

	// Check DHCP/DNS/TFTP services
	checkNetworkServices(r)
}

// checkProvisioningTemplates checks provisioning templates and settings
func checkProvisioningTemplates(r *report.AsciiDocReport) {
	checkID := "satellite-provisioning-templates"
	checkName := "Provisioning Templates"
	checkDesc := "Checks provisioning templates and settings."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get provisioning templates
	templatesCmd := "hammer template list --per-page 20"
	templatesOutput, err := utils.RunCommand("bash", "-c", templatesCmd)

	var detail strings.Builder
	detail.WriteString("Provisioning Templates Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving provisioning templates:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve provisioning templates",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/provisioning_hosts/configuring_provisioning_resources_provisioning",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("Provisioning Templates (sample):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(templatesOutput)
	detail.WriteString("\n----\n\n")

	// Check partition tables
	partitionsCmd := "hammer partition-table list"
	partitionsOutput, _ := utils.RunCommand("bash", "-c", partitionsCmd)

	detail.WriteString("Partition Tables:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(partitionsOutput)
	detail.WriteString("\n----\n\n")

	// Check operating systems
	osCmd := "hammer os list"
	osOutput, _ := utils.RunCommand("bash", "-c", osCmd)

	detail.WriteString("Operating Systems:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(osOutput)
	detail.WriteString("\n----\n\n")

	// Check installation media
	mediaCmd := "hammer medium list"
	mediaOutput, _ := utils.RunCommand("bash", "-c", mediaCmd)

	detail.WriteString("Installation Media:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(mediaOutput)
	detail.WriteString("\n----\n\n")

	// Check for custom templates
	customTemplatesCmd := "hammer template list --search 'locked = false'"
	customTemplatesOutput, _ := utils.RunCommand("bash", "-c", customTemplatesCmd)

	detail.WriteString("Custom (Unlocked) Templates:\n")
	if strings.Contains(customTemplatesOutput, "No templates found") {
		detail.WriteString("No custom templates found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(customTemplatesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check provisioning settings
	provisioningSettingsCmd := "hammer settings list --search 'name ~ provision'"
	provisioningSettingsOutput, _ := utils.RunCommand("bash", "-c", provisioningSettingsCmd)

	detail.WriteString("Provisioning Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(provisioningSettingsOutput)
	detail.WriteString("\n----\n")

	// Count templates by type
	totalTemplates := 0
	provisionTemplates := 0
	kickstartTemplates := 0
	pxeLinuxTemplates := 0
	customTemplates := 0

	// Count templates
	lines := strings.Split(templatesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			totalTemplates++

			if strings.Contains(strings.ToLower(line), "provision") {
				provisionTemplates++
			}
			if strings.Contains(strings.ToLower(line), "kickstart") {
				kickstartTemplates++
			}
			if strings.Contains(strings.ToLower(line), "pxelinux") {
				pxeLinuxTemplates++
			}
		}
	}

	// Count custom templates
	lines = strings.Split(customTemplatesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			customTemplates++
		}
	}

	// Evaluate results
	provisioningEnabled := provisionTemplates > 0 && kickstartTemplates > 0 && pxeLinuxTemplates > 0
	hasCustomizations := customTemplates > 0

	if !provisioningEnabled {
		check.Result = report.NewResult(report.StatusWarning,
			"Incomplete provisioning template configuration",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify all required provisioning templates are present")
		report.AddRecommendation(&check.Result, "Configure PXE, kickstart, and provisioning templates")
	} else if hasCustomizations {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d custom provisioning templates detected", customTemplates),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Document custom template changes for future reference")
		report.AddRecommendation(&check.Result, "Consider using Satellite's template sync feature to track changes")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d standard provisioning templates configured", totalTemplates),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/provisioning_hosts/configuring_provisioning_resources_provisioning",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkComputeResources checks compute resources configuration
func checkComputeResources(r *report.AsciiDocReport) {
	checkID := "satellite-compute-resources"
	checkName := "Compute Resources"
	checkDesc := "Checks compute resources configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get compute resources
	resourcesCmd := "hammer compute-resource list"
	resourcesOutput, err := utils.RunCommand("bash", "-c", resourcesCmd)

	var detail strings.Builder
	detail.WriteString("Compute Resources Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving compute resources:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve compute resources",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/provisioning_hosts/index",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	detail.WriteString("Compute Resources:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(resourcesOutput)
	detail.WriteString("\n----\n\n")

	// Get compute profiles
	profilesCmd := "hammer compute-profile list"
	profilesOutput, _ := utils.RunCommand("bash", "-c", profilesCmd)

	detail.WriteString("Compute Profiles:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(profilesOutput)
	detail.WriteString("\n----\n\n")

	// Check compute resource providers
	providersCmd := "hammer compute-resource list --fields id,name,provider"
	providersOutput, _ := utils.RunCommand("bash", "-c", providersCmd)

	detail.WriteString("Compute Resource Providers:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(providersOutput)
	detail.WriteString("\n----\n\n")

	// Try to get detailed info about compute resources if available
	resourceDetailCmd := "hammer compute-resource list --fields id,name,provider | grep -v '^--\\|^ID' | awk '{print $1}' | head -1"
	resourceIDOutput, _ := utils.RunCommand("bash", "-c", resourceDetailCmd)
	resourceID := strings.TrimSpace(resourceIDOutput)

	if resourceID != "" {
		resourceDetailCmd = fmt.Sprintf("hammer compute-resource info --id %s", resourceID)
		resourceDetailOutput, _ := utils.RunCommand("bash", "-c", resourceDetailCmd)

		detail.WriteString("Sample Compute Resource Detail:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(resourceDetailOutput)
		detail.WriteString("\n----\n")
	} else {
		detail.WriteString("No compute resources available for detailed info\n\n")
	}

	// Count compute resources and types
	totalResources := 0
	vmwareResources := 0
	libvirtResources := 0
	openstackResources := 0
	awsResources := 0
	azureResources := 0
	gcpResources := 0

	lines := strings.Split(providersOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			totalResources++

			if strings.Contains(strings.ToLower(line), "vmware") {
				vmwareResources++
			} else if strings.Contains(strings.ToLower(line), "libvirt") {
				libvirtResources++
			} else if strings.Contains(strings.ToLower(line), "openstack") {
				openstackResources++
			} else if strings.Contains(strings.ToLower(line), "ec2") || strings.Contains(strings.ToLower(line), "aws") {
				awsResources++
			} else if strings.Contains(strings.ToLower(line), "azure") {
				azureResources++
			} else if strings.Contains(strings.ToLower(line), "gce") || strings.Contains(strings.ToLower(line), "gcp") {
				gcpResources++
			}
		}
	}

	// Determine compute resource status
	hasComputeResources := totalResources > 0

	// Evaluate results
	if !hasComputeResources {
		check.Result = report.NewResult(report.StatusWarning,
			"No compute resources configured",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Configure compute resources if using Satellite for provisioning")
		report.AddRecommendation(&check.Result, "If provisioning is not needed, this can be ignored")
	} else {
		providerInfo := []string{}
		if vmwareResources > 0 {
			providerInfo = append(providerInfo, fmt.Sprintf("%d VMware", vmwareResources))
		}
		if libvirtResources > 0 {
			providerInfo = append(providerInfo, fmt.Sprintf("%d Libvirt", libvirtResources))
		}
		if openstackResources > 0 {
			providerInfo = append(providerInfo, fmt.Sprintf("%d OpenStack", openstackResources))
		}
		if awsResources > 0 {
			providerInfo = append(providerInfo, fmt.Sprintf("%d AWS", awsResources))
		}
		if azureResources > 0 {
			providerInfo = append(providerInfo, fmt.Sprintf("%d Azure", azureResources))
		}
		if gcpResources > 0 {
			providerInfo = append(providerInfo, fmt.Sprintf("%d GCP", gcpResources))
		}

		providersStr := strings.Join(providerInfo, ", ")

		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d compute resources configured (%s)", totalResources, providersStr),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/provisioning_hosts/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkNetworkServices checks DHCP/DNS/TFTP services
func checkNetworkServices(r *report.AsciiDocReport) {
	checkID := "satellite-network-services"
	checkName := "Network Services"
	checkDesc := "Checks DHCP/DNS/TFTP services for provisioning."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Network Services Analysis:\n\n")

	// Check subnets
	subnetsCmd := "hammer subnet list"
	subnetsOutput, err := utils.RunCommand("bash", "-c", subnetsCmd)

	if err != nil {
		detail.WriteString("Error retrieving subnet information:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")
	} else {
		detail.WriteString("Subnets:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(subnetsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check domains
	domainsCmd := "hammer domain list"
	domainsOutput, _ := utils.RunCommand("bash", "-c", domainsCmd)

	detail.WriteString("Domains:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(domainsOutput)
	detail.WriteString("\n----\n\n")

	// Check DHCP configuration
	dhcpSettingsCmd := "hammer settings list --search 'name ~ dhcp'"
	dhcpSettingsOutput, _ := utils.RunCommand("bash", "-c", dhcpSettingsCmd)

	detail.WriteString("DHCP Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(dhcpSettingsOutput)
	detail.WriteString("\n----\n\n")

	// Check DNS configuration
	dnsSettingsCmd := "hammer settings list --search 'name ~ dns'"
	dnsSettingsOutput, _ := utils.RunCommand("bash", "-c", dnsSettingsCmd)

	detail.WriteString("DNS Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(dnsSettingsOutput)
	detail.WriteString("\n----\n\n")

	// Check TFTP configuration
	tftpSettingsCmd := "hammer settings list --search 'name ~ tftp'"
	tftpSettingsOutput, _ := utils.RunCommand("bash", "-c", tftpSettingsCmd)

	detail.WriteString("TFTP Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(tftpSettingsOutput)
	detail.WriteString("\n----\n\n")

	// Check proxy features (which DHCP/DNS/TFTP services are managed)
	proxyFeaturesCmd := "hammer proxy list --fields id,name,url,features"
	proxyFeaturesOutput, _ := utils.RunCommand("bash", "-c", proxyFeaturesCmd)

	detail.WriteString("Proxy Features:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(proxyFeaturesOutput)
	detail.WriteString("\n----\n")

	// Check for enabled network services
	hasDHCP := strings.Contains(proxyFeaturesOutput, "DHCP")
	hasDNS := strings.Contains(proxyFeaturesOutput, "DNS")
	hasTFTP := strings.Contains(proxyFeaturesOutput, "TFTP")
	hasSubnets := !strings.Contains(subnetsOutput, "No subnets found")
	hasDomains := !strings.Contains(domainsOutput, "No domains found")

	enabledServices := []string{}
	if hasDHCP {
		enabledServices = append(enabledServices, "DHCP")
	}
	if hasDNS {
		enabledServices = append(enabledServices, "DNS")
	}
	if hasTFTP {
		enabledServices = append(enabledServices, "TFTP")
	}

	// Count subnets and domains
	subnetCount := 0
	domainCount := 0

	lines := strings.Split(subnetsOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			subnetCount++
		}
	}

	lines = strings.Split(domainsOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			domainCount++
		}
	}

	// Evaluate results
	allServicesEnabled := hasDHCP && hasDNS && hasTFTP
	someServicesEnabled := len(enabledServices) > 0
	hasNetworkConfig := hasSubnets && hasDomains

	if allServicesEnabled && hasNetworkConfig {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("All network services (DHCP, DNS, TFTP) enabled with %d subnets and %d domains", subnetCount, domainCount),
			report.ResultKeyNoChange)
	} else if someServicesEnabled && hasNetworkConfig {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Partial network services enabled: %s", strings.Join(enabledServices, ", ")),
			report.ResultKeyAdvisory)

		if !hasDHCP {
			report.AddRecommendation(&check.Result, "Consider enabling DHCP for complete provisioning support")
		}
		if !hasDNS {
			report.AddRecommendation(&check.Result, "Consider enabling DNS for complete provisioning support")
		}
		if !hasTFTP {
			report.AddRecommendation(&check.Result, "Consider enabling TFTP for complete provisioning support")
		}
	} else if someServicesEnabled && !hasNetworkConfig {
		check.Result = report.NewResult(report.StatusWarning,
			"Network services enabled but subnets/domains not configured",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure subnets and domains for provisioning")
	} else {
		check.Result = report.NewResult(report.StatusWarning,
			"Network services for provisioning not configured",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "If provisioning is needed, configure DHCP, DNS and TFTP services")
		report.AddRecommendation(&check.Result, "If provisioning is not needed, this can be ignored")
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/provisioning_hosts/configuring_networking_provisioning",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
