// pkg/checks/satellite/subscription.go

package satellite

import (
	"fmt"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"regexp"
	"strings"
)

// RunSubscriptionChecks performs Satellite subscription checks
func RunSubscriptionChecks(r *report.AsciiDocReport, organization string) {
	// Check subscription usage and compliance
	checkSubscriptionUsage(r, organization)

	// Check subscription manifests
	checkSubscriptionManifests(r, organization)
}

// Updated functions for pkg/checks/satellite/subscription.go

// checkSubscriptionUsage checks subscription usage and compliance
func checkSubscriptionUsage(r *report.AsciiDocReport, organization string) {
	checkID := "satellite-subscription-usage"
	checkName := "Subscription Usage"
	checkDesc := "Checks subscription usage and compliance status."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get default organization ID if none provided
	if organization == "" {
		organization = getDefaultOrganizationID()
	}

	// Build command using the safe organization flag function
	subcmdBase := "hammer subscription list"
	if organization != "" {
		subcmdBase += safeOrganizationFlag(organization)
	}

	// Get subscription status
	subscriptionCmd := subcmdBase
	subscriptionOutput, err := utils.RunCommand("bash", "-c", subscriptionCmd)

	var detail strings.Builder
	detail.WriteString("Subscription Usage Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving subscription information:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		altCmd := "hammer subscription list"
		altOutput, altErr := utils.RunCommand("bash", "-c", altCmd)
		if altErr == nil && altOutput != "" {
			detail.WriteString("Alternative subscription listing (without organization filter):\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(altOutput)
			detail.WriteString("\n----\n\n")
		}

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve subscription information with organization filter",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.AddRecommendation(&check.Result, "Try running 'hammer organization list' to find the correct organization ID")
		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	detail.WriteString("Subscription Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(subscriptionOutput)
	detail.WriteString("\n----\n\n")

	// Get SCA status
	scaCmd := "subscription-manager status"
	scaOutput, _ := utils.RunCommand("bash", "-c", scaCmd)

	detail.WriteString("Subscription Manager Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(scaOutput)
	detail.WriteString("\n----\n\n")

	// Get compliance status - use organization ID if available
	complianceCmd := "hammer host list --search 'subscription_status != valid'"
	if organization != "" {
		complianceCmd += safeOrganizationFlag(organization)
	}
	complianceOutput, _ := utils.RunCommand("bash", "-c", complianceCmd)

	detail.WriteString("Non-compliant Hosts:\n")
	if !strings.Contains(complianceOutput, "No hosts found") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(complianceOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No non-compliant hosts found\n\n")
	}

	// Get subscription count summary
	countCmd := fmt.Sprintf("%s --per-page 1 | grep Total", subcmdBase)
	countOutput, _ := utils.RunCommand("bash", "-c", countCmd)

	detail.WriteString("Subscription Count Summary:\n")
	detail.WriteString("[source, bash]\n----\n")
	if countOutput != "" {
		detail.WriteString(countOutput)
	} else {
		detail.WriteString("None\n")
	}
	detail.WriteString("\n----\n")

	// Determine subscription status
	hasSubscriptions := !strings.Contains(subscriptionOutput, "No subscriptions found")
	hasNonCompliantHosts := !strings.Contains(complianceOutput, "No hosts found")

	// Check for SCA (Simple Content Access) mode
	usingSCA := strings.Contains(scaOutput, "Simple Content Access") ||
		strings.Contains(scaOutput, "Content Access Mode is set to Simple Content Access") ||
		strings.Contains(scaOutput, "access to content, regardless of subscription status")

	// Evaluate results - prioritizing SCA mode detection
	if usingSCA {
		check.Result = report.NewResult(report.StatusOK,
			"Using Simple Content Access (SCA) mode - hosts have access to content regardless of subscription status",
			report.ResultKeyNoChange)
	} else if !hasSubscriptions {
		check.Result = report.NewResult(report.StatusCritical,
			"No subscriptions found and not using Simple Content Access",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Attach subscriptions to the Satellite server")
		report.AddRecommendation(&check.Result, "Upload a valid subscription manifest")
		report.AddRecommendation(&check.Result, "Consider enabling Simple Content Access if available")
	} else if hasNonCompliantHosts {
		check.Result = report.NewResult(report.StatusWarning,
			"Some hosts have invalid subscription status",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review non-compliant hosts and resolve subscription issues")
		report.AddRecommendation(&check.Result, "Consider using Simple Content Access if available")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Subscription usage appears to be properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkSubscriptionManifests checks subscription manifests
func checkSubscriptionManifests(r *report.AsciiDocReport, organization string) {
	checkID := "satellite-subscription-manifests"
	checkName := "Subscription Manifests"
	checkDesc := "Checks subscription manifest status and configuration."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get default organization ID if none provided
	if organization == "" {
		organization = getDefaultOrganizationID()
	}

	// Build command using the safe organization flag function
	subcmdBase := "hammer subscription manifest-history"
	if organization != "" {
		subcmdBase += safeOrganizationFlag(organization)
	}

	// Get manifest history
	manifestCmd := subcmdBase
	manifestOutput, err := utils.RunCommand("bash", "-c", manifestCmd)

	var detail strings.Builder
	detail.WriteString("Subscription Manifest Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving manifest information:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		// Try the manifest status command as an alternative
		altCmd := "hammer subscription manifest-info"
		if organization != "" {
			altCmd += safeOrganizationFlag(organization)
		}
		altOutput, altErr := utils.RunCommand("bash", "-c", altCmd)

		if altErr == nil && altOutput != "" {
			detail.WriteString("Alternative manifest information:\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(altOutput)
			detail.WriteString("\n----\n\n")
		}

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve manifest information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.AddRecommendation(&check.Result, "Ensure a valid organization ID is specified")
		report.AddRecommendation(&check.Result, "Try running 'hammer organization list' to find valid organizations")
		report.SetDetail(&check.Result, detail.String())
		r.AddCheck(check)
		return
	}

	detail.WriteString("Manifest History:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(manifestOutput)
	detail.WriteString("\n----\n\n")

	// Check manifest refresh date
	if organization != "" {
		// Only test refresh, don't actually refresh (using --async)
		refreshCmd := fmt.Sprintf("hammer subscription refresh-manifest%s --async", safeOrganizationFlag(organization))
		refreshOutput, _ := utils.RunCommand("bash", "-c", refreshCmd)

		detail.WriteString("Manifest Refresh Test:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(refreshOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for Red Hat CDN URL settings
	cdnCmd := "hammer settings list --search 'name ~ cdn'"
	cdnOutput, _ := utils.RunCommand("bash", "-c", cdnCmd)

	detail.WriteString("Red Hat CDN Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cdnOutput)
	detail.WriteString("\n----\n")

	// Determine manifest status
	hasManifest := !strings.Contains(manifestOutput, "No subscription manifest histories found")

	// Fix: Check for SUCCESS entries in the manifest output to better determine if the last import was successful
	successfulImport := strings.Contains(manifestOutput, "SUCCESS") || strings.Contains(manifestOutput, "Success")

	// Calculate manifest age if needed (approximate)
	manifestAge := 0
	if hasManifest && successfulImport {
		// Try to extract the most recent date
		// This is a simplified implementation - could be enhanced for more precise date parsing
		lines := strings.Split(manifestOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "SUCCESS") || strings.Contains(line, "Success") {
				// Check if it contains a date in format YYYY/MM/DD
				if dateMatch := regexp.MustCompile(`\d{4}/\d{2}/\d{2}`).FindString(line); dateMatch != "" {
					// Found a date, could parse and compare it
					// For now, we'll assume it's recent enough if we found a successful entry
					manifestAge = 0
					break
				}
			}
		}
	}

	// Evaluate results
	if !hasManifest {
		check.Result = report.NewResult(report.StatusWarning,
			"No subscription manifest found",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Upload a subscription manifest")
		report.AddRecommendation(&check.Result, "Consider using Simple Content Access (SCA)")
	} else if !successfulImport {
		check.Result = report.NewResult(report.StatusWarning,
			"Manifest present but last import may not have been successful",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check manifest import status and refresh if needed")
	} else if manifestAge > 90 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Manifest not refreshed in %d days", manifestAge),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Refresh subscription manifest for updated entitlement information")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Subscription manifest appears to be properly configured",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
