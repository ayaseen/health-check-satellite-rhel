// pkg/checks/satellite/capsule.go

package satellite

import (
	"fmt"
	"strings"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunCapsuleChecks performs Satellite capsule health checks
func RunCapsuleChecks(r *report.AsciiDocReport) {
	// Check capsule status and connectivity
	checkCapsuleStatus(r)

	// Check pulp content synchronization
	checkPulpSyncStatus(r)

	// Check capsule certificate expiry
	checkCapsuleCerts(r)

	// Check content synchronization status for standalone capsules
	checkCapsuleSyncStatus(r)
}

// checkCapsuleStatus checks if capsules are properly registered and connected
func checkCapsuleStatus(r *report.AsciiDocReport) {
	checkID := "satellite-capsule-status"
	checkName := "Capsule Status"
	checkDesc := "Checks if all capsules are properly registered and connected."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of all capsules
	capsulesCmd := "hammer capsule list"
	capsulesOutput, err := utils.RunCommand("bash", "-c", capsulesCmd)

	var detail strings.Builder
	detail.WriteString("Capsules Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving capsules:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve capsule information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_capsule_server/",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("Registered Capsules:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(capsulesOutput)
	detail.WriteString("\n----\n\n")

	// Count capsules and check their features
	totalCapsules := 0
	problemCapsules := 0
	defaultCapsule := false

	// Parse the output to identify capsules
	lines := strings.Split(capsulesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			totalCapsules++

			// Check for problems
			if strings.Contains(line, "not connected") {
				problemCapsules++
			}
		}
	}

	// Check if the Satellite itself is registered as the default capsule
	// The default capsule is typically the Satellite itself with Life Cycle features enabled
	defaultCapsuleCmd := "hammer capsule info --id 1 | grep 'Features\\|Pulp\\|Lifecycle'"
	defaultCapsuleOutput, _ := utils.RunCommand("bash", "-c", defaultCapsuleCmd)

	// If we find Pulp or Lifecycle Environment features, consider it as default capsule
	if strings.Contains(defaultCapsuleOutput, "Pulp") ||
		strings.Contains(defaultCapsuleOutput, "Pulpcore") ||
		strings.Contains(defaultCapsuleOutput, "Lifecycle") {
		defaultCapsule = true
	}

	// Check detailed capsule info for each capsule
	if totalCapsules > 0 {
		// Extract capsule IDs
		capsuleIDsCmd := "hammer capsule list --fields id,name,url | grep -v '^--\\|^ID' | awk '{print $1}'"
		capsuleIDsOutput, _ := utils.RunCommand("bash", "-c", capsuleIDsCmd)
		capsuleIDs := strings.Split(strings.TrimSpace(capsuleIDsOutput), "\n")

		detail.WriteString("Detailed Capsule Information:\n\n")

		// Limit to maximum 3 capsules to keep report concise
		maxCapsulesShown := 3
		capsulesShown := 0

		for _, id := range capsuleIDs {
			if id == "" {
				continue
			}

			if capsulesShown >= maxCapsulesShown {
				detail.WriteString("(More capsules exist - output limited)\n\n")
				break
			}

			capsuleInfoCmd := fmt.Sprintf("hammer capsule info --id %s", id)
			capsuleInfoOutput, _ := utils.RunCommand("bash", "-c", capsuleInfoCmd)

			// Check if this capsule has content features which would make it a default
			if !defaultCapsule && (strings.Contains(capsuleInfoOutput, "Pulp") ||
				strings.Contains(capsuleInfoOutput, "Pulpcore") ||
				strings.Contains(capsuleInfoOutput, "Content") ||
				strings.Contains(capsuleInfoOutput, "Lifecycle")) {
				defaultCapsule = true
			}

			detail.WriteString(fmt.Sprintf("Capsule ID: %s\n\n", id))
			detail.WriteString("[source, text]\n----\n")
			detail.WriteString(capsuleInfoOutput)
			detail.WriteString("\n----\n\n")

			capsulesShown++
		}
	}

	// Check for smart proxies as well
	smartProxiesCmd := "hammer proxy list"
	smartProxiesOutput, _ := utils.RunCommand("bash", "-c", smartProxiesCmd)

	// If we have Pulpcore or content in the smart proxy, it's likely a default capsule
	if !defaultCapsule && (strings.Contains(smartProxiesOutput, "Pulp") ||
		strings.Contains(smartProxiesOutput, "Pulpcore")) {
		defaultCapsule = true
	}

	detail.WriteString("Smart Proxies:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(smartProxiesOutput)
	detail.WriteString("\n----\n\n")

	// Check Foreman Tasks status
	foremanTasksCmd := "hammer ping foreman"
	foremanTasksOutput, _ := utils.RunCommand("bash", "-c", foremanTasksCmd)

	detail.WriteString("Foreman Status:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(foremanTasksOutput)
	detail.WriteString("\n----\n\n")

	// Check Katello/Pulp status
	pulpStatusCmd := "hammer ping katello"
	pulpStatusOutput, _ := utils.RunCommand("bash", "-c", pulpStatusCmd)

	detail.WriteString("Katello/Pulp Status:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(pulpStatusOutput)
	detail.WriteString("\n----\n\n")

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Capsule Status Summary:\n\n")
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Value\n")
	detail.WriteString(fmt.Sprintf("|Total Capsules|%d\n", totalCapsules))
	detail.WriteString(fmt.Sprintf("|Problem Capsules|%d\n", problemCapsules))
	detail.WriteString(fmt.Sprintf("|Default Capsule Present|%s\n", boolToYesNo(defaultCapsule)))

	// Check Pulp service health
	pulpHealthy := strings.Contains(pulpStatusOutput, "Status: ok") ||
		strings.Contains(pulpStatusOutput, "Status: OK") ||
		strings.Contains(pulpStatusOutput, "Status:          ok")
	detail.WriteString(fmt.Sprintf("|Pulp Service Healthy|%s\n", boolToYesNo(pulpHealthy)))
	detail.WriteString("|===\n\n")

	// Evaluate results
	if totalCapsules == 0 {
		check.Result = report.NewResult(report.StatusOK,
			"No external capsules detected, which is normal for a standalone Satellite",
			report.ResultKeyNoChange)
	} else if problemCapsules > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d out of %d capsules have connectivity issues", problemCapsules, totalCapsules),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check network connectivity to problematic capsules")
		report.AddRecommendation(&check.Result, "Verify capsule certificates are valid")
		report.AddRecommendation(&check.Result, "Restart capsule services: satellite-maintain service restart --only qdrouterd,foreman-proxy")
	} else if !defaultCapsule {
		check.Result = report.NewResult(report.StatusWarning,
			"No default capsule detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Configure a default capsule for content distribution")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("All %d capsules appear to be properly connected", totalCapsules),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_capsule_server/",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1542213") // Capsule troubleshooting

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkPulpSyncStatus checks if Pulp content is properly synchronized to capsules
func checkPulpSyncStatus(r *report.AsciiDocReport) {
	checkID := "satellite-pulp-sync"
	checkName := "Pulp Content Synchronization"
	checkDesc := "Checks if Pulp content is properly synchronized to capsules."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check for recent content sync tasks
	syncTasksCmd := "hammer task list --search 'action = \"Sync Repository on Capsule(s)\" and state != stopped' --per-page 10"
	syncTasksOutput, err := utils.RunCommand("bash", "-c", syncTasksCmd)

	var detail strings.Builder
	detail.WriteString("Pulp Content Synchronization Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving sync tasks:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))
	} else {
		detail.WriteString("Current Sync Tasks:\n\n")
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(syncTasksOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check recent completed sync tasks
	completedSyncCmd := "hammer task list --search 'action = \"Sync Repository on Capsule(s)\" and result = success' --order='started_at DESC' --per-page 10"
	completedSyncOutput, _ := utils.RunCommand("bash", "-c", completedSyncCmd)

	detail.WriteString("Recent Completed Sync Tasks:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(completedSyncOutput)
	detail.WriteString("\n----\n\n")

	// Check for sync errors
	syncErrorsCmd := "hammer task list --search 'action = \"Sync Repository on Capsule(s)\" and result != success' --order='started_at DESC' --per-page 10"
	syncErrorsOutput, _ := utils.RunCommand("bash", "-c", syncErrorsCmd)

	detail.WriteString("Recent Sync Errors:\n\n")
	if !strings.Contains(syncErrorsOutput, "No tasks found") {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(syncErrorsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No recent sync errors found\n\n")
	}

	// Get capsule and content sync status using methods compatible with Satellite 6.15

	// Method 3: Check repository sync status - works in all versions
	repoSyncCmd := "hammer repository list --fields id,name,content_type,sync_state,last_sync_words --per-page 20"
	repoSyncOutput, _ := utils.RunCommand("bash", "-c", repoSyncCmd)

	// Method 4: Check content view publish/promote status for content flow
	cvPublishCmd := "hammer task list --fields action,state,result,started_at --search 'label = Actions::Katello::ContentView::Publish' --order='started_at DESC' --per-page 5"
	cvPublishOutput, _ := utils.RunCommand("bash", "-c", cvPublishCmd)

	cvPromoteCmd := "hammer task list --fields action,state,result,started_at --search 'label = Actions::Katello::ContentView::Promote' --order='started_at DESC' --per-page 5"
	cvPromoteOutput, _ := utils.RunCommand("bash", "-c", cvPromoteCmd)

	// Method 5: Check service status for both pulp and pulpcore (for compatibility)
	pulpStatusCmd := "systemctl status 'pulp*' 2>/dev/null || echo 'No pulp services found'"
	pulpStatusOutput, _ := utils.RunCommand("bash", "-c", pulpStatusCmd)

	// Method 6: Use hammer ping to check overall service health
	pingCmd := "hammer ping"
	pingOutput, _ := utils.RunCommand("bash", "-c", pingCmd)

	// Add additional sync status information
	detail.WriteString("Repository Sync Status:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(repoSyncOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Content View Publication Status (Recent):\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(cvPublishOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Content View Promotion Status (Recent):\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(cvPromoteOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Pulp Service Status:\n\n")
	if strings.Contains(pulpStatusOutput, "No pulp services found") {
		detail.WriteString("No pulp services found\n\n")
	} else {
		// Format pulp services as a table
		detail.WriteString("{set:cellbgcolor!}\n")
		detail.WriteString("|===\n")
		detail.WriteString("|Service|Status|Active|Description\n\n")

		// Parse the systemctl output to create table rows
		lines := strings.Split(pulpStatusOutput, "\n")
		currentService := ""
		status := ""
		active := ""
		description := ""

		for _, line := range lines {
			if strings.Contains(line, ".service") {
				// If we had a previous service, write it out
				if currentService != "" {
					detail.WriteString(fmt.Sprintf("|%s|%s|%s|%s\n",
						currentService, status, active, description))
				}

				// Start a new service entry
				parts := strings.Fields(line)
				if len(parts) > 0 {
					currentService = parts[0]
					status = "Unknown"
					active = "Unknown"
					description = ""
				}
			} else if strings.Contains(line, "Active:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					activeInfo := strings.TrimSpace(parts[1])
					if strings.Contains(activeInfo, "active (running)") {
						status = "Running"
						active = "Yes"
					} else if strings.Contains(activeInfo, "inactive (dead)") {
						status = "Stopped"
						active = "No"
					} else if strings.Contains(activeInfo, "failed") {
						status = "Failed"
						active = "No"
					} else {
						status = activeInfo
						active = "Unknown"
					}
				}
			} else if strings.TrimSpace(line) != "" && description == "" {
				// Try to get a description from the line
				description = strings.TrimSpace(line)
			}
		}

		// Add the last service if there was one
		if currentService != "" {
			detail.WriteString(fmt.Sprintf("|%s|%s|%s|%s\n",
				currentService, status, active, description))
		}

		detail.WriteString("|===\n\n")
	}

	detail.WriteString("Overall Service Health:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(pingOutput)
	detail.WriteString("\n----\n\n")

	// Analyze results
	hasRunningTasks := !strings.Contains(syncTasksOutput, "No tasks found")
	hasSuccessfulSyncs := !strings.Contains(completedSyncOutput, "No tasks found") &&
		strings.Contains(completedSyncOutput, "success")
	hasSyncErrors := !strings.Contains(syncErrorsOutput, "No tasks found")

	// Check for repository sync issues
	repoSyncIssues := strings.Contains(repoSyncOutput, "failed") ||
		strings.Contains(repoSyncOutput, "never synced")

	// Check for running/recent content view publications/promotions
	hasRecentCVActivity := !strings.Contains(cvPublishOutput, "No tasks found") ||
		!strings.Contains(cvPromoteOutput, "No tasks found")

	// Check for service health
	serviceIssues := strings.Contains(pingOutput, "FAIL") ||
		strings.Contains(pulpStatusOutput, "failed")

	// Count failures and successes
	failedSyncs := 0
	successfulSyncs := 0

	if !strings.Contains(completedSyncOutput, "No tasks found") {
		lines := strings.Split(completedSyncOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "| success |") {
				successfulSyncs++
			} else if strings.Contains(line, "| error |") || strings.Contains(line, "| warning |") {
				failedSyncs++
			}
		}
	}

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Sync Status Summary:\n\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Value\n")
	detail.WriteString(fmt.Sprintf("|Running Sync Tasks|%s\n", boolToYesNo(hasRunningTasks)))
	detail.WriteString(fmt.Sprintf("|Successful Recent Syncs|%d\n", successfulSyncs))
	detail.WriteString(fmt.Sprintf("|Failed Recent Syncs|%d\n", failedSyncs))
	detail.WriteString(fmt.Sprintf("|Sync Errors Present|%s\n", boolToYesNo(hasSyncErrors)))
	detail.WriteString(fmt.Sprintf("|Repository Sync Issues|%s\n", boolToYesNo(repoSyncIssues)))
	detail.WriteString(fmt.Sprintf("|Recent Content View Activity|%s\n", boolToYesNo(hasRecentCVActivity)))
	detail.WriteString(fmt.Sprintf("|Service Health Issues|%s\n", boolToYesNo(serviceIssues)))
	detail.WriteString("|===\n\n")

	// Evaluate results with checks compatible with Satellite 6.15
	if hasSyncErrors && failedSyncs > successfulSyncs {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Capsule content sync issues detected (%d failed tasks)", failedSyncs),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate sync failures in the tasks page of the Satellite web UI")
		report.AddRecommendation(&check.Result, "Check network connectivity between Satellite and capsules")
		report.AddRecommendation(&check.Result, "Verify sufficient disk space on capsules")
	} else if serviceIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Pulp service or content service health issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check pulp services with systemctl status pulp*")
		report.AddRecommendation(&check.Result, "Review /var/log/messages and /var/log/foreman/production.log for errors")
		report.AddRecommendation(&check.Result, "Consider restarting pulp services: satellite-maintain service restart --only pulp")
	} else if repoSyncIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Repository sync issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check repositories that have never been synced or have failed syncs")
		report.AddRecommendation(&check.Result, "Verify network connectivity to repository sources")
		report.AddRecommendation(&check.Result, "Check for SSL certificate issues with external repositories")
	} else if hasSyncErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Some capsule content sync errors detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Monitor sync tasks for recurring issues")
	} else if !hasSuccessfulSyncs && !hasRunningTasks && !hasRecentCVActivity {
		check.Result = report.NewResult(report.StatusWarning,
			"No recent content synchronization activity detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify content is being synchronized to capsules regularly")
		report.AddRecommendation(&check.Result, "Check if content views are being published and promoted")
		report.AddRecommendation(&check.Result, "For external capsules, run 'hammer capsule content synchronize --id <CAPSULE_ID>' to manually trigger a sync")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Content synchronization appears to be working properly",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_content/managing_ansible_content",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1619193") // Satellite content synchronization troubleshooting

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkCapsuleCerts checks the status of capsule certificates
func checkCapsuleCerts(r *report.AsciiDocReport) {
	checkID := "satellite-capsule-certs"
	checkName := "Capsule Certificates"
	checkDesc := "Checks the status of capsule certificates."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of all capsules
	capsulesCmd := "hammer capsule list"
	capsulesOutput, _ := utils.RunCommand("bash", "-c", capsulesCmd)

	var detail strings.Builder
	detail.WriteString("Capsule Certificate Status:\n\n")

	detail.WriteString("Registered Capsules:\n\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(capsulesOutput)
	detail.WriteString("\n----\n\n")

	// Look for capsule certificate info in installer logs without showing full certificate content
	certInfoCmd := "grep -r \"capsule.*cert\" /var/log/foreman-installer/ | grep -v BEGIN | grep -v KEY | tail -20"
	certInfoOutput, _ := utils.RunCommand("bash", "-c", certInfoCmd)

	detail.WriteString("Capsule Certificate Information from Logs:\n\n")
	if certInfoOutput == "" {
		detail.WriteString("No certificate information found in installer logs\n\n")
	} else {
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(certInfoOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check for any certificate generation/expiry issues in logs
	certIssuesCmd := "grep -r \"certificate.*expire\\|cert.*invalid\" /var/log/messages /var/log/foreman-installer/ 2>/dev/null | tail -20"
	certIssuesOutput, _ := utils.RunCommand("bash", "-c", certIssuesCmd)

	// Check for certs directory
	certsCmd := "find /etc/pki -name '*capsule*' -o -name '*foreman-proxy*' | head -10"
	certsOutput, _ := utils.RunCommand("bash", "-c", certsCmd)

	detail.WriteString("Capsule Certificate Files:\n\n")
	if certsOutput == "" {
		detail.WriteString("No capsule certificate files found\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(certsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check capsule certificate expiry (for the first capsule certificate found)
	// But only show the expiration dates, not the full certificate
	certExpiry := []string{}
	hasCertIssues := false
	certificateExpired := false
	certNearExpiry := false

	if certsOutput != "" {
		certFiles := strings.Split(certsOutput, "\n")
		detail.WriteString("Certificate Expiration Information:\n\n")
		detail.WriteString("[source, text]\n----\n")

		for i, certFile := range certFiles {
			if certFile == "" || i >= 5 { // Limit to first 5 certificates
				continue
			}

			// Get only the notBefore and notAfter dates
			expiryCmd := fmt.Sprintf("openssl x509 -noout -dates -in %s 2>/dev/null || echo 'Not a valid certificate'", certFile)
			expiryOutput, _ := utils.RunCommand("bash", "-c", expiryCmd)

			if !strings.Contains(expiryOutput, "Not a valid certificate") {
				// Extract just the filename for display
				filename := certFile
				if parts := strings.Split(certFile, "/"); len(parts) > 0 {
					filename = parts[len(parts)-1]
				}

				detail.WriteString(fmt.Sprintf("Certificate: %s\n", filename))

				// Process expiry information
				for _, line := range strings.Split(expiryOutput, "\n") {
					if strings.HasPrefix(line, "notBefore=") || strings.HasPrefix(line, "notAfter=") {
						detail.WriteString(line + "\n")
						certExpiry = append(certExpiry, line)

						// Check if certificate is expiring soon or expired
						if strings.HasPrefix(line, "notAfter=") {
							// Parse the date to check for expiry
							dateStr := strings.TrimPrefix(line, "notAfter=")
							expiryDate, err := time.Parse("Jan 2 15:04:05 2006 MST", dateStr)

							if err == nil {
								// Check if certificate is expired
								if time.Now().After(expiryDate) {
									certNearExpiry = false
									certificateExpired = true
								} else {
									// Check if certificate expires in less than 90 days
									daysUntilExpiry := expiryDate.Sub(time.Now()).Hours() / 24
									if daysUntilExpiry < 90 {
										certNearExpiry = true
									}
								}
							}
						}
					}
				}
				detail.WriteString("\n")
			} else {
				detail.WriteString(fmt.Sprintf("File %s: Not a valid certificate\n\n", certFile))
				hasCertIssues = true
			}
		}
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("Could not find any certificate files to check expiration\n\n")
	}

	// Create a summary table
	detail.WriteString("{set:cellbgcolor!}\n")
	detail.WriteString("Certificate Status Summary:\n\n")
	detail.WriteString("[cols=\"2,1\", options=\"header\"]\n|===\n")
	detail.WriteString("|Item|Status\n")
	detail.WriteString(fmt.Sprintf("|Certificate Files Present|%s\n", boolToYesNo(certsOutput != "")))
	detail.WriteString(fmt.Sprintf("|Certificate Issues in Logs|%s\n", boolToYesNo(certIssuesOutput != "")))

	if certNearExpiry {
		detail.WriteString("|Certificate Expiry|Near expiry (< 90 days)\n")
	} else if certificateExpired {
		detail.WriteString("|Certificate Expiry|Expired\n")
	} else if len(certExpiry) > 0 {
		detail.WriteString("|Certificate Expiry|Valid\n")
	}

	detail.WriteString("|===\n\n")

	// Determine if there are issues - only when there are actual problems
	// FIX: Modified to not treat log mentions of certificates as issues unless there are actual problems
	hasCertIssues = hasCertIssues || certNearExpiry || certificateExpired

	// Evaluate results
	if certificateExpired {
		check.Result = report.NewResult(report.StatusWarning,
			"One or more capsule certificates have expired",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Regenerate expired certificates immediately")
		report.AddRecommendation(&check.Result, "Use satellite-installer --help to find options for regenerating certificates")
	} else if certNearExpiry {
		check.Result = report.NewResult(report.StatusWarning,
			"One or more capsule certificates will expire soon",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Plan to regenerate certificates before they expire")
		report.AddRecommendation(&check.Result, "Use satellite-installer --help to find options for regenerating certificates")
	} else if hasCertIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Potential capsule certificate issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review certificate issues in logs")
		report.AddRecommendation(&check.Result, "Consider regenerating capsule certificates if they are invalid")
		report.AddRecommendation(&check.Result, "Use satellite-installer --help to find options for regenerating certificates")
	} else if certInfoOutput == "" && certsOutput == "" {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not find information about capsule certificates",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Verify capsules are properly registered")
		report.AddRecommendation(&check.Result, "Check if this is a standalone Satellite without capsules")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No issues detected with capsule certificates",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_capsule_server/configuring_capsule_server",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/3047891") // Capsule certificate troubleshooting

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkCapsuleSyncStatus checks content synchronization status for standalone capsules
func checkCapsuleSyncStatus(r *report.AsciiDocReport) {
	checkID := "satellite-capsule-sync-status"
	checkName := "Capsule Sync Status"
	checkDesc := "Checks content synchronization status for standalone capsules."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of all capsules
	capsulesCmd := "hammer capsule list"
	capsulesOutput, err := utils.RunCommand("bash", "-c", capsulesCmd)

	var detail strings.Builder
	detail.WriteString("Capsule Content Sync Status:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving capsules:\n")
		detail.WriteString(fmt.Sprintf("```\n%s\n```\n\n", err.Error()))

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve capsule information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/installing_capsule_server/",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	// Extract capsule IDs
	var capsuleIDs []string
	lines := strings.Split(capsulesOutput, "\n")
	for _, line := range lines {
		if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
			fields := strings.Fields(line)
			if len(fields) > 0 {
				capsuleIDs = append(capsuleIDs, fields[0])
			}
		}
	}

	// Create a map to store standalone capsule info
	standaloneCapsules := make(map[string]map[string]string)
	standaloneCapsuleCount := 0
	syncIssuesCount := 0

	// Check each capsule for sync status
	for _, id := range capsuleIDs {
		if id == "" {
			continue
		}

		syncStatusCmd := fmt.Sprintf("hammer capsule content synchronization-status --id %s 2>&1", id)
		syncStatusOutput, _ := utils.RunCommand("bash", "-c", syncStatusCmd)

		// Skip integrated capsules which return this message
		if strings.Contains(syncStatusOutput, "This request may only be performed on a Capsule that has the Pulpcore feature with mirror=true") {
			detail.WriteString(fmt.Sprintf("Capsule ID %s: Integrated capsule (skipping)\n\n", id))
			continue
		}

		// This appears to be a standalone capsule
		standaloneCapsuleCount++

		// Extract capsule name for better reporting
		capsuleInfoCmd := fmt.Sprintf("hammer capsule info --id %s | grep Name", id)
		capsuleInfoOutput, _ := utils.RunCommand("bash", "-c", capsuleInfoCmd)
		capsuleName := "Unknown"
		if infoFields := strings.Fields(capsuleInfoOutput); len(infoFields) >= 3 {
			capsuleName = infoFields[2]
		}

		// Store capsule info
		capsuleInfo := make(map[string]string)
		capsuleInfo["name"] = capsuleName
		capsuleInfo["sync_status"] = syncStatusOutput

		// Parse important sync status fields
		lastSyncTime := "Unknown"
		syncStatus := "Unknown"
		runningTasks := "None"
		lastFailure := "None"

		for _, line := range strings.Split(syncStatusOutput, "\n") {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "Last sync:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					lastSyncTime = strings.TrimSpace(parts[1])
				}
			} else if strings.HasPrefix(line, "Status:") {
				parts := strings.SplitN(line, ":", 2)
				if len(parts) > 1 {
					syncStatus = strings.TrimSpace(parts[1])
				}
			} else if strings.Contains(line, "Task id:") && strings.Contains(syncStatusOutput, "Currently running sync tasks:") {
				runningTasks = "Yes"
			} else if strings.Contains(line, "Messages:") && strings.Contains(syncStatusOutput, "Last failure:") {
				lastFailure = "Yes"
				syncIssuesCount++
			}
		}

		capsuleInfo["last_sync"] = lastSyncTime
		capsuleInfo["status"] = syncStatus
		capsuleInfo["running_tasks"] = runningTasks
		capsuleInfo["last_failure"] = lastFailure

		standaloneCapsules[id] = capsuleInfo

		// Add detailed sync status to the report
		detail.WriteString(fmt.Sprintf("Capsule ID %s (%s):\n", id, capsuleName))
		detail.WriteString("[source, text]\n----\n")
		detail.WriteString(syncStatusOutput)
		detail.WriteString("\n----\n\n")
	}

	// Create a summary table
	if standaloneCapsuleCount > 0 {
		detail.WriteString("{set:cellbgcolor!}\n")
		detail.WriteString("Standalone Capsule Sync Summary:\n\n")
		detail.WriteString("[cols=\"1,2,2,1,1,1\", options=\"header\"]\n|===\n")
		detail.WriteString("|ID|Name|Last Sync|Status|Running Tasks|Last Failure\n\n")

		for id, info := range standaloneCapsules {
			detail.WriteString(fmt.Sprintf("|%s|%s|%s|%s|%s|%s\n",
				id,
				info["name"],
				info["last_sync"],
				info["status"],
				info["running_tasks"],
				info["last_failure"]))
		}

		detail.WriteString("|===\n\n")
	} else {
		detail.WriteString("No standalone capsules detected. Only integrated capsules found.\n\n")
	}

	// Evaluate capsule sync status
	if standaloneCapsuleCount == 0 {
		check.Result = report.NewResult(report.StatusInfo,
			"No standalone capsules detected",
			report.ResultKeyNotApplicable)
	} else if syncIssuesCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Sync issues detected on %d out of %d standalone capsules", syncIssuesCount, standaloneCapsuleCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate sync failures on affected capsules")
		report.AddRecommendation(&check.Result, "Check network connectivity between Satellite and capsules")
		report.AddRecommendation(&check.Result, "Verify DNS resolution for all capsules")
		report.AddRecommendation(&check.Result, "Run 'hammer capsule content synchronize --id <CAPSULE_ID>' to manually trigger a sync")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("All %d standalone capsules are synchronized", standaloneCapsuleCount),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_content/managing_content_with_capsule_servers_managing-content",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/solutions/1260183") // Troubleshooting content synchronization

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
