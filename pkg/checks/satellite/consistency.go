// pkg/checks/satellite/consistency.go

package satellite

import (
	"fmt"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
	"strings"
)

// RunConsistencyChecks performs Satellite consistency checks
func RunConsistencyChecks(r *report.AsciiDocReport) {
	// Check content view and repository consistency
	checkContentViewConsistency(r)

	// Check host and subscription consistency
	checkHostSubscriptionConsistency(r)
}

// checkContentViewConsistency checks consistency between content views and repositories
func checkContentViewConsistency(r *report.AsciiDocReport) {
	checkID := "satellite-content-consistency"
	checkName := "Content View Consistency"
	checkDesc := "Checks for consistency between content views, repositories, and published content."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get list of content views
	cvCmd := "hammer content-view list --fields id,name,composite,repository_ids"
	cvOutput, err := utils.RunCommand("bash", "-c", cvCmd)

	var detail strings.Builder
	detail.WriteString("Content View Consistency Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving content view information:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not retrieve content view information for consistency checks",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify hammer CLI is working properly")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_content/managing_content_views",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("Content Views:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(cvOutput)
	detail.WriteString("\n----\n\n")

	// Get repository information
	repoCmd := "hammer repository list --fields id,name,content_type,product_id"
	repoOutput, _ := utils.RunCommand("bash", "-c", repoCmd)

	detail.WriteString("Repositories:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(repoOutput)
	detail.WriteString("\n----\n\n")

	// Check for orphaned content views (no repositories)
	orphanedCVsCmd := "hammer content-view list --search 'repository_ids = null'"
	orphanedCVsOutput, _ := utils.RunCommand("bash", "-c", orphanedCVsCmd)

	detail.WriteString("Orphaned Content Views (no repositories):\n")
	if !strings.Contains(orphanedCVsOutput, "No content views found") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(orphanedCVsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No orphaned content views found\n\n")
	}

	// Check for content view issues in logs
	cvIssuesCmd := "grep -i 'content view.*error\\|content view.*fail' /var/log/foreman/production.log | tail -20"
	cvIssuesOutput, _ := utils.RunCommand("bash", "-c", cvIssuesCmd)

	detail.WriteString("Content View Issues in Logs:\n")
	if cvIssuesOutput == "" {
		detail.WriteString("No content view issues found in logs\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(cvIssuesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Calculate consistency status
	hasOrphanedCVs := !strings.Contains(orphanedCVsOutput, "No content views found")
	hasCVIssues := cvIssuesOutput != ""

	// Evaluate results
	if hasOrphanedCVs && hasCVIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Content view consistency issues detected",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review orphaned content views and consider cleanup")
		report.AddRecommendation(&check.Result, "Check logs for content view errors")
	} else if hasOrphanedCVs {
		check.Result = report.NewResult(report.StatusWarning,
			"Orphaned content views detected",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review and clean up unused content views")
	} else if hasCVIssues {
		check.Result = report.NewResult(report.StatusWarning,
			"Content view errors detected in logs",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate content view errors in logs")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Content view consistency appears good",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_content/managing_content_views",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkHostSubscriptionConsistency checks consistency between hosts and subscriptions
func checkHostSubscriptionConsistency(r *report.AsciiDocReport) {
	checkID := "satellite-host-subscription-consistency"
	checkName := "Host Subscription Consistency"
	checkDesc := "Checks for consistency between hosts and their subscriptions."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteContent)

	// Get subscription status
	subStatusCmd := "hammer subscription list-status"
	subStatusOutput, err := utils.RunCommand("bash", "-c", subStatusCmd)

	var detail strings.Builder
	detail.WriteString("Host Subscription Consistency Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving subscription status:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")
	} else {
		detail.WriteString("Subscription Status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(subStatusOutput)
		detail.WriteString("\n----\n\n")
	}

	// Get hosts without subscriptions
	hostsNoSubsCmd := "hammer host list --search 'subscription_status = invalid'"
	hostsNoSubsOutput, _ := utils.RunCommand("bash", "-c", hostsNoSubsCmd)

	detail.WriteString("Hosts Without Valid Subscriptions:\n")
	if !strings.Contains(hostsNoSubsOutput, "No hosts found") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(hostsNoSubsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No hosts with invalid subscriptions found\n\n")
	}

	// Check for subscription errors in logs
	subErrorsCmd := "grep -i 'subscription.*error\\|candlepin.*error' /var/log/foreman/production.log | tail -20"
	subErrorsOutput, _ := utils.RunCommand("bash", "-c", subErrorsCmd)

	detail.WriteString("Subscription Errors in Logs:\n")
	if subErrorsOutput == "" {
		detail.WriteString("No subscription errors found in logs\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(subErrorsOutput)
		detail.WriteString("\n----\n\n")
	}

	// Calculate consistency status
	hasHostsNoSubs := !strings.Contains(hostsNoSubsOutput, "No hosts found")
	hasSubErrors := subErrorsOutput != ""

	// Count hosts without subs
	hostsNoSubsCount := 0
	if hasHostsNoSubs {
		lines := strings.Split(hostsNoSubsOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
				hostsNoSubsCount++
			}
		}
	}

	// Evaluate results
	if hasHostsNoSubs && hostsNoSubsCount > 5 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d hosts have invalid subscription status", hostsNoSubsCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review hosts with invalid subscriptions")
		report.AddRecommendation(&check.Result, "Consider using Subscription Manager to register hosts properly")
	} else if hasSubErrors {
		check.Result = report.NewResult(report.StatusWarning,
			"Subscription errors detected in logs",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate subscription errors in logs")
	} else if hasHostsNoSubs {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d hosts have invalid subscription status", hostsNoSubsCount),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Review hosts with invalid subscriptions")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Host and subscription consistency appears good",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/configuring_host_management",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/subscription_central/")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// RunOrchestrationChecks performs Satellite orchestration checks
func RunOrchestrationChecks(r *report.AsciiDocReport) {
	// Check for remote execution capability
	checkRemoteExecution(r)

	// Check for job templates and schedules
	checkJobTemplates(r)
}

// checkRemoteExecution checks remote execution capability
func checkRemoteExecution(r *report.AsciiDocReport) {
	checkID := "satellite-remote-execution"
	checkName := "Remote Execution"
	checkDesc := "Checks Satellite's remote execution capability."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Remote Execution Analysis:\n\n")

	// Check if remote execution plugin is installed
	rexPluginCmd := "rpm -qa | grep remote_execution"
	rexPluginOutput, _ := utils.RunCommand("bash", "-c", rexPluginCmd)

	detail.WriteString("Remote Execution Plugin Status:\n")
	if rexPluginOutput == "" {
		detail.WriteString("Remote Execution plugin not detected\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(rexPluginOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check remote execution settings
	rexSettingsCmd := "hammer settings list --search 'name ~ remote_execution'"
	rexSettingsOutput, _ := utils.RunCommand("bash", "-c", rexSettingsCmd)

	detail.WriteString("Remote Execution Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rexSettingsOutput)
	detail.WriteString("\n----\n\n")

	// Check recent job invocations
	jobsCmd := "hammer job-invocation list --per-page 10"
	jobsOutput, _ := utils.RunCommand("bash", "-c", jobsCmd)

	detail.WriteString("Recent Job Invocations:\n")
	if !strings.Contains(jobsOutput, "No job invocations found") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(jobsOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No recent job invocations found\n\n")
	}

	// Check SSH setup for remote execution
	sshSetupCmd := "grep remote_execution_ssh /etc/foreman-proxy/settings.d/* 2>/dev/null"
	sshSetupOutput, _ := utils.RunCommand("bash", "-c", sshSetupCmd)

	detail.WriteString("Remote Execution SSH Setup:\n")
	if sshSetupOutput == "" {
		detail.WriteString("No SSH configuration found for remote execution\n\n")
	} else {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(sshSetupOutput)
		detail.WriteString("\n----\n\n")
	}

	// Determine remote execution status
	hasRexPlugin := rexPluginOutput != ""
	hasRecentJobs := !strings.Contains(jobsOutput, "No job invocations found")
	hasSSHSetup := sshSetupOutput != ""

	// Evaluate results
	if !hasRexPlugin {
		check.Result = report.NewResult(report.StatusWarning,
			"Remote Execution plugin not installed",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider installing Remote Execution plugin if orchestration is needed")
	} else if !hasSSHSetup {
		check.Result = report.NewResult(report.StatusWarning,
			"Remote Execution plugin installed but SSH setup may not be complete",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify SSH setup for remote execution")
		report.AddRecommendation(&check.Result, "Check remote_execution_ssh_* settings in Satellite")
	} else if !hasRecentJobs {
		check.Result = report.NewResult(report.StatusWarning,
			"Remote Execution configured but no recent jobs found",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Test remote execution functionality if being used")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Remote Execution appears to be properly configured and used",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/configuring_and_setting_up_remote_jobs",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkJobTemplates checks job templates and schedules
func checkJobTemplates(r *report.AsciiDocReport) {
	checkID := "satellite-job-templates"
	checkName := "Job Templates"
	checkDesc := "Checks Satellite's job templates and schedules."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("Job Templates Analysis:\n\n")

	// Check job templates
	templatesCmd := "hammer job-template list"
	templatesOutput, err := utils.RunCommand("bash", "-c", templatesCmd)

	if err != nil {
		detail.WriteString("Error retrieving job templates:\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n\n")
	} else {
		detail.WriteString("Job Templates:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(templatesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check recurring jobs
	recurringCmd := "hammer job-invocation list --search 'recurring = true'"
	recurringOutput, _ := utils.RunCommand("bash", "-c", recurringCmd)

	detail.WriteString("Recurring Jobs:\n")
	if !strings.Contains(recurringOutput, "No job invocations found") {
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(recurringOutput)
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("No recurring jobs found\n\n")
	}

	// Check template inputs for a specific template (only if templates exist)
	// First, get the ID of a template to use as an example
	templateIdCmd := "hammer job-template list | grep -v '^--\\|^ID' | head -1 | awk '{print $1}'"
	templateId, templateIdErr := utils.RunCommand("bash", "-c", templateIdCmd)
	templateId = strings.TrimSpace(templateId)

	detail.WriteString("Template Inputs (sample):\n")
	if templateIdErr == nil && templateId != "" {
		// Get inputs for a specific template
		inputsCmd := fmt.Sprintf("hammer template-input list --template-id %s", templateId)
		inputsOutput, _ := utils.RunCommand("bash", "-c", inputsCmd)

		if !strings.Contains(inputsOutput, "No template inputs found") {
			// Only show part of the output if very long
			detail.WriteString("[source, bash]\n----\n")
			inputsLines := strings.Split(inputsOutput, "\n")
			if len(inputsLines) > 20 {
				for i := 0; i < 20; i++ {
					detail.WriteString(inputsLines[i] + "\n")
				}
				detail.WriteString("... (output truncated) ...\n")
			} else {
				detail.WriteString(inputsOutput)
			}
			detail.WriteString("\n----\n\n")
		} else {
			detail.WriteString("No template inputs found for selected template\n\n")
		}
	} else {
		detail.WriteString("Could not get template inputs (no templates available)\n\n")
	}

	// Determine job template status
	hasTemplates := !strings.Contains(templatesOutput, "No job templates found")
	hasRecurringJobs := !strings.Contains(recurringOutput, "No job invocations found")

	// Count templates
	templateCount := 0
	if hasTemplates {
		lines := strings.Split(templatesOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "|") && !strings.Contains(line, "---") && !strings.Contains(line, "ID") {
				templateCount++
			}
		}
	}

	// Evaluate results
	if !hasTemplates {
		check.Result = report.NewResult(report.StatusWarning,
			"No job templates found",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider creating job templates if orchestration is needed")
	} else if !hasRecurringJobs && templateCount > 5 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d job templates defined but no recurring jobs", templateCount),
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider setting up recurring jobs for regular tasks")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d job templates configured properly", templateCount),
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/managing_hosts/configuring_and_setting_up_remote_jobs",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
