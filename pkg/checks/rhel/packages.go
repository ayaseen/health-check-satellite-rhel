// pkg/checks/rhel/packages.go

package rhel

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunPackagesChecks performs package related checks
func RunPackagesChecks(r *report.AsciiDocReport) {
	// Create a WaitGroup to run all checks in parallel
	var wg sync.WaitGroup
	wg.Add(4)

	// Run all four checks in parallel
	go func() {
		defer wg.Done()
		// Check if latest security patches are applied
		checkSecurityPatches(r)
	}()

	go func() {
		defer wg.Done()
		// Validate enabled repositories
		checkEnabledRepositories(r)
	}()

	go func() {
		defer wg.Done()
		// Remove outdated or unnecessary packages
		checkUnnecessaryPackages(r)
	}()

	go func() {
		defer wg.Done()
		// Ensure consistent kernel version across nodes
		checkKernelConsistency(r)
	}()

	// Wait for all checks to complete
	wg.Wait()
}

// checkSecurityPatches confirms latest security patches are applied
func checkSecurityPatches(r *report.AsciiDocReport) {
	checkID := "packages-security"
	checkName := "Security Patches"
	checkDesc := "Confirms latest security patches are applied."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryUpdates)

	// Run commands concurrently to speed up data collection
	var securityUpdatesOutput, errataOutput, lastUpdateOutput, lastUpdatedOutput string
	var wg sync.WaitGroup

	wg.Add(4)

	// Check for security updates
	go func() {
		defer wg.Done()
		securityUpdatesCmd := "yum updateinfo list security --security 2>/dev/null || echo 'No security information available'"
		securityUpdatesOutput, _ = utils.RunCommand("bash", "-c", securityUpdatesCmd)
	}()

	// Check for errata info
	go func() {
		defer wg.Done()
		errataCmd := "yum updateinfo summary 2>/dev/null || echo 'No errata information available'"
		errataOutput, _ = utils.RunCommand("bash", "-c", errataCmd)
	}()

	// Get last yum update
	go func() {
		defer wg.Done()
		lastUpdateCmd := "rpm -qa --last | head -5"
		lastUpdateOutput, _ = utils.RunCommand("bash", "-c", lastUpdateCmd)
	}()

	// Get last-updated
	go func() {
		defer wg.Done()
		lastUpdatedCmd := "yum history list 2>/dev/null | head -5 || echo 'No yum history available'"
		lastUpdatedOutput, _ = utils.RunCommand("bash", "-c", lastUpdatedCmd)
	}()

	// Wait for all commands to complete
	wg.Wait()

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	securityDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/security_hardening/scanning-the-system-for-security-compliance-and-vulnerabilities", rhelVersion)
	packageDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_software_with_the_dnf_tool/updating-packages", rhelVersion)

	var detail strings.Builder
	detail.WriteString("Security Updates Available:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(securityUpdatesOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Update Information Summary:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(errataOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Last Updated Packages:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(lastUpdateOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Yum Update History:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(lastUpdatedOutput)
	detail.WriteString("\n----\n")

	// Count security updates
	securityUpdatesCount := 0
	importantUpdates := 0
	criticalUpdates := 0

	if !strings.Contains(securityUpdatesOutput, "No security information available") {
		for _, line := range strings.Split(securityUpdatesOutput, "\n") {
			if strings.Contains(line, "security") {
				securityUpdatesCount++
				if strings.Contains(line, "Important") {
					importantUpdates++
				} else if strings.Contains(line, "Critical") {
					criticalUpdates++
				}
			}
		}
	}

	// Evaluate security patches
	if criticalUpdates > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("Found %d critical security updates available", criticalUpdates),
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Apply critical security updates as soon as possible")
		report.AddRecommendation(&check.Result, "Run 'yum update --security' to apply security updates")
		report.AddReferenceLink(&check.Result, securityDocURL)
	} else if importantUpdates > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d important security updates available", importantUpdates),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Schedule installation of security updates")
		report.AddRecommendation(&check.Result, "Run 'yum update --security' to apply security updates")
		report.AddReferenceLink(&check.Result, securityDocURL)
	} else if securityUpdatesCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d security updates available", securityUpdatesCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Review and apply security updates")
		report.AddRecommendation(&check.Result, "Run 'yum update --security' to apply security updates")
		report.AddReferenceLink(&check.Result, packageDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"System appears to have all security patches applied",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkEnabledRepositories validates enabled repositories
func checkEnabledRepositories(r *report.AsciiDocReport) {
	checkID := "packages-repositories"
	checkName := "Enabled Repositories"
	checkDesc := "Validates enabled repositories."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryUpdates)

	// Run commands concurrently to speed up data collection
	var reposOutput, repoFilesOutput, rhelVersionOutput string
	var wg sync.WaitGroup

	wg.Add(3)

	// Get enabled repositories
	go func() {
		defer wg.Done()
		reposCmd := "yum repolist enabled -v 2>/dev/null || echo 'No repository information available'"
		reposOutput, _ = utils.RunCommand("bash", "-c", reposCmd)
	}()

	// Get repository files
	go func() {
		defer wg.Done()
		repoFilesCmd := "ls -l /etc/yum.repos.d/"
		repoFilesOutput, _ = utils.RunCommand("bash", "-c", repoFilesCmd)
	}()

	// Get RHEL version
	go func() {
		defer wg.Done()
		rhelVersionCmd := "cat /etc/redhat-release 2>/dev/null || echo 'RHEL version information not available'"
		rhelVersionOutput, _ = utils.RunCommand("bash", "-c", rhelVersionCmd)
	}()

	// Wait for all commands to complete
	wg.Wait()

	rhelVersion := strings.TrimSpace(rhelVersionOutput)

	// Get RHEL version for documentation reference
	rhDocVersion := utils.GetRedHatVersion()
	repoDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_software_with_the_dnf_tool/getting-started-with-the-dnf-tool", rhDocVersion)
	subsDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_subscription_management/%s/html/managing_red_hat_subscriptions/index", rhDocVersion)

	var detail strings.Builder
	detail.WriteString("Enabled Repositories:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(reposOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Repository Configuration Files:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(repoFilesOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("RHEL Version:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(rhelVersion)
	detail.WriteString("\n----\n")

	// Check for required repositories based on RHEL version
	requiredRepos := []string{}
	if strings.Contains(rhelVersion, "7.") {
		requiredRepos = []string{"rhel-7-server-rpms"}
	} else if strings.Contains(rhelVersion, "8.") {
		requiredRepos = []string{"rhel-8-for-x86_64-baseos-rpms", "rhel-8-for-x86_64-appstream-rpms"}
	} else if strings.Contains(rhelVersion, "9.") {
		requiredRepos = []string{"rhel-9-for-x86_64-baseos-rpms", "rhel-9-for-x86_64-appstream-rpms"}
	}

	// Check which required repos are missing
	missingRepos := []string{}
	for _, repo := range requiredRepos {
		if !strings.Contains(reposOutput, repo) {
			missingRepos = append(missingRepos, repo)
		}
	}

	// Count enabled repos
	enabledReposCount := 0
	for _, line := range strings.Split(reposOutput, "\n") {
		if strings.Contains(line, "Repo-id") {
			enabledReposCount++
		}
	}

	// Evaluate repositories
	if len(missingRepos) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Missing %d required repositories", len(missingRepos)),
			report.ResultKeyRecommended)

		for _, repo := range missingRepos {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Enable repository '%s'", repo))
		}

		report.AddRecommendation(&check.Result, "Use 'subscription-manager repos --enable=REPO_ID' to enable repositories")
		report.AddReferenceLink(&check.Result, repoDocURL)
	} else if enabledReposCount == 0 {
		check.Result = report.NewResult(report.StatusWarning,
			"No repositories appear to be enabled",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Check system registration status")
		report.AddRecommendation(&check.Result, "Enable appropriate repositories for your RHEL version")
		report.AddReferenceLink(&check.Result, subsDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			fmt.Sprintf("%d repositories are enabled, including all required ones", enabledReposCount),
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkUnnecessaryPackages identifies outdated or unnecessary packages
func checkUnnecessaryPackages(r *report.AsciiDocReport) {
	checkID := "packages-unnecessary"
	checkName := "Unnecessary Packages"
	checkDesc := "Identifies outdated or unnecessary packages."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryUpdates)

	// Run commands concurrently to speed up data collection
	var obsoleteOutput, duplicateOutput, oldKernelsOutput, currentKernelOutput string
	var wg sync.WaitGroup

	wg.Add(4)

	// Check for obsolete packages
	go func() {
		defer wg.Done()
		obsoleteCmd := "yum list obsolete 2>/dev/null || echo 'No obsolete packages'"
		obsoleteOutput, _ = utils.RunCommand("bash", "-c", obsoleteCmd)
	}()

	// Check for duplicate packages
	go func() {
		defer wg.Done()
		// Check for duplicate packages directly using rpm instead of relying on package-cleanup
		duplicateCmd := "rpm -qa --queryformat '%{NAME}.%{ARCH}\\n' | sort | uniq -c | grep -v '^[[:space:]]*1[[:space:]]' || echo 'No duplicate packages found'"
		duplicateOutput, _ = utils.RunCommand("bash", "-c", duplicateCmd)
	}()

	// Check for old kernel packages
	go func() {
		defer wg.Done()
		oldKernelsCmd := "rpm -q kernel | sort -V"
		oldKernelsOutput, _ = utils.RunCommand("bash", "-c", oldKernelsCmd)
	}()

	// Get current kernel
	go func() {
		defer wg.Done()
		currentKernelCmd := "uname -r"
		currentKernelOutput, _ = utils.RunCommand("bash", "-c", currentKernelCmd)
	}()

	// Wait for all commands to complete
	wg.Wait()

	currentKernel := strings.TrimSpace(currentKernelOutput)

	var detail strings.Builder
	detail.WriteString("Obsolete Packages:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(obsoleteOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Duplicate Packages:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(duplicateOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Installed Kernel Packages:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(oldKernelsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Current Running Kernel:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(currentKernel)
	detail.WriteString("\n----\n")

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	packageDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_software_with_the_dnf_tool/index", rhelVersion)

	// Check issues
	issues := []string{}

	// Check for obsolete packages
	if !strings.Contains(obsoleteOutput, "No obsolete packages") &&
		!strings.Contains(obsoleteOutput, "No matching Packages") {
		issues = append(issues, "Obsolete packages are installed")
	}

	// Check for duplicate packages
	hasDuplicates := false
	if !strings.Contains(duplicateOutput, "No duplicate packages found") {
		lines := strings.Split(duplicateOutput, "\n")
		for _, line := range lines {
			if line != "" && !strings.Contains(line, "No duplicate packages found") {
				hasDuplicates = true
				break
			}
		}
	}

	if hasDuplicates {
		issues = append(issues, "Duplicate packages are installed")
	}

	// Check for old kernels
	oldKernelsCount := 0
	kernels := strings.Split(strings.TrimSpace(oldKernelsOutput), "\n")
	if len(kernels) > 3 {
		oldKernelsCount = len(kernels) - 2 // Keep current and one previous kernel
		issues = append(issues, fmt.Sprintf("%d old kernel packages could be removed", oldKernelsCount))
	}

	// Evaluate package status
	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d package maintenance issues", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if strings.Contains(obsoleteOutput, "Obsolete Packages") {
			report.AddRecommendation(&check.Result, "Remove obsolete packages with 'yum remove $(yum list obsolete -q)'")
		}

		if hasDuplicates {
			report.AddRecommendation(&check.Result, "Install yum-utils package if needed")
			report.AddRecommendation(&check.Result, "Use 'rpm -qa --queryformat \"%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\\n\" | sort | uniq -d' to identify duplicates")
			report.AddRecommendation(&check.Result, "Remove specific duplicate packages using 'rpm -e' or 'yum remove'")
		}

		if oldKernelsCount > 0 {
			report.AddRecommendation(&check.Result, "Remove old kernels while keeping the current and one previous version")
			report.AddRecommendation(&check.Result, "Use 'package-cleanup --oldkernels --count=2' to keep only 2 kernels")
		}

		report.AddReferenceLink(&check.Result, packageDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"No unnecessary or outdated packages detected",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkKernelConsistency ensures consistent kernel version across nodes
func checkKernelConsistency(r *report.AsciiDocReport) {
	checkID := "packages-kernel"
	checkName := "Kernel Consistency"
	checkDesc := "Ensures consistent kernel version across nodes."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategoryUpdates)

	// Run commands concurrently to speed up data collection
	var currentKernelOutput, installedKernelsOutput, latestAvailableOutput, repoMetaAgeOutput, kernelModulesOutput string
	var wg sync.WaitGroup

	wg.Add(5)

	// Get current kernel with full version - this is the running kernel
	go func() {
		defer wg.Done()
		currentKernelCmd := "uname -r"
		currentKernelOutput, _ = utils.RunCommand("bash", "-c", currentKernelCmd)
	}()

	// Get all installed kernels
	go func() {
		defer wg.Done()
		installedKernelsCmd := "rpm -q kernel"
		installedKernelsOutput, _ = utils.RunCommand("bash", "-c", installedKernelsCmd)
	}()

	// Get latest available kernel from repositories - using grep to filter out any messages
	go func() {
		defer wg.Done()
		latestAvailableCmd := "dnf repoquery --latest-limit 1 kernel 2>/dev/null | grep -o 'kernel-[0-9].*' || echo 'Unable to query latest'"
		latestAvailableOutput, _ = utils.RunCommand("bash", "-c", latestAvailableCmd)
	}()

	// Check repository metadata age to detect stale repositories
	go func() {
		defer wg.Done()
		repoMetaAgeCmd := "find /var/cache/dnf -type f -path '*/repodata/repomd.xml' -exec stat -c '%Y' {} \\; 2>/dev/null | sort -nr | head -n1 || echo '0'"
		repoMetaAgeOutput, _ = utils.RunCommand("bash", "-c", repoMetaAgeCmd)
	}()

	// Get kernel modules
	go func() {
		defer wg.Done()
		kernelModulesCmd := "lsmod | head -10"
		kernelModulesOutput, _ = utils.RunCommand("bash", "-c", kernelModulesCmd)
	}()

	// Wait for all commands to complete
	wg.Wait()

	currentKernel := strings.TrimSpace(currentKernelOutput)
	latestAvailable := strings.TrimSpace(latestAvailableOutput)

	// Format the latest available kernel for comparison
	formattedLatestAvailable := latestAvailable
	formattedLatestAvailable = strings.TrimPrefix(formattedLatestAvailable, "kernel-0:")
	formattedLatestAvailable = strings.TrimPrefix(formattedLatestAvailable, "kernel-")

	// Calculate repository metadata age in days
	repoMetaTimestamp, err := strconv.ParseInt(strings.TrimSpace(repoMetaAgeOutput), 10, 64)
	if err != nil {
		repoMetaTimestamp = 0
	}
	now := time.Now().Unix()
	metaAgeDays := (now - repoMetaTimestamp) / 86400

	// Get RHEL version for documentation reference
	rhelVersion := utils.GetRedHatVersion()
	kernelDocURL := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/%s/html/managing_monitoring_and_updating_the_kernel/index", rhelVersion)

	var detail strings.Builder
	detail.WriteString("Current Running Kernel:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(currentKernel)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Installed Kernel Packages:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(installedKernelsOutput)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Latest Available Kernel:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(latestAvailable)
	detail.WriteString("\n----\n\n")

	detail.WriteString("Repository Metadata Status:\n")
	detail.WriteString("[source, bash]\n----\n")
	if repoMetaTimestamp > 0 {
		metaDate := time.Unix(repoMetaTimestamp, 0).Format("2006-01-02 15:04:05")
		detail.WriteString(fmt.Sprintf("Metadata last updated: %s (%d days ago)\n", metaDate, metaAgeDays))
	} else {
		detail.WriteString("Could not determine repository metadata age\n")
	}
	detail.WriteString("\n----\n\n")

	detail.WriteString("Loaded Kernel Modules (Top 10):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(kernelModulesOutput)
	detail.WriteString("\n----\n\n")

	// Simple direct comparison - is running kernel the latest available?
	staleMetadata := metaAgeDays > 7 // Consider metadata stale if older than 7 days
	runningLatest := currentKernel == formattedLatestAvailable

	// Add kernel status summary
	detail.WriteString("Kernel Version Status Summary:\n")
	detail.WriteString("[source, text]\n----\n")
	detail.WriteString(fmt.Sprintf("Running kernel: %s\n", currentKernel))
	detail.WriteString(fmt.Sprintf("Latest available kernel: %s\n", latestAvailable))
	detail.WriteString(fmt.Sprintf("Formatted for comparison: %s\n", formattedLatestAvailable))
	detail.WriteString(fmt.Sprintf("Repository metadata age: %d days\n", metaAgeDays))
	detail.WriteString(fmt.Sprintf("Running latest kernel: %v\n", runningLatest))
	detail.WriteString("\n----\n\n")

	// Evaluate kernel consistency
	issues := []string{}

	if staleMetadata {
		issues = append(issues, fmt.Sprintf("Repository metadata is %d days old - unable to reliably determine if latest kernel is installed", metaAgeDays))
	} else if !runningLatest && strings.Contains(latestAvailable, "Unable to query") {
		issues = append(issues, "Unable to determine latest available kernel")
	} else if !runningLatest {
		issues = append(issues, fmt.Sprintf("System is not running the latest available kernel (running: %s, latest: %s)",
			currentKernel, formattedLatestAvailable))
	}

	// Evaluate kernel status
	if len(issues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Found %d kernel consistency issues", len(issues)),
			report.ResultKeyRecommended)

		for _, issue := range issues {
			report.AddRecommendation(&check.Result, issue)
		}

		if staleMetadata {
			report.AddRecommendation(&check.Result, "Refresh repository metadata with 'subscription-manager refresh'")
			report.AddRecommendation(&check.Result, "For disconnected environments, sync content from Satellite server")
		} else if !runningLatest && strings.Contains(latestAvailable, "Unable to query") {
			report.AddRecommendation(&check.Result, "Check repository configuration and connectivity")
			report.AddRecommendation(&check.Result, "For systems managed via Satellite, verify content views are properly synced")
		} else if !runningLatest {
			report.AddRecommendation(&check.Result, "Update kernel with 'yum update kernel' and reboot")
		}

		report.AddReferenceLink(&check.Result, kernelDocURL)
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"System is running the latest available kernel",
			report.ResultKeyNoChange)
	}

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
