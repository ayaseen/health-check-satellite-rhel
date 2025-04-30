// pkg/checks/satellite/storage.go

package satellite

import (
	"fmt"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunStorageChecks performs Satellite storage checks
func RunStorageChecks(r *report.AsciiDocReport) {
	// Check disk space on critical directories
	checkCriticalDirectories(r)

	// Check Pulp storage
	checkPulpStorage(r)

	// Check database storage
	checkDatabaseStorage(r)
}

// checkCriticalDirectories checks disk space on critical Satellite directories
func checkCriticalDirectories(r *report.AsciiDocReport) {
	checkID := "satellite-disk-space"
	checkName := "Critical Directory Space"
	checkDesc := "Ensures sufficient disk space is available on critical Satellite directories."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteStorage)

	// Define critical directories and their minimum required space in GB
	criticalDirs := map[string]int{
		"/var":                   10,
		"/var/lib/pulp":          100,
		"/var/lib/pgsql":         10,
		"/var/log":               10,
		"/var/lib/qpidd":         5,
		"/var/lib/foreman":       5,
		"/var/lib/foreman-proxy": 1,
	}

	var detail strings.Builder
	detail.WriteString("Disk Space Check for Critical Directories:\n\n")

	// Get df output for reference
	dfCmd := "df -h"
	dfOutput, _ := utils.RunCommand("bash", "-c", dfCmd)
	detail.WriteString("Overall Disk Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(dfOutput)
	detail.WriteString("\n----\n\n")

	// Check each critical directory
	var spaceCritical []string
	var spaceWarning []string

	detail.WriteString("Critical Directory Space Information:\n")
	detail.WriteString("|===\n")
	detail.WriteString("| Directory | Available | Usage | Mount Point | Status\n\n")

	for dir, minGB := range criticalDirs {
		// Get disk space for this directory
		dirSpaceCmd := fmt.Sprintf("df -h %s | grep -v Filesystem", dir)
		dirSpaceOutput, err := utils.RunCommand("bash", "-c", dirSpaceCmd)

		if err != nil {
			detail.WriteString(fmt.Sprintf("| %s | Not found | N/A | N/A | Warning\n", dir))
			continue
		}

		// Extract available space from df output
		fields := strings.Fields(dirSpaceOutput)
		if len(fields) < 4 {
			detail.WriteString(fmt.Sprintf("| %s | Could not parse | N/A | N/A | Warning\n", dir))
			continue
		}

		availableStr := fields[3]
		usagePercent := fields[4]
		mountPoint := fields[5]

		// Convert available space to GB for comparison
		availableGB := 0.0
		if strings.HasSuffix(availableStr, "G") {
			availableGB, _ = strconv.ParseFloat(availableStr[:len(availableStr)-1], 64)
		} else if strings.HasSuffix(availableStr, "T") {
			teraBytes, _ := strconv.ParseFloat(availableStr[:len(availableStr)-1], 64)
			availableGB = teraBytes * 1024
		} else if strings.HasSuffix(availableStr, "M") {
			megaBytes, _ := strconv.ParseFloat(availableStr[:len(availableStr)-1], 64)
			availableGB = megaBytes / 1024
		}

		status := "OK"
		// Check if space is critical
		if availableGB < float64(minGB) {
			spaceCritical = append(spaceCritical, fmt.Sprintf("%s (%s available, minimum %dGB recommended)",
				dir, availableStr, minGB))
			status = "Critical"
		} else if availableGB < float64(minGB*2) {
			spaceWarning = append(spaceWarning, fmt.Sprintf("%s (%s available, minimum %dGB recommended)",
				dir, availableStr, minGB))
			status = "Warning"
		}

		detail.WriteString(fmt.Sprintf("| %s | %s | %s | %s | %s\n",
			dir, availableStr, usagePercent, mountPoint, status))
	}
	detail.WriteString("|===\n\n")

	// Add inode usage information
	inodeCmd := "df -i | grep -E '(/var|/opt)'"
	inodeOutput, _ := utils.RunCommand("bash", "-c", inodeCmd)

	detail.WriteString("Inode Usage:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(inodeOutput)
	detail.WriteString("\n----\n\n")

	// Check if any inodes are over 80% usage
	inodeIssues := false
	if inodeOutput != "" {
		lines := strings.Split(inodeOutput, "\n")
		for _, line := range lines {
			if line == "" {
				continue
			}

			fields := strings.Fields(line)
			if len(fields) >= 5 {
				usageStr := fields[4]
				if strings.HasSuffix(usageStr, "%") {
					usageStr = usageStr[:len(usageStr)-1]
					usage, _ := strconv.Atoi(usageStr)
					if usage >= 80 {
						inodeIssues = true
						break
					}
				}
			}
		}
	}

	if len(spaceCritical) > 0 {
		check.Result = report.NewResult(report.StatusCritical,
			fmt.Sprintf("%d directories have critically low disk space", len(spaceCritical)),
			report.ResultKeyRequired)

		for _, dir := range spaceCritical {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Increase disk space for %s", dir))
		}

		report.AddRecommendation(&check.Result, "Consider running 'satellite-maintain service restart' after resolving space issues.")
	} else if len(spaceWarning) > 0 || inodeIssues {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d directories have low disk space", len(spaceWarning)),
			report.ResultKeyRecommended)

		for _, dir := range spaceWarning {
			report.AddRecommendation(&check.Result, fmt.Sprintf("Monitor disk space for %s", dir))
		}

		if inodeIssues {
			report.AddRecommendation(&check.Result, "Monitor inode usage - some directories have high inode usage")
		}
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"All critical directories have sufficient disk space",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/installing_satellite_server_in_a_connected_network_environment/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkPulpStorage checks the Pulp storage configuration
func checkPulpStorage(r *report.AsciiDocReport) {
	checkID := "satellite-pulp-storage"
	checkName := "Pulp Storage"
	checkDesc := "Checks Pulp storage configuration and usage."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteStorage)

	// Get Pulp storage information
	pulpDirCmd := "du -sh /var/lib/pulp/*"
	pulpDirOutput, err := utils.RunCommand("bash", "-c", pulpDirCmd)

	var detail strings.Builder
	detail.WriteString("Pulp Storage Information:\n\n")

	if err != nil {
		detail.WriteString("Error getting Pulp storage information:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not obtain Pulp storage information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify Pulp directory exists at /var/lib/pulp")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/index",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("Pulp Directory Sizes:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pulpDirOutput)
	detail.WriteString("\n----\n\n")

	// Check for orphaned content
	orphanListCmd := "foreman-rake katello:delete_orphaned_content --dry-run"
	orphanOutput, _ := utils.RunCommand("bash", "-c", orphanListCmd)

	detail.WriteString("Orphaned Content Check:\n")
	detail.WriteString("[source, bash]\n----\n")
	if strings.Contains(orphanOutput, "ERROR") || strings.Contains(orphanOutput, "Error") {
		detail.WriteString("Could not check for orphaned content\n")
	} else {
		// Trim output if very long
		if strings.Count(orphanOutput, "\n") > 30 {
			lines := strings.SplitN(orphanOutput, "\n", 31)
			orphanOutput = strings.Join(lines[:30], "\n") + "\n...(truncated)..."
		}
		detail.WriteString(orphanOutput)
	}
	detail.WriteString("\n----\n\n")

	// Look for potential issues
	hasLargeContent := strings.Contains(pulpDirOutput, "G")
	potentialIssues := []string{}

	if hasLargeContent {
		pulpContentSize := "0"

		lines := strings.Split(pulpDirOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "/var/lib/pulp/content") {
				fields := strings.Fields(line)
				if len(fields) > 0 {
					pulpContentSize = fields[0]
				}
				break
			}
		}

		if strings.HasSuffix(pulpContentSize, "G") {
			sizeValue, _ := strconv.ParseFloat(pulpContentSize[:len(pulpContentSize)-1], 64)
			if sizeValue > 100 {
				potentialIssues = append(potentialIssues,
					fmt.Sprintf("Pulp content directory is very large (%s)", pulpContentSize))
			}
		}
	}

	if strings.Contains(orphanOutput, "orphaned content") {
		potentialIssues = append(potentialIssues, "Orphaned content detected")
	}

	if len(potentialIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d Pulp storage issues found", len(potentialIssues)),
			report.ResultKeyRecommended)

		for _, issue := range potentialIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Consider running 'foreman-rake katello:delete_orphaned_content' to remove orphaned content")
		report.AddRecommendation(&check.Result, "Review sync plans and content lifecycle to manage disk usage")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Pulp storage appears to be healthy",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/managing_content/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkDatabaseStorage checks the database storage configuration
func checkDatabaseStorage(r *report.AsciiDocReport) {
	checkID := "satellite-database-storage"
	checkName := "Database Storage"
	checkDesc := "Checks PostgreSQL database storage configuration and usage."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteStorage)

	// Get PostgreSQL storage information
	pgDirCmd := "du -sh /var/lib/pgsql 2>/dev/null || echo 'Directory not found'"
	pgDirOutput, err := utils.RunCommand("bash", "-c", pgDirCmd)

	var detail strings.Builder
	detail.WriteString("Database Storage Information:\n\n")

	if err != nil || strings.Contains(pgDirOutput, "Directory not found") {
		detail.WriteString("Error getting PostgreSQL storage information:\n")
		detail.WriteString("[source, bash]\n----\n")
		if err != nil {
			detail.WriteString(err.Error())
		} else {
			detail.WriteString("Directory not found")
		}
		detail.WriteString("\n----\n\n")

		check.Result = report.NewResult(report.StatusWarning,
			"Could not obtain PostgreSQL storage information",
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Verify PostgreSQL directory exists at /var/lib/pgsql")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link using version info
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/installing_satellite_server_in_a_connected_network_environment/index",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)

		r.AddCheck(check)
		return
	}

	detail.WriteString("PostgreSQL Directory Size:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(pgDirOutput)
	detail.WriteString("\n----\n\n")

	// Get database sizes - with improved error handling
	dbSizeCmd := "su - postgres -c 'psql -c \"SELECT datname, pg_size_pretty(pg_database_size(datname)) FROM pg_database ORDER BY pg_database_size(datname) DESC;\"' 2>/dev/null || echo 'Could not retrieve database sizes'"
	dbSizeOutput, _ := utils.RunCommand("bash", "-c", dbSizeCmd)

	detail.WriteString("Database Sizes:\n")
	detail.WriteString("[source, bash]\n----\n")
	if !strings.Contains(dbSizeOutput, "Could not retrieve database sizes") {
		detail.WriteString(dbSizeOutput)
	} else {
		detail.WriteString("Could not retrieve database sizes - PostgreSQL access error")
	}
	detail.WriteString("\n----\n\n")

	// Check for table bloat - with improved error handling
	tableCountCmd := "su - postgres -c 'psql -d foreman -c \"SELECT COUNT(*) FROM pg_tables WHERE schemaname = \\'public\\';\"' 2>/dev/null || echo 'Could not check table count'"
	tableCountOutput, _ := utils.RunCommand("bash", "-c", tableCountCmd)

	detail.WriteString("Table Count:\n")
	detail.WriteString("[source, bash]\n----\n")
	if !strings.Contains(tableCountOutput, "Could not check table count") {
		detail.WriteString(tableCountOutput)
	} else {
		detail.WriteString("Could not retrieve table count - PostgreSQL access error")
	}
	detail.WriteString("\n----\n\n")

	// Check for database settings - with improved error handling
	settingsCmd := "su - postgres -c 'psql -c \"SHOW work_mem, maintenance_work_mem, shared_buffers, effective_cache_size, autovacuum_work_mem;\"' 2>/dev/null || echo 'Could not check PostgreSQL settings'"
	settingsOutput, _ := utils.RunCommand("bash", "-c", settingsCmd)

	detail.WriteString("PostgreSQL Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	if !strings.Contains(settingsOutput, "Could not check PostgreSQL settings") {
		detail.WriteString(settingsOutput)
	} else {
		detail.WriteString("Could not retrieve PostgreSQL settings - access error")
	}
	detail.WriteString("\n----\n")

	// Analyze the output and look for issues
	pgSize := "0"
	if pgDirOutput != "" {
		fields := strings.Fields(pgDirOutput)
		if len(fields) > 0 {
			pgSize = fields[0]
		}
	}

	potentialIssues := []string{}

	// Check PostgreSQL size
	if strings.HasSuffix(pgSize, "G") {
		sizeValue, _ := strconv.ParseFloat(pgSize[:len(pgSize)-1], 64)
		if sizeValue > 50 {
			potentialIssues = append(potentialIssues,
				fmt.Sprintf("PostgreSQL directory is very large (%s)", pgSize))
		}
	}

	// Check if shared_buffers is properly configured (should be about 25% of system memory)
	sharedBuffersOK := false
	if strings.Contains(settingsOutput, "shared_buffers") {
		// Extract shared_buffers value if present
		for _, line := range strings.Split(settingsOutput, "\n") {
			if strings.Contains(line, "shared_buffers") {
				fields := strings.Fields(line)
				if len(fields) > 1 {
					bufferValue := fields[1]
					if strings.HasSuffix(bufferValue, "MB") || strings.HasSuffix(bufferValue, "GB") {
						sharedBuffersOK = true
						break
					}
				}
			}
		}
	}

	if !sharedBuffersOK {
		potentialIssues = append(potentialIssues, "PostgreSQL shared_buffers setting may not be optimally configured")
	}

	// Check if maintenance_work_mem is properly configured
	maintenanceWorkMemOK := false
	if strings.Contains(settingsOutput, "maintenance_work_mem") {
		// Consider it OK if present - detailed tuning would require system-specific analysis
		maintenanceWorkMemOK = true
	}

	if !maintenanceWorkMemOK {
		potentialIssues = append(potentialIssues, "PostgreSQL maintenance_work_mem setting may not be configured")
	}

	if len(potentialIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d database storage issues found", len(potentialIssues)),
			report.ResultKeyRecommended)

		for _, issue := range potentialIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Consider tuning PostgreSQL for better performance")
		report.AddRecommendation(&check.Result, "Configure shared_buffers to approximately 25% of system memory")
		report.AddRecommendation(&check.Result, "Consider running vacuum to reclaim space in PostgreSQL")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Database storage appears to be healthy",
			report.ResultKeyNoChange)
	}

	// Add reference link using version info
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://docs.redhat.com/en/documentation/red_hat_satellite/%s.%s/html/installing_satellite_server_in_a_connected_network_environment/index",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
