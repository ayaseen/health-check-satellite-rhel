// pkg/checks/satellite/database.go

package satellite

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/utils"
)

// RunDatabaseChecks performs Satellite database health checks
func RunDatabaseChecks(r *report.AsciiDocReport) {
	// Check PostgreSQL service status
	checkPostgresStatus(r)

	// Check database configuration
	checkDatabaseConfig(r)

	// Check for bloated tables or dead tuples
	checkDatabaseBloat(r)

	// Check database performance
	checkDatabasePerformance(r)
}

// checkPostgresStatus checks if PostgreSQL is running and responsive
func checkPostgresStatus(r *report.AsciiDocReport) {
	checkID := "satellite-postgres-status"
	checkName := "PostgreSQL Service Status"
	checkDesc := "Verifies PostgreSQL service is running and responsive."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Check PostgreSQL service status
	statusCmd := "systemctl status postgresql"
	statusOutput, err := utils.RunCommand("bash", "-c", statusCmd)

	var detail strings.Builder
	detail.WriteString("PostgreSQL Service Status:\n\n")

	if err != nil {
		detail.WriteString("Error checking PostgreSQL service status:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		check.Result = report.NewResult(report.StatusCritical,
			"PostgreSQL service may not be running",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Start PostgreSQL service: systemctl start postgresql")
		report.AddRecommendation(&check.Result, "Check PostgreSQL logs: journalctl -u postgresql")
		report.SetDetail(&check.Result, detail.String())

		// Add reference link directly
		versionInfo := GetSatelliteVersion()
		docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/configuration_management_tools",
			versionInfo.MajorVersion, versionInfo.MinorVersion)
		report.AddReferenceLink(&check.Result, docsUrl)
		report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/using-postgresql_deploying-different-types-of-servers")

		r.AddCheck(check)
		return
	}

	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(statusOutput)
	detail.WriteString("\n----\n\n")

	// Check if PostgreSQL is responsive
	pingCmd := "su - postgres -c 'psql -c \"SELECT 1;\"' 2>/dev/null"
	pingOutput, pingErr := utils.RunCommand("bash", "-c", pingCmd)

	detail.WriteString("PostgreSQL Connectivity Test:\n")
	if pingErr != nil {
		detail.WriteString("Error connecting to PostgreSQL:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(pingErr.Error())
		detail.WriteString("\n----\n")

		check.Result = report.NewResult(report.StatusCritical,
			"PostgreSQL service is running but not accepting connections",
			report.ResultKeyRequired)
		report.AddRecommendation(&check.Result, "Check PostgreSQL configuration: cat /var/lib/pgsql/data/postgresql.conf")
		report.AddRecommendation(&check.Result, "Check PostgreSQL access rules: cat /var/lib/pgsql/data/pg_hba.conf")
		report.AddRecommendation(&check.Result, "Restart PostgreSQL: systemctl restart postgresql")
	} else {
		detail.WriteString("Successfully connected to PostgreSQL:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(pingOutput)
		detail.WriteString("\n----\n")

		// Check PostgreSQL version
		versionCmd := "su - postgres -c 'psql -c \"SELECT version();\"' 2>/dev/null"
		versionOutput, _ := utils.RunCommand("bash", "-c", versionCmd)
		detail.WriteString("\nPostgreSQL Version:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(versionOutput)
		detail.WriteString("\n----\n")

		// Check database size
		sizeCmd := "su - postgres -c 'psql -c \"SELECT pg_database.datname, pg_size_pretty(pg_database_size(pg_database.datname)) FROM pg_database ORDER BY pg_database_size(pg_database.datname) DESC;\"' 2>/dev/null"
		sizeOutput, _ := utils.RunCommand("bash", "-c", sizeCmd)
		detail.WriteString("\nDatabase Sizes:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(sizeOutput)
		detail.WriteString("\n----\n")

		check.Result = report.NewResult(report.StatusOK,
			"PostgreSQL service is running and accepting connections",
			report.ResultKeyNoChange)
	}

	// Add reference link directly
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/configuration_management_tools",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/deploying_different_types_of_servers/using-postgresql_deploying-different-types-of-servers")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkDatabaseConfig checks PostgreSQL configuration parameters
func checkDatabaseConfig(r *report.AsciiDocReport) {
	checkID := "satellite-postgres-config"
	checkName := "PostgreSQL Configuration"
	checkDesc := "Checks PostgreSQL configuration parameters for optimal performance."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	var detail strings.Builder
	detail.WriteString("PostgreSQL Configuration Parameters:\n\n")

	// Check key PostgreSQL configuration parameters one at a time
	parameters := []string{
		"max_connections",
		"shared_buffers",
		"work_mem",
		"maintenance_work_mem",
		"effective_cache_size",
		"autovacuum",
		"log_min_duration_statement",
	}

	// Build a map to store parameter values
	configValues := make(map[string]string)

	// Check each parameter individually
	for _, param := range parameters {
		configCmd := fmt.Sprintf("su - postgres -c 'psql -c \"SHOW %s;\"' 2>/dev/null", param)
		configOutput, err := utils.RunCommand("bash", "-c", configCmd)

		if err == nil && configOutput != "" {
			// Extract value from output - typical format is:
			// max_connections
			// ----------------
			//  100
			// (1 row)
			lines := strings.Split(configOutput, "\n")
			if len(lines) >= 3 {
				value := strings.TrimSpace(lines[2])
				configValues[param] = value

				detail.WriteString(fmt.Sprintf("%s = %s\n", param, value))
			}
		} else {
			detail.WriteString(fmt.Sprintf("Could not retrieve %s: %v\n", param, err))
		}
	}

	detail.WriteString("\n")

	// Get system memory information for context
	memCmd := "free -h"
	memOutput, _ := utils.RunCommand("bash", "-c", memCmd)
	detail.WriteString("System Memory Information:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(memOutput)
	detail.WriteString("\n----\n\n")

	// Get raw memory in KB for calculations
	totalMemKb := 0
	memRawCmd := "grep MemTotal /proc/meminfo | awk '{print $2}'"
	memRawOutput, _ := utils.RunCommand("bash", "-c", memRawCmd)
	fmt.Sscanf(strings.TrimSpace(memRawOutput), "%d", &totalMemKb)

	// Get additional configuration from postgresql.conf
	confFileCmd := "grep -E 'shared_buffers|work_mem|maintenance_work_mem|effective_cache_size|autovacuum|max_connections' /var/lib/pgsql/data/postgresql.conf | grep -v '^#'"
	confFileOutput, _ := utils.RunCommand("bash", "-c", confFileCmd)
	detail.WriteString("PostgreSQL Configuration File Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(confFileOutput)
	detail.WriteString("\n----\n\n")

	// Add tracking and logging settings
	loggingCmd := "grep -E 'log_min_duration|log_statement|log_checkpoints|log_lock_waits' /var/lib/pgsql/data/postgresql.conf | grep -v '^#'"
	loggingOutput, _ := utils.RunCommand("bash", "-c", loggingCmd)
	detail.WriteString("PostgreSQL Logging Settings:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(loggingOutput)
	detail.WriteString("\n----\n")

	// Check for configuration issues
	configIssues := []string{}

	// Check shared_buffers (should be ~25% of system memory)
	sharedBuffers := configValues["shared_buffers"]
	if sharedBuffers != "" {
		// Check if it's set to a reasonable value
		if !strings.Contains(strings.ToLower(sharedBuffers), "gb") && !strings.Contains(sharedBuffers, "MB") {
			configIssues = append(configIssues, "shared_buffers may be too small: "+sharedBuffers)
		} else {
			// Very basic check - for a proper check we'd need to parse the values and compare with system memory
			if strings.Contains(sharedBuffers, "MB") {
				valueMB, _ := strconv.Atoi(strings.TrimSuffix(sharedBuffers, "MB"))
				if totalMemKb > 0 && (valueMB*1024) < (totalMemKb/8) {
					configIssues = append(configIssues, fmt.Sprintf("shared_buffers (%s) may be too small for this system (%d MB RAM)",
						sharedBuffers, totalMemKb/1024))
				}
			}
		}
	}

	// Check work_mem
	workMem := configValues["work_mem"]
	if workMem != "" && !strings.Contains(workMem, "MB") && !strings.Contains(workMem, "GB") {
		configIssues = append(configIssues, "work_mem may be too small: "+workMem)
	}

	// Check maintenance_work_mem
	maintenanceWorkMem := configValues["maintenance_work_mem"]
	if maintenanceWorkMem != "" && !strings.Contains(maintenanceWorkMem, "MB") && !strings.Contains(maintenanceWorkMem, "GB") {
		configIssues = append(configIssues, "maintenance_work_mem may be too small: "+maintenanceWorkMem)
	}

	// Check autovacuum
	autovacuum := configValues["autovacuum"]
	if autovacuum != "" && strings.ToLower(autovacuum) != "on" {
		configIssues = append(configIssues, "autovacuum is not enabled")
	}

	// Check max_connections
	maxConnections := configValues["max_connections"]
	if maxConnections != "" {
		maxConnVal, err := strconv.Atoi(maxConnections)
		if err == nil {
			// Check if max_connections is too high (could cause memory issues)
			if maxConnVal > 500 {
				configIssues = append(configIssues, fmt.Sprintf("max_connections (%s) may be too high", maxConnections))
			}
			// Also check if it's too low for a typical Satellite server
			if maxConnVal < 100 {
				configIssues = append(configIssues, fmt.Sprintf("max_connections (%s) may be too low for a Satellite server", maxConnections))
			}
		}
	}

	if len(configIssues) > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("%d PostgreSQL configuration issues found", len(configIssues)),
			report.ResultKeyRecommended)

		for _, issue := range configIssues {
			report.AddRecommendation(&check.Result, issue)
		}

		report.AddRecommendation(&check.Result, "Consider tuning PostgreSQL configuration for optimal performance")
		report.AddRecommendation(&check.Result, "Recommended settings: shared_buffers = 25% of RAM, work_mem = 16MB, maintenance_work_mem = 128MB")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"PostgreSQL configuration appears to be optimized",
			report.ResultKeyNoChange)
	}

	// Add reference link directly
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/configuration_management_tools",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_using_database_servers/configuring-postgresql_configuring-and-using-database-servers")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// extractConfigValue extracts a configuration value from PostgreSQL output
func extractConfigValue(output string, parameter string) string {
	re := regexp.MustCompile(fmt.Sprintf(`(?i)%s\s+\|\s+([^\s|]+)`, parameter))
	match := re.FindStringSubmatch(output)
	if len(match) > 1 {
		return match[1]
	}
	return ""
}

// checkDatabaseBloat checks for bloated tables and indices
func checkDatabaseBloat(r *report.AsciiDocReport) {
	checkID := "satellite-db-bloat"
	checkName := "Database Bloat"
	checkDesc := "Checks for bloated tables and indices that need maintenance."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Query to find bloated tables (basic version)
	bloatQueryCmd := `su - postgres -c "psql -d foreman -c \"SELECT schemaname, tablename, pg_size_pretty(relation_size), pg_size_pretty(dead_tuples::bigint) as dead_tuples_size, round(dead_tuples::numeric / case when relation_size > 0 then relation_size else 1 end * 100, 2) AS dead_tuples_pct FROM (SELECT pgns.nspname as schemaname, pgc.relname as tablename, pg_relation_size(pgc.oid) as relation_size, NULLIF(pgstat.n_dead_tup, 0) as dead_tuples FROM pg_class pgc JOIN pg_namespace pgns ON pgns.oid = pgc.relnamespace JOIN pg_stat_user_tables pgstat ON pgstat.relname = pgc.relname WHERE pgc.relkind = 'r' AND pgns.nspname NOT IN ('pg_catalog', 'information_schema') AND pgstat.n_dead_tup > 0 ORDER BY pgstat.n_dead_tup DESC) as s WHERE round(dead_tuples::numeric / case when relation_size > 0 then relation_size else 1 end * 100, 2) > 10 LIMIT 20;\"" 2>/dev/null`

	bloatOutput, err := utils.RunCommand("bash", "-c", bloatQueryCmd)

	var detail strings.Builder
	detail.WriteString("Database Bloat Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error running database bloat analysis:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")

		// Try a simpler query
		simpleBloatCmd := `su - postgres -c "psql -d foreman -c \"SELECT relname, n_dead_tup FROM pg_stat_user_tables WHERE n_dead_tup > 1000 ORDER BY n_dead_tup DESC LIMIT 10;\"" 2>/dev/null`
		simpleBloatOutput, simpleErr := utils.RunCommand("bash", "-c", simpleBloatCmd)

		if simpleErr == nil {
			detail.WriteString("Tables with Dead Tuples (simplified query):\n")
			detail.WriteString("[source, bash]\n----\n")
			detail.WriteString(simpleBloatOutput)
			detail.WriteString("\n----\n")
		}
	} else {
		detail.WriteString("Bloated Tables (>10% dead tuples):\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(bloatOutput)
		detail.WriteString("\n----\n\n")
	}

	// Check last autovacuum runs
	vacuumCmd := `su - postgres -c "psql -d foreman -c \"SELECT relname, last_vacuum, last_autovacuum, last_analyze, last_autoanalyze FROM pg_stat_user_tables WHERE relname IN (SELECT relname FROM pg_stat_user_tables ORDER BY n_dead_tup DESC LIMIT 10);\"" 2>/dev/null`
	vacuumOutput, _ := utils.RunCommand("bash", "-c", vacuumCmd)

	detail.WriteString("\nRecent Vacuum Activity on Top Tables:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(vacuumOutput)
	detail.WriteString("\n----\n\n")

	// Get total tables count and approximate bloat percentage
	tableCountCmd := `su - postgres -c "psql -d foreman -c \"SELECT COUNT(*) FROM pg_stat_user_tables WHERE n_dead_tup > 0;\"" 2>/dev/null`
	tableCountOutput, _ := utils.RunCommand("bash", "-c", tableCountCmd)

	bloatedTables := 0
	totalDeadTuples := 0

	// Count tables with significant bloat (>10% dead tuples)
	significantBloatCmd := `su - postgres -c "psql -d foreman -c \"SELECT COUNT(*) FROM (SELECT pgns.nspname as schemaname, pgc.relname as tablename, pg_relation_size(pgc.oid) as relation_size, NULLIF(pgstat.n_dead_tup, 0) as dead_tuples FROM pg_class pgc JOIN pg_namespace pgns ON pgns.oid = pgc.relnamespace JOIN pg_stat_user_tables pgstat ON pgstat.relname = pgc.relname WHERE pgc.relkind = 'r' AND pgns.nspname NOT IN ('pg_catalog', 'information_schema') AND pgstat.n_dead_tup > 0) as s WHERE round(dead_tuples::numeric / case when relation_size > 0 then relation_size else 1 end * 100, 2) > 10;\"" 2>/dev/null`
	significantBloatOutput, _ := utils.RunCommand("bash", "-c", significantBloatCmd)

	fmt.Sscanf(strings.TrimSpace(significantBloatOutput), "%d", &bloatedTables)

	// Check total dead tuples
	deadTuplesCmd := `su - postgres -c "psql -d foreman -c \"SELECT SUM(n_dead_tup) FROM pg_stat_user_tables;\"" 2>/dev/null`
	deadTuplesOutput, _ := utils.RunCommand("bash", "-c", deadTuplesCmd)

	fmt.Sscanf(strings.TrimSpace(deadTuplesOutput), "%d", &totalDeadTuples)

	detail.WriteString("\nDatabase Bloat Summary:\n")
	detail.WriteString(fmt.Sprintf("- Tables with significant bloat (>10%%): %d\n", bloatedTables))
	detail.WriteString(fmt.Sprintf("- Total dead tuples: %d\n", totalDeadTuples))
	detail.WriteString("\nTable Count:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(tableCountOutput)
	detail.WriteString("\n----\n")

	// Check database size
	dbSizeCmd := `su - postgres -c "psql -d foreman -c \"SELECT pg_size_pretty(pg_database_size('foreman')) as db_size;\"" 2>/dev/null`
	dbSizeOutput, _ := utils.RunCommand("bash", "-c", dbSizeCmd)

	detail.WriteString("\nForeman Database Size:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(dbSizeOutput)
	detail.WriteString("\n----\n")

	if bloatedTables > 5 || totalDeadTuples > 1000000 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Database has %d significantly bloated tables", bloatedTables),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Run VACUUM ANALYZE on bloated tables")
		report.AddRecommendation(&check.Result, "Consider running `foreman-rake db:sessions:clear` to remove expired sessions")
		report.AddRecommendation(&check.Result, "Check that autovacuum is properly configured")
	} else if err != nil {
		check.Result = report.NewResult(report.StatusWarning,
			"Could not properly analyze database bloat",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Run VACUUM ANALYZE as a preventive measure")
		report.AddRecommendation(&check.Result, "Check PostgreSQL error logs")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Database tables do not show significant bloat",
			report.ResultKeyNoChange)
	}

	// Add reference link directly
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/configuration_management_tools",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_using_database_servers/optimizing-postgresql-performance_configuring-and-using-database-servers")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}

// checkDatabasePerformance checks database performance metrics
func checkDatabasePerformance(r *report.AsciiDocReport) {
	checkID := "satellite-db-performance"
	checkName := "Database Performance"
	checkDesc := "Analyzes PostgreSQL performance metrics and long-running queries."

	check := report.NewCheck(checkID, checkName, checkDesc, report.CategorySatelliteSystem)

	// Get list of active queries
	activeQueriesCmd := `su - postgres -c "psql -c \"SELECT pid, datname, usename, application_name, client_addr, state, backend_start, xact_start, query_start, state_change, wait_event_type, wait_event, query FROM pg_stat_activity WHERE state != 'idle' AND pid != pg_backend_pid() ORDER BY query_start ASC;\"" 2>/dev/null`
	activeQueriesOutput, err := utils.RunCommand("bash", "-c", activeQueriesCmd)

	var detail strings.Builder
	detail.WriteString("Database Performance Analysis:\n\n")

	if err != nil {
		detail.WriteString("Error retrieving active queries:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(err.Error())
		detail.WriteString("\n----\n\n")
	} else {
		detail.WriteString("Active Queries:\n")
		detail.WriteString("[source, bash]\n----\n")
		detail.WriteString(activeQueriesOutput)
		detail.WriteString("\n----\n\n")
	}

	// Get long-running queries (running for more than 30 seconds)
	longQueriesCmd := `su - postgres -c "psql -c \"SELECT pid, datname, usename, application_name, now() - query_start as duration, state, query FROM pg_stat_activity WHERE state != 'idle' AND pid != pg_backend_pid() AND now() - query_start > interval '30 seconds' ORDER BY duration DESC;\"" 2>/dev/null`
	longQueriesOutput, _ := utils.RunCommand("bash", "-c", longQueriesCmd)

	detail.WriteString("Long-Running Queries (>30 seconds):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(longQueriesOutput)
	detail.WriteString("\n----\n\n")

	// Get database statistics
	statsCmd := `su - postgres -c "psql -c \"SELECT sum(numbackends) as connections, sum(xact_commit) as commits, sum(xact_rollback) as rollbacks, sum(blks_read) as disk_reads, sum(blks_hit) as buffer_hits, (sum(blks_hit) * 100 / NULLIF(sum(blks_hit) + sum(blks_read), 0)) as hit_percent FROM pg_stat_database;\"" 2>/dev/null`
	statsOutput, _ := utils.RunCommand("bash", "-c", statsCmd)

	detail.WriteString("Database Statistics:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(statsOutput)
	detail.WriteString("\n----\n\n")

	// Check for locks
	locksCmd := `su - postgres -c "psql -c \"SELECT bl.pid AS blocked_pid, a.usename AS blocked_user, kl.pid AS blocking_pid, ka.usename AS blocking_user, a.query AS blocked_statement, ka.query AS blocking_statement FROM pg_catalog.pg_locks bl JOIN pg_catalog.pg_stat_activity a ON bl.pid = a.pid JOIN pg_catalog.pg_locks kl JOIN pg_catalog.pg_stat_activity ka ON kl.pid = ka.pid ON bl.transactionid = kl.transactionid AND bl.pid != kl.pid WHERE NOT bl.granted;\"" 2>/dev/null`
	locksOutput, _ := utils.RunCommand("bash", "-c", locksCmd)

	detail.WriteString("Locks Analysis:\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(locksOutput)
	detail.WriteString("\n----\n\n")

	// Check for index usage
	indexUsageCmd := `su - postgres -c "psql -d foreman -c \"SELECT schemaname, relname, indexrelname, idx_scan, idx_tup_read, idx_tup_fetch, pg_size_pretty(pg_relation_size(indexrelid::regclass)) as idx_size FROM pg_stat_user_indexes WHERE idx_scan = 0 AND pg_relation_size(indexrelid::regclass) > 1048576 ORDER BY pg_relation_size(indexrelid::regclass) DESC LIMIT 10;\"" 2>/dev/null`
	indexUsageOutput, _ := utils.RunCommand("bash", "-c", indexUsageCmd)

	detail.WriteString("Unused Large Indexes (>1MB):\n")
	detail.WriteString("[source, bash]\n----\n")
	detail.WriteString(indexUsageOutput)
	detail.WriteString("\n----\n")

	// Count long-running queries and locks
	longQueryCount := 0
	lockCount := 0

	// Count long-running queries
	if !strings.Contains(longQueriesOutput, "no rows") && !strings.Contains(longQueriesOutput, "0 rows") {
		lines := strings.Split(longQueriesOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "|") {
				longQueryCount++
			}
		}
		// Adjust for header rows
		if longQueryCount > 2 {
			longQueryCount -= 2
		}
	}

	// Count locks
	if !strings.Contains(locksOutput, "no rows") && !strings.Contains(locksOutput, "0 rows") {
		lines := strings.Split(locksOutput, "\n")
		for _, line := range lines {
			if strings.Contains(line, "|") {
				lockCount++
			}
		}
		// Adjust for header rows
		if lockCount > 2 {
			lockCount -= 2
		}
	}

	// Check for issues
	if lockCount > 0 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Database has %d blocked queries due to locks", lockCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate and resolve blocked queries")
		report.AddRecommendation(&check.Result, "Consider terminating long-running queries: SELECT pg_terminate_backend(pid)")
	} else if longQueryCount > 5 {
		check.Result = report.NewResult(report.StatusWarning,
			fmt.Sprintf("Database has %d long-running queries", longQueryCount),
			report.ResultKeyRecommended)
		report.AddRecommendation(&check.Result, "Investigate long-running queries and optimize if necessary")
		report.AddRecommendation(&check.Result, "Check for issues with specific Satellite services that may be causing slow queries")
	} else if strings.Contains(indexUsageOutput, "---") && !strings.Contains(indexUsageOutput, "no rows") {
		check.Result = report.NewResult(report.StatusWarning,
			"Database has unused indexes that may impact performance",
			report.ResultKeyAdvisory)
		report.AddRecommendation(&check.Result, "Consider removing unused indexes to improve write performance")
		report.AddRecommendation(&check.Result, "WARNING: Analyze index usage over time before removing any indexes")
	} else {
		check.Result = report.NewResult(report.StatusOK,
			"Database performance appears normal",
			report.ResultKeyNoChange)
	}

	// Add reference link directly
	versionInfo := GetSatelliteVersion()
	docsUrl := fmt.Sprintf("https://access.redhat.com/documentation/en-us/red_hat_satellite/%s.%s/html/administering_red_hat_satellite/configuration_management_tools",
		versionInfo.MajorVersion, versionInfo.MinorVersion)
	report.AddReferenceLink(&check.Result, docsUrl)
	report.AddReferenceLink(&check.Result, "https://access.redhat.com/documentation/en-us/red_hat_enterprise_linux/8/html/configuring_and_using_database_servers/monitoring-postgresql-performance_configuring-and-using-database-servers")

	report.SetDetail(&check.Result, detail.String())
	r.AddCheck(check)
}
