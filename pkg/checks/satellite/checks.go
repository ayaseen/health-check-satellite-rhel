// pkg/checks/satellite/checks.go

package satellite

import (
	"gitlab.consulting.redhat.com/ksa/health-check-satellite-rhel/pkg/report"
)

// Function declarations for all check categories
// These act as entry points to the actual implementations in their respective files

// RunSystemChecks performs Satellite system checks
func RunSystemChecks(r *report.AsciiDocReport) {
	// Satellite version
	checkSatelliteVersion(r)

	// Satellite registration
	checkSatelliteRegistration(r)

	// Satellite repositories
	checkSatelliteRepositories(r)

	// Satellite services
	checkSatelliteServices(r)
}

// RunStorageChecks performs Satellite storage checks
// Implementation in storage.go
// We don't need any implementation here as it's fully implemented in storage.go

// RunDatabaseChecks performs Satellite database checks
// Implementation in database.go

// RunContentChecks performs Satellite content management checks
// Implementation in content.go
// This function has a different signature with an organization parameter

// RunCapsuleChecks performs Satellite capsule checks
// Implementation in capsule.go

// RunPerformanceChecks performs Satellite performance checks
// Implementation in performance.go

// RunSecurityChecks performs Satellite security checks
// Implementation in security.go

// RunTasksChecks performs Satellite tasks checks
// Implementation in tasks.go

// RunBackupChecks performs Satellite backup checks
// Implementation in backup.go

// RunMonitoringChecks performs Satellite monitoring checks
// Implementation in monitoring.go

// RunMonitoringIntegrationChecks performs Satellite monitoring integration checks
// Implementation in monitoring.go

// RunConfigurationChecks performs Satellite configuration checks
// Implementation in configuration.go

// RunSubscriptionChecks performs Satellite subscription checks
// Implementation in subscription.go
// This function has a different signature with an organization parameter

// RunConsistencyChecks performs Satellite consistency checks
// Implementation in consistency.go

// RunOrchestrationChecks performs Satellite orchestration checks
// Implementation in orchestration.go

// RunPluginChecks performs Satellite plugin checks
// Implementation in plugin.go

// RunProxyChecks performs Satellite proxy checks
// Implementation in proxy.go

// RunProvisioningChecks performs Satellite provisioning checks
// Implementation in provisioning.go

// RunUserChecks performs Satellite user checks
// Implementation in user.go

// RunLegacyChecks performs Satellite legacy checks
// Implementation in legacy.go

// RunDocumentationChecks performs Satellite documentation checks
// Implementation in documentation.go

// RunInsightsChecks performs Satellite Insights checks
// Implementation in insights.go
