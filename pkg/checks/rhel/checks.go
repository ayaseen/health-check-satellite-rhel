// pkg/checks/rhel/checks.go

package rhel

/*
This file serves as an index to all RHEL health check functions.

Available checks:
- System Information:
  - RunSystemInfoChecks (system_info.go) - Checks system hostname, RHEL version, uptime, registration, repositories

- Time & Date:
  - RunTimeChecks (time.go) - Checks timezone, NTP/chrony, system clock consistency

- Memory and Swap:
  - RunMemoryChecks (memory.go) - Checks physical memory, swap configuration, VM tuning

- Disk & Filesystem:
  - RunDiskChecks (disk.go) - Checks disk usage, mount points, storage config, I/O performance

- CPU & Performance:
  - RunCPUChecks (cpu.go) - Checks CPU info, tuned profile, bottlenecks
  - RunPerformanceChecks (performance.go) - Checks system performance, bottlenecks, caches

- Network:
  - RunNetworkChecks (network.go) - Checks IP, bonding, hostname, MTU, firewall
  - RunConnectivityChecks (connectivity.go) - Checks dependent services, DNS, latency
  - RunHANetworkingChecks (ha_networking.go) - Checks multicast, fencing, VLAN/MTU, NIC failover

- Security:
  - RunSecurityChecks (security.go) - Checks SELinux, audit, password policy, SSH
  - RunComplianceChecks (compliance.go) - Checks CIS compliance, security scans, policies

- Services:
  - RunServicesChecks (services.go) - Checks unnecessary services, required services, boot target
  - RunLogsChecks (logs.go) - Checks system logs, log rotation, logging system
  - RunMonitoringChecks (monitoring.go) - Checks centralized logging, alerting, monitoring agents

- Updates & Packages:
  - RunPackagesChecks (packages.go) - Checks security patches, repositories, unnecessary packages, kernel

- Clustering:
  - RunClusterChecks (cluster.go) - Checks cluster software, nodes, fencing, constraints, autostart

- Authentication:
  - RunAuthChecks (auth.go) - Checks central auth, SSSD, sudo/PAM, Kerberos

- Backup & Recovery:
  - RunBackupChecks (backup.go) - Checks backup systems, recovery process, application backups

- Kernel & Firmware:
  - RunKernelChecks (kernel.go) - Checks kernel/microcode versions, firmware, unused devices

- Storage:
  - RunStorageChecks (storage.go) - Checks multipath, filesystem types, errors, alignment
  - RunStorageConsiderationsChecks (storage_considerations.go) - Checks performance, reliability, capacity
*/
